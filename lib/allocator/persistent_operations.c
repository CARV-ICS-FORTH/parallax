// Copyright [2021] [FORTH-ICS]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include "persistent_operations.h"
#include "../btree/bloom_filter.h"
#include "../btree/btree.h"
#include "../btree/btree_node.h"
#include "../btree/conf.h"
#include "../btree/gc.h"
#include "../btree/kv_pairs.h"
#include "../btree/lsn.h"
#include "redo_undo_log.h"
#include <assert.h>
#include <log.h>
#include <spin_loop.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

// IWYU pragma: no_forward_declare node_header
// IWYU pragma: no_forward_declare pbf_desc

struct log_info {
	uint64_t head_dev_offt;
	uint64_t tail_dev_offt;
	uint64_t size;
};

/**
 *<new_persistent_design>*/
static void pr_flush_allocation_log_and_level_info(struct db_descriptor *db_desc, uint8_t src_level_id,
						   uint8_t dst_level_id, uint8_t tree_id)
{
	/*Flush my allocations*/
	struct rul_log_info rul_log = rul_flush_txn(db_desc, db_desc->levels[dst_level_id].allocation_txn_id[tree_id]);
	/*new info about allocation_log*/
	db_desc->db_superblock->allocation_log.head_dev_offt = rul_log.head_dev_offt;
	db_desc->db_superblock->allocation_log.tail_dev_offt = rul_log.tail_dev_offt;
	db_desc->db_superblock->allocation_log.size = rul_log.size;
	db_desc->db_superblock->allocation_log.txn_id = rul_log.txn_id;

	/*zero out Li*/
	if (src_level_id) {
		db_desc->db_superblock->root_r[src_level_id][0] = 0;
		db_desc->db_superblock->first_segment[src_level_id][0] = 0;
		db_desc->db_superblock->last_segment[src_level_id][0] = 0;
		db_desc->db_superblock->offset[src_level_id][0] = 0;
		db_desc->db_superblock->level_size[src_level_id][0] = 0;
		db_desc->db_superblock->root_r[src_level_id][0] = 0;
	}

	if (dst_level_id) {
		/*new info about my level*/
		db_desc->db_superblock->root_r[dst_level_id][0] =
			ABSOLUTE_ADDRESS(db_desc->levels[dst_level_id].root[tree_id]);

		db_desc->db_superblock->first_segment[dst_level_id][0] =
			ABSOLUTE_ADDRESS(db_desc->levels[dst_level_id].first_segment[tree_id]);
		log_debug("Persist %u first was %lu", dst_level_id,
			  ABSOLUTE_ADDRESS(db_desc->levels[dst_level_id].first_segment[tree_id]));
		assert(db_desc->levels[dst_level_id].first_segment[tree_id]);

		db_desc->db_superblock->last_segment[dst_level_id][0] =
			ABSOLUTE_ADDRESS(db_desc->levels[dst_level_id].last_segment[tree_id]);

		db_desc->db_superblock->offset[dst_level_id][0] = db_desc->levels[dst_level_id].offset[tree_id];

		db_desc->db_superblock->level_size[dst_level_id][0] = db_desc->levels[dst_level_id].level_size[tree_id];
		log_debug("Writing root[%u][%u] = %p", dst_level_id, tree_id,
			  (void *)db_desc->levels[dst_level_id].root[tree_id]);

		db_desc->db_superblock->root_r[dst_level_id][0] =
			ABSOLUTE_ADDRESS(db_desc->levels[dst_level_id].root[tree_id]);
	}

	pr_flush_db_superblock(db_desc);
}

static void pr_update_bloom_info(db_descriptor *db_desc)
{
	for (uint8_t i = 0; i < MAX_LEVELS; i++) {
		for (uint8_t j = 0; j < NUM_TREES_PER_LEVEL; j++) {
			if (NULL == db_desc->levels[i].bloom_desc[j]) {
				db_desc->db_superblock->bloom_filter_hash[i][j] = UINT64_MAX;
				db_desc->db_superblock->bloom_filter_valid[i][j] = 0;
				continue;
			}
			db_desc->db_superblock->bloom_filter_hash[i][j] =
				pbf_get_bf_file_hash(db_desc->levels[i].bloom_desc[j]);
			db_desc->db_superblock->bloom_filter_valid[i][j] = 1;
		}
	}
}
/**
 * Persists L0 key value pairs in storage making it recoverable.
 * @param db_desc is the descriptor of the db
 * @param tree_id The id of the tree in L0. Parallax performs double buffering
 * in L0 during a compaction operation from L0 to L1. As a result, valid tree_id
 * values are from 0 to NUM_TREES_PER_LEVEL-1.
*/
void pr_flush_L0(struct db_descriptor *db_desc, uint8_t tree_id)
{
	if (!db_desc->dirty) {
		log_debug("DB: %s clean nothing to flush ", db_desc->db_superblock->db_name);
		return;
	}

	struct log_info large_log;
	struct log_info L0_recovery_log;

	MUTEX_LOCK(&db_desc->flush_L0_lock);

	/*Lock logs L0_recovery_log, medium, and Large locked*/
	MUTEX_LOCK(&db_desc->lock_log);

	/*keep Large log state prior to releasing the lock*/
	large_log.head_dev_offt = db_desc->big_log.head_dev_offt;
	large_log.tail_dev_offt = db_desc->big_log.tail_dev_offt;
	large_log.size = db_desc->big_log.size;

	/*keep L0_recovery_log state prior to releasing the lock*/
	L0_recovery_log.head_dev_offt = db_desc->small_log.head_dev_offt;
	L0_recovery_log.tail_dev_offt = db_desc->small_log.tail_dev_offt;
	L0_recovery_log.size = db_desc->small_log.size;

	MUTEX_UNLOCK(&db_desc->lock_log);

	/*
   * Flush large and L0_recovery_log may flush more. We do this
   * 1)To avoid holding all logs lock while doing I/O
   * 2)We are sure that the (tail, size) of the previous step
   * will be at the device
  */

	/*Flush large log*/
	pr_flush_log_tail(db_desc, &db_desc->big_log);

	/*Flush L0 recovery log*/
	pr_flush_log_tail(db_desc, &db_desc->small_log);

	uint64_t txn_id = db_desc->levels[0].allocation_txn_id[tree_id];

	/*time to write superblock*/
	pr_lock_db_superblock(db_desc);
	/*Flush my allocations*/

	struct rul_log_info rul_log = rul_flush_txn(db_desc, txn_id);
	/*new info about large*/
	db_desc->db_superblock->big_log_head_offt = large_log.head_dev_offt;
	db_desc->db_superblock->big_log_tail_offt = large_log.tail_dev_offt;
	db_desc->db_superblock->big_log_size = large_log.size;
	/*new info about L0_recovery_log*/
	db_desc->db_superblock->small_log_head_offt = L0_recovery_log.head_dev_offt;
	db_desc->db_superblock->small_log_tail_offt = L0_recovery_log.tail_dev_offt;
	db_desc->db_superblock->small_log_size = L0_recovery_log.size;
	/*new info about allocation_log*/
	db_desc->db_superblock->allocation_log.head_dev_offt = rul_log.head_dev_offt;
	db_desc->db_superblock->allocation_log.tail_dev_offt = rul_log.tail_dev_offt;
	db_desc->db_superblock->allocation_log.size = rul_log.size;
	db_desc->db_superblock->allocation_log.txn_id = rul_log.txn_id;
	/*Just a refresher*/
	db_desc->db_superblock->small_log_start_segment_dev_offt = db_desc->small_log_start_segment_dev_offt;
	db_desc->db_superblock->small_log_offt_in_start_segment = db_desc->small_log_start_offt_in_segment;
	db_desc->db_superblock->big_log_start_segment_dev_offt = db_desc->big_log_start_segment_dev_offt;
	db_desc->db_superblock->big_log_offt_in_start_segment = db_desc->big_log_start_offt_in_segment;
	/*flush db superblock*/
	pr_flush_db_superblock(db_desc);

	pr_unlock_db_superblock(db_desc);

	MUTEX_UNLOCK(&db_desc->flush_L0_lock);
	rul_apply_txn_buf_freeops_and_destroy(db_desc, txn_id);
}

static void pr_flush_L0_to_L1(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	struct log_info medium_log;

	/*
   * Keep medium log state. We don't need to lock because ONLY one compaction
   * from L0 to L1 is allowed.
  */
	medium_log.head_dev_offt = db_desc->medium_log.head_dev_offt;
	medium_log.tail_dev_offt = db_desc->medium_log.tail_dev_offt;
	medium_log.size = db_desc->medium_log.size;
	/*Flush medium log*/
	pr_flush_log_tail(db_desc, &db_desc->medium_log);
	pr_lock_db_superblock(db_desc);
	uint64_t txn_id = db_desc->levels[level_id].allocation_txn_id[tree_id];

	/*medium log info*/
	db_desc->db_superblock->medium_log_head_offt = medium_log.head_dev_offt;
	db_desc->db_superblock->medium_log_tail_offt = medium_log.tail_dev_offt;
	db_desc->db_superblock->medium_log_size = medium_log.size;

	/*trim L0_recovery_log*/
	struct segment_header *tail = REAL_ADDRESS(db_desc->small_log_start_segment_dev_offt);
	log_debug("Tail segment id %lu", tail->segment_id);

	struct segment_header *head = REAL_ADDRESS(db_desc->db_superblock->small_log_head_offt);
	log_debug("Head segment id %lu", head->segment_id);

	uint64_t bytes_freed = 0;
	(void)bytes_freed;

	if (tail != head) {
		struct segment_header *curr = REAL_ADDRESS(tail->prev_segment);
		while (1) {
			struct rul_log_entry log_entry = { .dev_offt = ABSOLUTE_ADDRESS(curr),
							   .txn_id = txn_id,
							   .op_type = RUL_FREE,
							   .size = SEGMENT_SIZE };
			log_debug("Triming L0 recovery log segment:%lu curr segment id:%lu", log_entry.dev_offt,
				  curr->segment_id);
			rul_add_entry_in_txn_buf(db_desc, &log_entry);
			bytes_freed += SEGMENT_SIZE;

			if (curr->segment_id == head->segment_id)
				break;
			curr = REAL_ADDRESS(curr->prev_segment);
		}
	}

	log_debug("Freed a total of %lu MB bytes from trimming L0 recovery log head %lu tail %lu size %lu ***",
		  bytes_freed / (1024 * 1024), db_desc->db_superblock->small_log_head_offt,
		  db_desc->db_superblock->small_log_tail_offt, db_desc->db_superblock->small_log_size);

	db_desc->small_log.head_dev_offt = db_desc->db_superblock->small_log_head_offt =
		db_desc->db_superblock->small_log_start_segment_dev_offt;

	/*recovery info for L0 L0_recovery_log*/
	db_desc->db_superblock->small_log_start_segment_dev_offt = db_desc->small_log_start_segment_dev_offt;
	db_desc->db_superblock->small_log_offt_in_start_segment = db_desc->small_log_start_offt_in_segment;
	db_desc->db_superblock->big_log_start_segment_dev_offt = db_desc->big_log_start_segment_dev_offt;
	db_desc->db_superblock->big_log_offt_in_start_segment = db_desc->big_log_start_offt_in_segment;

	pr_flush_allocation_log_and_level_info(db_desc, level_id - 1, level_id, tree_id);
	pr_unlock_db_superblock(db_desc);
	rul_apply_txn_buf_freeops_and_destroy(db_desc, txn_id);
}

/**
* Flushes compaction from level Lmax where the medium KV pairs are transferred
* from the medium log to in-place
*/
static void pr_flush_Lmax_to_Ln(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	log_debug("Flushing Lmax to Ln!");
	struct level_descriptor *level_desc = &db_desc->levels[level_id];

	uint64_t txn_id = db_desc->levels[level_id].allocation_txn_id[tree_id];
	/*trim medium log*/

	uint64_t new_medium_log_head_offt = db_desc->medium_log.head_dev_offt;

	if (0 == level_desc->medium_in_place_segment_dev_offt ||
	    level_desc->medium_in_place_segment_dev_offt == db_desc->medium_log.head_dev_offt)
		goto update_superblock;

	new_medium_log_head_offt = level_desc->medium_in_place_segment_dev_offt;
	struct segment_header *trim_end_segment = REAL_ADDRESS(level_desc->medium_in_place_segment_dev_offt);
	struct segment_header *head = REAL_ADDRESS(db_desc->medium_log.head_dev_offt);
	uint64_t bytes_freed = 0;
	(void)bytes_freed;

	for (struct segment_header *curr_trim_segment = REAL_ADDRESS(trim_end_segment->prev_segment);;
	     curr_trim_segment = REAL_ADDRESS(curr_trim_segment->prev_segment)) {
		struct rul_log_entry log_entry = { .dev_offt = ABSOLUTE_ADDRESS(curr_trim_segment),
						   .txn_id = txn_id,
						   .op_type = RUL_FREE,
						   .size = SEGMENT_SIZE };
		rul_add_entry_in_txn_buf(db_desc, &log_entry);
		bytes_freed += SEGMENT_SIZE;
		if (curr_trim_segment->segment_id == head->segment_id)
			break;
	}
	level_desc->medium_in_place_segment_dev_offt = 0;
	level_desc->medium_in_place_max_segment_id = 0;

	log_debug("*** Freed a total of %lu MB bytes from trimming medium log head %lu tail %lu size %lu ***",
		  bytes_freed / (1024 * 1024L), db_desc->db_superblock->small_log_head_offt,
		  db_desc->db_superblock->small_log_tail_offt, db_desc->db_superblock->small_log_size);

update_superblock:

	pr_lock_db_superblock(db_desc);
	/*new info about medium log after trim operation*/
	db_desc->medium_log.head_dev_offt = db_desc->db_superblock->medium_log_head_offt = new_medium_log_head_offt;

	pr_flush_allocation_log_and_level_info(db_desc, level_id - 1, level_id, tree_id);

	pr_unlock_db_superblock(db_desc);
	rul_apply_txn_buf_freeops_and_destroy(db_desc, txn_id);
}

void pr_flush_compaction(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	if (level_id == 1) {
		pr_flush_L0_to_L1(db_desc, level_id, tree_id);
		return;
	}

	if (level_id == db_desc->level_medium_inplace) {
		pr_flush_Lmax_to_Ln(db_desc, level_id, tree_id);
		return;
	}

	uint64_t txn_id = db_desc->levels[level_id].allocation_txn_id[tree_id];
	pr_lock_db_superblock(db_desc);

	pr_flush_allocation_log_and_level_info(db_desc, level_id - 1, level_id, tree_id);

	pr_unlock_db_superblock(db_desc);
	rul_apply_txn_buf_freeops_and_destroy(db_desc, txn_id);
}

void pr_lock_db_superblock(struct db_descriptor *db_desc)
{
	MUTEX_LOCK(&db_desc->db_volume->db_superblock_lock[db_desc->db_superblock->id]);
}

void pr_unlock_db_superblock(struct db_descriptor *db_desc)
{
	MUTEX_UNLOCK(&db_desc->db_volume->db_superblock_lock[db_desc->db_superblock->id]);
}

void pr_flush_db_superblock(struct db_descriptor *db_desc)
{
	pr_update_bloom_info(db_desc);
	int64_t last_lsn_id = lsn_factory_get_ticket(&db_desc->lsn_factory);
	set_lsn_id(&db_desc->db_superblock->last_lsn, last_lsn_id);
	uint64_t superblock_offt =
		sizeof(struct superblock) + (sizeof(struct pr_db_superblock) * db_desc->db_superblock->id);
	ssize_t total_bytes_written = 0;
	ssize_t size = sizeof(struct pr_db_superblock);
	while (total_bytes_written < size) {
		ssize_t bytes_written = pwrite(db_desc->db_volume->vol_fd, db_desc->db_superblock,
					       size - total_bytes_written, superblock_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to write region's %s superblock", db_desc->db_superblock->db_name);
			perror("Reason");
			BUG_ON();
		}
		total_bytes_written += bytes_written;
	}
}

static void pr_print_db_superblock(struct pr_db_superblock *superblock)
{
	(void)superblock;
	log_info("DB name: %s id in the volume's superblock array: %u valid: %u", superblock->db_name, superblock->id,
		 superblock->valid);
	log_info("BIG log head_dev_offt: %lu tail_dev_offt: %lu size: %lu", superblock->big_log_head_offt,
		 superblock->big_log_tail_offt, superblock->big_log_size);
	log_info("Medium log head_dev_offt: %lu tail_dev_offt: %lu size: %lu", superblock->medium_log_head_offt,
		 superblock->medium_log_tail_offt, superblock->medium_log_size);
	log_info("L0 L0_recovery_log log head_dev_offt: %lu tail_dev_offt: %lu size: %lu",
		 superblock->small_log_head_offt, superblock->small_log_tail_offt, superblock->small_log_size);
	log_info("latest LSN: %lu", get_lsn_id(&superblock->last_lsn));
	log_info("Recovery of L0_recovery_log starts from segment_dev_offt: %lu offt_in_seg: %lu",
		 superblock->small_log_start_segment_dev_offt, superblock->small_log_offt_in_start_segment);
	log_info("Recovery of BIG log starts from segment_dev_offt: %lu offt_in_seg: %lu",
		 superblock->big_log_start_segment_dev_offt, superblock->big_log_offt_in_start_segment);
#if 0
  for (uint32_t level_id = 0; level_id < MAX_LEVELS; ++level_id) {
		for (uint32_t tree_id = 0; tree_id < NUM_TREES_PER_LEVEL; ++tree_id) {
			log_info("Tree[%u][%u] root dev_offt = %llu", level_id, tree_id,
				 superblock->root_r[level_id][tree_id]);
			log_info("Tree[%u][%u] first_segment_dev_offt = %llu", level_id, tree_id,
				 superblock->first_segment[level_id][tree_id]);
			log_info("Tree[%u][%u] last_segment_dev_offt = %llu", level_id, tree_id,
				 superblock->last_segment[level_id][tree_id]);
			log_info("Tree[%u][%u] level size = %llu", level_id, tree_id,
				 superblock->level_size[level_id][tree_id]);
		}
	}
#endif
}

void pr_read_db_superblock(struct db_descriptor *db_desc)
{
	//where is my superblock
	ssize_t total_bytes_written = 0;
	ssize_t size = sizeof(struct pr_db_superblock);
	uint64_t superblock_offt =
		sizeof(struct superblock) + (sizeof(struct pr_db_superblock) * db_desc->db_superblock->id);

	while (total_bytes_written < size) {
		ssize_t bytes_written = pwrite(db_desc->db_volume->vol_fd, db_desc->db_superblock,
					       size - total_bytes_written, superblock_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to read region's %s superblock", db_desc->db_superblock->db_name);
			perror("Reason");
			BUG_ON();
		}
		total_bytes_written += bytes_written;
	}
	pr_print_db_superblock(db_desc->db_superblock);
}

void pr_flush_log_tail(struct db_descriptor *db_desc, struct log_descriptor *log_desc)
{
	uint64_t offt_in_seg = log_desc->size % SEGMENT_SIZE;
	if (!offt_in_seg)
		return;

	int last_tail = log_desc->curr_tail_id % LOG_TAIL_NUM_BUFS;

	/*Barrier wait all previous operations to finish*/
	uint32_t chunk_id = offt_in_seg / LOG_CHUNK_SIZE;
	for (uint32_t i = 0; i < chunk_id; ++i)
		wait_for_value(&log_desc->tail[last_tail]->bytes_in_chunk[i], LOG_CHUNK_SIZE);

	uint64_t start_offt;
	start_offt = chunk_id * LOG_CHUNK_SIZE;

	uint64_t end_offt = start_offt + LOG_CHUNK_SIZE;
	log_debug("Flushing log tail start_offt: %lu end_offt: %lu last tail %d", start_offt, end_offt, last_tail);
	while (start_offt < end_offt) {
		ssize_t bytes_written = pwrite(db_desc->db_volume->vol_fd, &log_desc->tail[last_tail]->buf[start_offt],
					       end_offt - start_offt, log_desc->tail[last_tail]->dev_offt + start_offt);

		if (bytes_written == -1) {
			log_fatal("Failed to write LOG_CHUNK reason follows");
			perror("Reason");
			BUG_ON();
		}
		start_offt += bytes_written;
	}
}

#define PR_CURSOR_MAX_SEGMENTS_SIZE 64

struct segment_array {
	uint64_t *segments;
	int size;
	int n_entries;
	int entry_id;
};

static int add_segment_in_array(struct segment_array *segments, uint64_t dev_offt)
{
	if (segments->entry_id < 0) {
		/*resize*/
		int double_size = 2 * segments->size;
		uint64_t *new_array = calloc(double_size, sizeof(uint64_t));
		memcpy(&new_array[double_size / 2], segments->segments, sizeof(uint64_t) * segments->size);
		free(segments->segments);
		segments->segments = new_array;
		segments->size = double_size;
		segments->entry_id = (double_size / 2) - 1;
	}
	segments->segments[segments->entry_id] = dev_offt;
	++segments->n_entries;
	return segments->entry_id--;
}

static struct segment_array *find_N_last_small_log_segments(struct db_descriptor *db_desc)
{
	/*traverse small log and fill the segment array*/
	log_debug("Recovery of small log start from segment dev offt: %lu", db_desc->small_log_start_segment_dev_offt);
	struct segment_header *first_recovery_segment = REAL_ADDRESS(db_desc->small_log_start_segment_dev_offt);
	struct segment_array *segment_array = calloc(1, sizeof(struct segment_array));

	if (!segment_array) {
		log_fatal("Calloc did not return memory");
		BUG_ON();
	}

	segment_array->segments = calloc(PR_CURSOR_MAX_SEGMENTS_SIZE, sizeof(uint64_t));
	if (!segment_array->segments) {
		log_fatal("Calloc did not return memory");
		BUG_ON();
	}

	segment_array->size = PR_CURSOR_MAX_SEGMENTS_SIZE;
	segment_array->entry_id = PR_CURSOR_MAX_SEGMENTS_SIZE - 1;

	for (struct segment_header *segment = REAL_ADDRESS(db_desc->small_log.tail_dev_offt);
	     segment != first_recovery_segment; segment = REAL_ADDRESS(segment->prev_segment)) {
		add_segment_in_array(segment_array, ABSOLUTE_ADDRESS(segment));
	}
	add_segment_in_array(segment_array, ABSOLUTE_ADDRESS(first_recovery_segment));

	return segment_array;
}

/*Variables responsible to expose internal stats to tests!*/
static volatile uint32_t count_garbage_entries = 0;
static volatile uint32_t count_garbage_bytes = 0;
static uint8_t enable_validate_garbage_blob_bytes = 0;

uint32_t get_garbage_entries(void)
{
	return count_garbage_entries;
}

uint32_t get_garbage_bytes(void)
{
	return count_garbage_bytes;
}

void enable_validation_garbage_bytes(void)
{
	enable_validate_garbage_blob_bytes = 1;
}

void disable_validation_garbage_bytes(void)
{
	enable_validate_garbage_blob_bytes = 0;
}

/**
 * Counts the found garbage bytes during the recovery of the redo undo log.
 * Requires a call to \ref enable_validation_garbage_bytes before calling it otherwise instantly returns.
 */
static void validate_garbage_blob_bytes(struct large_log_segment_gc_entry *test_garbage_bytes_list)
{
	if (!enable_validate_garbage_blob_bytes)
		return;

	uint32_t count_entries = 0;
	uint32_t count_bytes = 0;

	struct large_log_segment_gc_entry *current_option = NULL;
	struct large_log_segment_gc_entry *tmp = NULL;

	HASH_ITER(hh, test_garbage_bytes_list, current_option, tmp)
	{
		/* Suprresses possible null pointer dereference of cppcheck*/
		assert(current_option);
		++count_entries;
		count_bytes += current_option->garbage_bytes;
	}

	count_garbage_entries = count_entries;
	count_garbage_bytes = count_bytes;
}

static struct segment_array *find_N_last_blobs(struct db_descriptor *db_desc, uint64_t start_segment_offt)
{
	struct blob_entry {
		uint64_t dev_offt;
		int array_id;
		UT_hash_handle hh;
	};
	struct blob_entry *root_blob_entry = NULL;
	struct large_log_segment_gc_entry *garbage_bytes_for_blobs = NULL;
	struct large_log_segment_gc_entry *node = NULL;
	log_debug("Allocation log cursor for volume %s DB: %s", db_desc->db_volume->volume_name,
		  db_desc->db_superblock->db_name);
	struct allocation_log_cursor *log_cursor =
		init_allocation_log_cursor(db_desc->db_volume, db_desc->db_superblock);
	struct segment_array *segments = calloc(1, sizeof(struct segment_array));
	segments->segments = calloc(PR_CURSOR_MAX_SEGMENTS_SIZE, sizeof(uint64_t));
	segments->size = PR_CURSOR_MAX_SEGMENTS_SIZE;
	segments->entry_id = PR_CURSOR_MAX_SEGMENTS_SIZE - 1;
	uint32_t start_tracing_segments = 0;

	struct blob_entry *b_entry;
	while (1) {
		struct rul_log_entry *log_entry = get_next_allocation_log_entry(log_cursor);
		if (!log_entry)
			break;

		switch (log_entry->op_type) {
		case RUL_LARGE_LOG_ALLOCATE:
			//log_info("Found allocation for BIG log");
			if (log_entry->dev_offt == start_segment_offt)
				start_tracing_segments = 1;

			if (!start_tracing_segments)
				break;

			b_entry = calloc(1, sizeof(struct blob_entry));
			b_entry->dev_offt = log_entry->dev_offt;
			b_entry->array_id = add_segment_in_array(segments, log_entry->dev_offt);
			HASH_ADD_PTR(root_blob_entry, dev_offt, b_entry);
			break;
		case RUL_MEDIUM_LOG_ALLOCATE:
		case RUL_SMALL_LOG_ALLOCATE:
		case RUL_ALLOCATE:
			//log_info("Found allocation for other logs not BIG");
			break;
		case RUL_LOG_FREE:
		case RUL_FREE: {
			//log_info("Found free operation");
			HASH_FIND_PTR(root_blob_entry, &log_entry->dev_offt, b_entry);
			if (b_entry != NULL)
				segments->segments[b_entry->array_id] = 0;
			break;
		}
		case BLOB_GARBAGE_BYTES:
			assert(log_entry->blob_garbage_bytes > 0 && log_entry->blob_garbage_bytes < SEGMENT_SIZE);
			HASH_FIND(hh, garbage_bytes_for_blobs, &log_entry->dev_offt, sizeof(log_entry->dev_offt), node);

			if (node)
				node->garbage_bytes += log_entry->blob_garbage_bytes;
			else {
				struct large_log_segment_gc_entry *temp_segment_entry =
					calloc(1, sizeof(struct large_log_segment_gc_entry));
				temp_segment_entry->segment_dev_offt = log_entry->dev_offt;
				temp_segment_entry->garbage_bytes = log_entry->blob_garbage_bytes;
				temp_segment_entry->segment_moved = 0;

				HASH_ADD(hh, garbage_bytes_for_blobs, segment_dev_offt, sizeof(log_entry->dev_offt),
					 temp_segment_entry);
			}

			break;
		default:
			log_fatal("Unknown/Corrupted entry in allocation log %d", log_entry->op_type);
			log_fatal(
				"Cursor status: chunk_id %u entry in chunk %u chunk entries: %u chunks_in_segment: %u",
				log_cursor->curr_chunk_id, log_cursor->curr_entry_in_chunk, log_cursor->chunk_entries,
				log_cursor->chunks_in_segment);
			BUG_ON();
		}
	}

	close_allocation_log_cursor(log_cursor);
	struct blob_entry *current_entry = NULL;
	struct blob_entry *tmp = NULL;

	if (garbage_bytes_for_blobs) {
		validate_garbage_blob_bytes(garbage_bytes_for_blobs);
		db_desc->segment_ht = garbage_bytes_for_blobs;
	}

	HASH_ITER(hh, root_blob_entry, current_entry, tmp)
	{
		HASH_DEL(root_blob_entry, current_entry);
		free(current_entry);
	}
	return segments;
}

struct kv_entry {
	struct lsn lsn;
	struct kv_splice *par_kv;
};

struct log_cursor {
	char *segment_in_mem_buffer;
	struct kv_entry entry;
	struct db_descriptor *db_desc;
	uint64_t log_tail_dev_offt;
	uint64_t log_size;
	struct segment_array *log_segments;
	uint64_t offt_in_segment;
	uint32_t segment_in_mem_size;
	enum log_type type;
	uint8_t valid;
	uint8_t tombstone : 1;
};

static char *get_position_in_segment(struct log_cursor *cursor)
{
	return &cursor->segment_in_mem_buffer[cursor->offt_in_segment];
}

static void prepare_cursor_op(struct log_cursor *cursor)
{
	cursor->entry.lsn = *(struct lsn *)get_position_in_segment(cursor);
	cursor->offt_in_segment += get_lsn_size();
	struct kv_splice *kv_pair = (struct kv_splice *)get_position_in_segment(cursor);

	cursor->entry.par_kv = (struct kv_splice *)get_position_in_segment(cursor);
	cursor->tombstone = is_tombstone_kv_pair(kv_pair);
	cursor->offt_in_segment += get_kv_size(cursor->entry.par_kv);
}

static void init_pos_log_cursor_in_segment(struct db_descriptor *db_desc, struct log_cursor *cursor)
{
	if (0 == cursor->log_segments->n_entries) {
		cursor->valid = 0;
		return;
	}
	cursor->valid = 1;

	//cursor->curr_segment = REAL_ADDRESS(cursor->log_segments->segments[cursor->log_segments->entry_id]);
	if (!read_dev_offt_into_buffer((char *)cursor->segment_in_mem_buffer, 0, cursor->segment_in_mem_size,
				       cursor->log_segments->segments[cursor->log_segments->entry_id],
				       db_desc->db_volume->vol_fd)) {
		log_fatal("Failed to read dev offt: %lu",
			  cursor->log_segments->segments[cursor->log_segments->entry_id]);
		_exit(EXIT_FAILURE);
	}

	/*Cornercases*/
	switch (cursor->type) {
	case SMALL_LOG:
		cursor->offt_in_segment = db_desc->small_log_start_offt_in_segment;
		if (cursor->log_segments->segments[cursor->log_segments->entry_id] == cursor->log_tail_dev_offt) {
			if (cursor->log_size % (uint64_t)SEGMENT_SIZE == sizeof(struct segment_header)) {
				/*Nothing to parse*/
				log_debug("Nothing to parse in the small log");
				cursor->valid = 0;
				return;
			}
		}
		break;
	case BIG_LOG:
		cursor->offt_in_segment = db_desc->big_log_start_offt_in_segment;
		if (cursor->log_segments->segments[cursor->log_segments->entry_id] == cursor->log_tail_dev_offt) {
			if (cursor->log_size == 0) {
				/*Nothing to parse*/
				log_debug("Nothing to parse in the big log");
				cursor->valid = 0;
				return;
			}
		}
		break;
	default:
		log_fatal("Unhandled cursor type");
		BUG_ON();
	}

	prepare_cursor_op(cursor);
}

static struct log_cursor *init_log_cursor(struct db_descriptor *db_desc, enum log_type type)
{
	struct log_cursor *cursor = calloc(1, sizeof(struct log_cursor));
	cursor->segment_in_mem_size = SEGMENT_SIZE;
	cursor->db_desc = db_desc;
	cursor->type = type;
	if (posix_memalign((void **)&cursor->segment_in_mem_buffer, ALIGNMENT_SIZE, cursor->segment_in_mem_size) != 0) {
		log_fatal("MEMALIGN FAILED");
		BUG_ON();
	}

	switch (cursor->type) {
	case BIG_LOG:
		cursor->log_tail_dev_offt = db_desc->big_log.tail_dev_offt;
		cursor->log_size = db_desc->big_log.size;
		cursor->log_segments = find_N_last_blobs(db_desc, db_desc->big_log_start_segment_dev_offt);
		cursor->log_segments->entry_id = cursor->log_segments->size - 1;
		log_debug("Big log n_segments max size %u entries found %u entry_id %u", cursor->log_segments->size,
			  cursor->log_segments->n_entries, cursor->log_segments->entry_id);
		break;
	case SMALL_LOG:
		cursor->log_tail_dev_offt = db_desc->small_log.tail_dev_offt;
		cursor->log_size = db_desc->small_log.size;
		cursor->log_segments = find_N_last_small_log_segments(db_desc);
		cursor->log_segments->entry_id = cursor->log_segments->size - cursor->log_segments->n_entries;
		log_debug("Small log n_segments max size %u entries found %u", cursor->log_segments->size,
			  cursor->log_segments->n_entries);
		break;
	default:
		log_fatal("Unknown/ Unsupported log type");
		BUG_ON();
	}

	init_pos_log_cursor_in_segment(db_desc, cursor);

	return cursor;
}

static void close_log_cursor(struct log_cursor *cursor)
{
	free(cursor->log_segments->segments);
	free(cursor->log_segments);
	free(cursor->segment_in_mem_buffer);
	free(cursor);
}

static void get_next_log_segment(struct log_cursor *cursor)
{
	switch (cursor->type) {
	case BIG_LOG:
		--cursor->log_segments->entry_id;
		//log_info("BIG LOG entry id: %d n_entries: %u size : %u", cursor->log_segments->entry_id,
		//	 cursor->log_segments->n_entries, cursor->log_segments->size);
		if (cursor->log_segments->entry_id < cursor->log_segments->size - cursor->log_segments->n_entries) {
			cursor->valid = 0;
			return;
		}

		if (!read_dev_offt_into_buffer((char *)cursor->segment_in_mem_buffer, 0, cursor->segment_in_mem_size,
					       cursor->log_segments->segments[cursor->log_segments->entry_id],
					       cursor->db_desc->db_volume->vol_fd)) {
			log_fatal("Failed to read dev offt: %lu",
				  cursor->log_segments->segments[cursor->log_segments->entry_id]);
		}
		cursor->offt_in_segment = 0;
		break;
	case SMALL_LOG:
		++cursor->log_segments->entry_id;
		if (cursor->log_segments->entry_id >= cursor->log_segments->size) {
			cursor->valid = 0;
			return;
		}

		if (!read_dev_offt_into_buffer((char *)cursor->segment_in_mem_buffer, 0, cursor->segment_in_mem_size,
					       cursor->log_segments->segments[cursor->log_segments->entry_id],
					       cursor->db_desc->db_volume->vol_fd)) {
			log_fatal("Failed to read dev offt: %lu",
				  cursor->log_segments->segments[cursor->log_segments->entry_id]);
		}
		cursor->offt_in_segment = sizeof(struct segment_header);
		break;
	default:
		log_fatal("Unhandled cursor type");
		BUG_ON();
	}
}

static struct kv_entry *get_next_log_entry(struct log_cursor *cursor)
{
start:
	if (!cursor->valid)
		return NULL;
	/*Advance cursor for future use*/
	/*Are there enough bytes in segment?*/

	uint32_t remaining_bytes_in_segment = 0;
	int is_tail = cursor->log_segments->segments[cursor->log_segments->entry_id] == cursor->log_tail_dev_offt;

	remaining_bytes_in_segment = (uint64_t)SEGMENT_SIZE - ((uint64_t)cursor->offt_in_segment);
	if (is_tail)
		remaining_bytes_in_segment =
			(cursor->log_size % (uint64_t)SEGMENT_SIZE) - ((uint64_t)cursor->offt_in_segment);

	char *pos_in_segment = get_position_in_segment(cursor);
	struct kv_splice *kv_pair = (struct kv_splice *)pos_in_segment;
	if (remaining_bytes_in_segment < get_min_possible_kv_size() || 0 == get_key_size(kv_pair)) {
		cursor->offt_in_segment += remaining_bytes_in_segment;
		get_next_log_segment(cursor);
		goto start;
	}

	prepare_cursor_op(cursor);

	return &cursor->entry;
}

void recover_L0(struct db_descriptor *db_desc)
{
	db_handle handle = { .db_desc = db_desc, .volume_desc = db_desc->db_volume };
	struct log_cursor *cursor[LOG_TYPES_COUNT] = { 0 };

	log_debug("Small log start %lu head %lu", db_desc->small_log_start_segment_dev_offt,
		  db_desc->small_log.head_dev_offt);
	assert(db_desc->small_log_start_segment_dev_offt == db_desc->small_log.head_dev_offt);
	cursor[SMALL_LOG] = init_log_cursor(db_desc, SMALL_LOG);
	log_debug("Small log cursor status: %u", cursor[SMALL_LOG]->valid);
	cursor[BIG_LOG] = init_log_cursor(db_desc, BIG_LOG);
	log_debug("Big log cursor status: %u", cursor[BIG_LOG]->valid);

	struct kv_entry *kvs[LOG_TYPES_COUNT];
	kvs[SMALL_LOG] = &cursor[SMALL_LOG]->entry;
	kvs[BIG_LOG] = &cursor[BIG_LOG]->entry;

	while (1) {
		if (!cursor[SMALL_LOG]->valid && !cursor[BIG_LOG]->valid)
			break;
		enum log_type choice = BIG_LOG;
		if (!cursor[SMALL_LOG]->valid)
			choice = BIG_LOG;
		else if (!cursor[BIG_LOG]->valid ||
			 compare_lsns(&cursor[SMALL_LOG]->entry.lsn, &cursor[BIG_LOG]->entry.lsn) < 0)
			choice = SMALL_LOG;

		const char *error_message = NULL;

		request_type op_type = !cursor[choice]->tombstone ? insertOp : deleteOp;
		serialized_insert_key_value(&handle, (const char *)kvs[choice]->par_kv, false, op_type, &error_message);

		if (error_message) {
			log_fatal("Insert failed reason = %s, exiting", error_message);
			BUG_ON();
		}

		kvs[choice] = get_next_log_entry(cursor[choice]);
	}
	close_log_cursor(cursor[SMALL_LOG]);
	close_log_cursor(cursor[BIG_LOG]);
}

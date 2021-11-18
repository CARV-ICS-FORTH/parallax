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
#include "../btree/btree.h"
#include "../btree/conf.h"
#include "../btree/segment_allocator.h"
#include "device_structures.h"
#include "log_structures.h"
#include "redo_undo_log.h"
#include "volume_manager.h"
#include <assert.h>
#include <list.h>
#include <log.h>
#include <signal.h>
#include <spin_loop.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*<new_persistent_design>*/
static void pr_flush_allocation_log_and_level_info(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	/*Flush my allocations*/
	struct rul_log_info rul_log = rul_flush_txn(db_desc, db_desc->levels[level_id].allocation_txn_id[tree_id]);
	/*new info about allocation_log*/
	db_desc->my_superblock.allocation_log.tail_dev_offt = rul_log.tail_dev_offt;
	db_desc->my_superblock.allocation_log.size = rul_log.size;
	db_desc->my_superblock.allocation_log.txn_id = rul_log.txn_id;
	/*new info about my level*/
	db_desc->my_superblock.root_r[level_id][tree_id] = ABSOLUTE_ADDRESS(db_desc->levels[level_id].root_r[tree_id]);
	db_desc->my_superblock.first_segment[level_id][0] =
		ABSOLUTE_ADDRESS(db_desc->levels[level_id].first_segment[tree_id]);
	db_desc->my_superblock.last_segment[level_id][tree_id] =
		ABSOLUTE_ADDRESS(db_desc->levels[level_id].last_segment[tree_id]);
	db_desc->my_superblock.offset[level_id][tree_id] = db_desc->levels[level_id].offset[tree_id];
	db_desc->my_superblock.level_size[level_id][tree_id] = db_desc->levels[level_id].level_size[tree_id];
	pr_flush_region_superblock(db_desc);
}

void pr_flush_L0(struct db_descriptor *db_desc, uint8_t tree_id)
{
	struct my_log_info {
		uint64_t head_dev_offt;
		uint64_t tail_dev_offt;
		uint64_t size;
	};

	struct my_log_info large_log;
	struct my_log_info L0_recovery_log;

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
	pr_flush_log_tail(db_desc, db_desc->my_volume, &db_desc->big_log);

	/*Flush L0 recovery log*/
	pr_flush_log_tail(db_desc, db_desc->my_volume, &db_desc->small_log);

	uint64_t my_txn_id = db_desc->levels[0].allocation_txn_id[tree_id];

	/*time to write superblock*/
	pr_lock_region_superblock(db_desc);
	/*Flush my allocations*/

	struct rul_log_info rul_log = rul_flush_txn(db_desc, my_txn_id);
	/*new info about large*/
	db_desc->my_superblock.big_log_tail_offt = large_log.tail_dev_offt;
	db_desc->my_superblock.big_log_size = large_log.size;
	/*new info about L0_recovery_log*/
	db_desc->my_superblock.small_log_head_offt = L0_recovery_log.head_dev_offt;
	db_desc->my_superblock.small_log_tail_offt = L0_recovery_log.tail_dev_offt;
	db_desc->my_superblock.small_log_size = L0_recovery_log.size;
	/*new info about allocation_log*/
	db_desc->my_superblock.allocation_log.tail_dev_offt = rul_log.tail_dev_offt;
	db_desc->my_superblock.allocation_log.size = rul_log.size;
	db_desc->my_superblock.allocation_log.txn_id = rul_log.txn_id;
	/*flush region superblock*/
	pr_flush_region_superblock(db_desc);

	pr_unlock_region_superblock(db_desc);

	MUTEX_UNLOCK(&db_desc->flush_L0_lock);
	rul_apply_txn_buf_freeops_and_destroy(db_desc, my_txn_id);
}

static void pr_flush_L0_to_L1(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	struct my_log_info {
		uint64_t tail_dev_offt;
		uint64_t size;
	};

	struct my_log_info medium_log;

	/*
   * Keep medium log state. We don't need to lock because ONLY one compaction
   * from L0 to L1 is allowed.
  */
	medium_log.tail_dev_offt = db_desc->medium_log.tail_dev_offt;
	medium_log.size = db_desc->medium_log.size;
	/*Flush medium log*/
	pr_flush_log_tail(db_desc, db_desc->my_volume, &db_desc->medium_log);
	pr_lock_region_superblock(db_desc);
	uint64_t my_txn_id = db_desc->levels[level_id].allocation_txn_id[tree_id];
	/*medium log info*/
	db_desc->my_superblock.medium_log_tail_offt = medium_log.tail_dev_offt;
	db_desc->my_superblock.medium_log_size = medium_log.size;

	/*trim L0_recovery_log*/
	struct segment_header *curr = REAL_ADDRESS(db_desc->my_superblock.small_log_tail_offt);
	log_info("Tail segment id %llu", curr->segment_id);
	curr = REAL_ADDRESS(curr->prev_segment);

	struct segment_header *head = REAL_ADDRESS(db_desc->my_superblock.small_log_head_offt);
	log_info("Head segment id %llu", head->segment_id);

	uint64_t bytes_freed = 0;
	while (curr && (uint64_t)curr->segment_id >= head->segment_id) {
		struct rul_log_entry E;
		E.dev_offt = ABSOLUTE_ADDRESS(curr);
		//log_info("Triming L0 recovery log segment:%llu curr segment id:%llu", E.dev_offt, curr->segment_id);
		E.txn_id = my_txn_id;
		E.op_type = RUL_FREE;
		E.size = SEGMENT_SIZE;
		rul_add_entry_in_txn_buf(db_desc, &E);
		bytes_freed += SEGMENT_SIZE;
		curr = REAL_ADDRESS(curr->prev_segment);
	}

	log_info("*** Freed a total of %llu MB bytes from trimming L0 recovery log head %llu tail %llu size %llu ***",
		 bytes_freed / (1024 * 1024), db_desc->my_superblock.small_log_head_offt,
		 db_desc->my_superblock.small_log_tail_offt, db_desc->my_superblock.small_log_size);

	db_desc->my_superblock.small_log_head_offt = db_desc->my_superblock.small_log_tail_offt;
	db_desc->small_log.head_dev_offt = db_desc->my_superblock.small_log_head_offt;

	pr_flush_allocation_log_and_level_info(db_desc, level_id, tree_id);
	pr_unlock_region_superblock(db_desc);
	rul_apply_txn_buf_freeops_and_destroy(db_desc, my_txn_id);
}

static void pr_flush_Lmax_to_Ln(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	log_info("Flushing Lmax to Ln!");
	struct level_descriptor *level_desc = &db_desc->levels[level_id];

	uint64_t my_txn_id = db_desc->levels[level_id].allocation_txn_id[tree_id];
	/*trim medium log*/
	struct segment_header *curr = REAL_ADDRESS(level_desc->medium_in_place_segment_dev_offt);
	//log_info("Max medium in place segment id %llu", curr->segment_id);
	curr = REAL_ADDRESS(curr->prev_segment);

	struct segment_header *head = REAL_ADDRESS(db_desc->medium_log.head_dev_offt);
	//log_info("Head of medium log segment id %llu", head->segment_id);

	uint64_t bytes_freed = 0;
	while (curr && (uint64_t)curr->segment_id >= head->segment_id) {
		struct rul_log_entry E;
		E.dev_offt = ABSOLUTE_ADDRESS(curr);
		//log_info("Triming medium log segment:%llu curr segment id:%llu", E.dev_offt, curr->segment_id);
		E.txn_id = my_txn_id;
		E.op_type = RUL_FREE;
		E.size = SEGMENT_SIZE;
		rul_add_entry_in_txn_buf(db_desc, &E);
		bytes_freed += SEGMENT_SIZE;
		curr = REAL_ADDRESS(curr->prev_segment);
	}

	log_info("*** Freed a total of %llu MB bytes from trimming medium log head %llu tail %llu size %llu ***",
		 bytes_freed / (1024 * 1024), db_desc->my_superblock.small_log_head_offt,
		 db_desc->my_superblock.small_log_tail_offt, db_desc->my_superblock.small_log_size);

	pr_lock_region_superblock(db_desc);

	/*new info about medium log after trim operation*/
	db_desc->medium_log.head_dev_offt = level_desc->medium_in_place_segment_dev_offt;
	db_desc->my_superblock.medium_log_head_offt = level_desc->medium_in_place_segment_dev_offt;
	level_desc->medium_in_place_segment_dev_offt = 0;
	level_desc->medium_in_place_max_segment_id = 0;
	pr_flush_allocation_log_and_level_info(db_desc, level_id, tree_id);

	pr_unlock_region_superblock(db_desc);
	rul_apply_txn_buf_freeops_and_destroy(db_desc, my_txn_id);
}

void pr_flush_compaction(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	if (level_id == 1)
		return pr_flush_L0_to_L1(db_desc, level_id, tree_id);

	if (level_id == LEVEL_MEDIUM_INPLACE)
		return pr_flush_Lmax_to_Ln(db_desc, level_id, tree_id);

	uint64_t my_txn_id = db_desc->levels[level_id].allocation_txn_id[tree_id];
	pr_lock_region_superblock(db_desc);

	pr_flush_allocation_log_and_level_info(db_desc, level_id, tree_id);

	pr_unlock_region_superblock(db_desc);
	rul_apply_txn_buf_freeops_and_destroy(db_desc, my_txn_id);
}

void pr_lock_region_superblock(struct db_descriptor *db_desc)
{
	MUTEX_LOCK(&db_desc->my_superblock_lock);
}

void pr_unlock_region_superblock(struct db_descriptor *db_desc)
{
	MUTEX_UNLOCK(&db_desc->my_superblock_lock);
}

void pr_flush_region_superblock(struct db_descriptor *db_desc)
{
	uint64_t my_superblock_offt =
		sizeof(struct superblock) + (sizeof(struct pr_region_superblock) + db_desc->my_superblock_idx);
	ssize_t total_bytes_written = 0;
	ssize_t bytes_written = 0;
	ssize_t size = sizeof(struct pr_region_superblock);
	while (total_bytes_written < size) {
		bytes_written = pwrite(db_desc->my_volume->my_fd, &db_desc->my_superblock, size - total_bytes_written,
				       my_superblock_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to write region's %s superblock", db_desc->my_superblock.region_name);
			perror("Reason");
			exit(EXIT_FAILURE);
		}
		total_bytes_written += bytes_written;
	}
}

void pr_read_region_superblock(struct db_descriptor *db_desc)
{
	//where is my superblock
	ssize_t total_bytes_written = 0;
	ssize_t bytes_written = 0;
	ssize_t size = sizeof(struct pr_region_superblock);
	uint64_t my_superblock_offt =
		sizeof(struct superblock) + (sizeof(struct pr_region_superblock) + db_desc->my_superblock_idx);

	while (total_bytes_written < size) {
		bytes_written = pwrite(db_desc->my_volume->my_fd, &db_desc->my_superblock, size - total_bytes_written,
				       my_superblock_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to read region's %s superblock", db_desc->my_superblock.region_name);
			perror("Reason");
			assert(0);
			exit(EXIT_FAILURE);
		}
		total_bytes_written += bytes_written;
	}
}
/*</new_persistent_design>*/

void pr_flush_log_tail(struct db_descriptor *db_desc, struct volume_descriptor *volume_desc,
		       struct log_descriptor *log_desc)
{
	(void)db_desc;
	(void)volume_desc;

#if 0
		/*These were hacks for fastmap to work due to its faulty behavior with direct I/O, remove them ASAP*/
		if (idx)
	{
		remaining_bytes = SEGMENT_SIZE - idx;
		memset(&log_desc->tail[last_tail]->buf[idx], 0, remaining_bytes);
		log_desc->size += remaining_bytes;
	}
	else
		return;

	int last_tail = log_desc->curr_tail_id % LOG_TAIL_NUM_BUFS;

	/*Barrier wait all previous operations to finish*/
	uint32_t chunk_id = offt_in_seg / LOG_CHUNK_SIZE;
	for (uint32_t i = 0; i < chunk_id; ++i)
		wait_for_value(&log_desc->tail[last_tail]->bytes_in_chunk[i], LOG_CHUNK_SIZE);
	for (int i = chunk_id; i < SEGMENT_SIZE / LOG_CHUNK_SIZE; ++i)
		log_desc->tail[last_tail]->bytes_in_chunk[i] = LOG_CHUNK_SIZE;
	log_desc->tail[last_tail]->IOs_completed_in_tail = SEGMENT_SIZE / LOG_CHUNK_SIZE;
#endif

	uint64_t offt_in_seg = log_desc->size % SEGMENT_SIZE;
	if (!offt_in_seg)
		return;

	int last_tail = log_desc->curr_tail_id % LOG_TAIL_NUM_BUFS;

	/*Barrier wait all previous operations to finish*/
	uint32_t chunk_id = offt_in_seg / LOG_CHUNK_SIZE;
	for (uint32_t i = 0; i < chunk_id; ++i)
		wait_for_value(&log_desc->tail[last_tail]->bytes_in_chunk[i], LOG_CHUNK_SIZE);

	uint64_t start_offt;
	if (chunk_id)
		start_offt = chunk_id * LOG_CHUNK_SIZE;
	else
		start_offt = sizeof(struct segment_header);

	ssize_t bytes_written = 0;
	uint64_t end_offt = start_offt + LOG_CHUNK_SIZE;
	while (start_offt < end_offt) {
		bytes_written = pwrite(FD, &log_desc->tail[last_tail]->buf[start_offt], end_offt - start_offt,
				       log_desc->tail[last_tail]->dev_offt + start_offt);

		if (bytes_written == -1) {
			log_fatal("Failed to write LOG_CHUNK reason follows");
			perror("Reason");
			exit(EXIT_FAILURE);
		}
		start_offt += bytes_written;
	}
}

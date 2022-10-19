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
#include "btree.h"
#include "../allocator/device_structures.h"
#include "../allocator/log_structures.h"
#include "../allocator/redo_undo_log.h"
#include "../allocator/volume_manager.h"
#include "../btree/kv_pairs.h"
#include "../common/common.h"
#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include "conf.h"
#include "dynamic_leaf.h"
#include "gc.h"
#include "index_node.h"
#include "lsn.h"
#include "segment_allocator.h"
#include "set_options.h"

#include <assert.h>
#include <inttypes.h>
#include <list.h>
#include <log.h>
#include <pthread.h>
#include <spin_loop.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;

/*number of locks per level*/
const uint32_t size_per_height[MAX_HEIGHT] = { 8192, 4096, 2048, 1024, 512, 256, 128, 64, 32 };

static uint8_t writers_join_as_readers(bt_insert_req *ins_req);
static uint8_t concurrent_insert(bt_insert_req *ins_req);

void assert_index_node(node_header *node);

struct bt_rebalance_result split_leaf(bt_insert_req *req, leaf_node *node);

int prefix_compare(char *l, char *r, size_t prefix_size)
{
	return memcmp(l, r, prefix_size);
}

void init_key_cmp(struct key_compare *key_cmp, void *key_buf, char key_format)
{
	key_cmp->is_NIL = key_buf == NULL;

	if (key_cmp->is_NIL == 1)
		return;

	if (key_format == KV_FORMAT) {
		struct kv_splice *key = (struct kv_splice *)key_buf;
		key_cmp->key_size = get_key_size(key);
		key_cmp->key = get_key_offset_in_kv(key);
		key_cmp->kv_dev_offt = UINT64_MAX;
		key_cmp->key_format = KV_FORMAT;
		return;
	}

	if (key_format == KV_PREFIX) {
		key_cmp->key_size = PREFIX_SIZE;
		key_cmp->key = ((struct kv_seperation_splice *)key_buf)->prefix;
		key_cmp->kv_dev_offt = ((struct kv_seperation_splice *)key_buf)->dev_offt;
		key_cmp->key_format = KV_PREFIX;
		return;
	}
	log_fatal("Unknown key category, exiting");
	BUG_ON();
}

/**
 * @param   index_key: address of the index_key
 * @param   index_key_len: length of the index_key in encoded form first 2
 * significant bytes row_key_size least 2 significant bytes quallifier size
 * @param   query_key: address of query_key
 * @param   query_key_len: query_key length again in encoded form
 */

int key_cmp(struct key_compare *key1, struct key_compare *key2)
{
	int ret;
	uint32_t size;
	/*we need the left most entry*/
	if (key2->is_NIL == 1)
		return 1;

	if (key1->is_NIL == 1)
		return -1;

	if (key1->key_format == KV_FORMAT && key2->key_format == KV_FORMAT) {
		size = key1->key_size <= key2->key_size ? key1->key_size : key2->key_size;

		ret = memcmp(key1->key, key2->key, size);
		if (ret != 0)
			return ret;

		return key1->key_size - key2->key_size;
	}

	if (key1->key_format == KV_FORMAT && key2->key_format == KV_PREFIX) {
		if (key1->key_size >= PREFIX_SIZE)
			ret = prefix_compare(key1->key, key2->key, PREFIX_SIZE);
		else
			ret = prefix_compare(key1->key, key2->key, key1->key_size);
		if (!ret)
			return ret;
		/*we have a tie, prefix didn't help, fetch query_key form KV log*/
		struct kv_format *key2f = (struct kv_format *)key2->kv_dev_offt;

		size = key1->key_size <= key2f->key_size ? key1->key_size : key2f->key_size;

		ret = memcmp(key1->key, key2f->key_buf, size);

		if (ret != 0)
			return ret;

		return key1->key_size - key2f->key_size;
	}

	if (key1->key_format == KV_PREFIX && key2->key_format == KV_FORMAT) {
		if (key2->key_size >= PREFIX_SIZE)
			ret = prefix_compare(key1->key, key2->key, PREFIX_SIZE);
		else // check here TODO
			ret = prefix_compare(key1->key, key2->key, key2->key_size);

		if (!ret)
			return ret;
		/* we have a tie, prefix didn't help, fetch query_key form KV log*/
		struct kv_format *key1f = (struct kv_format *)key1->kv_dev_offt;

		size = key1f->key_size < key2->key_size ? key1f->key_size : key2->key_size;

		ret = memcmp(key1f->key_buf, key2->key, size);
		if (ret != 0)
			return ret;

		return key1f->key_size - key2->key_size;
	}

	/*KV_PREFIX and KV_PREFIX*/
	ret = prefix_compare(key1->key, key2->key, PREFIX_SIZE);
	if (ret != 0)
		return ret;
	/*full comparison*/
	struct kv_format *key1f = (struct kv_format *)key1->kv_dev_offt;
	struct kv_format *key2f = (struct kv_format *)key2->kv_dev_offt;

	size = key1f->key_size < key2f->key_size ? key1f->key_size : key2f->key_size;

	ret = memcmp(key1f->key_buf, key2f->key_buf, size);
	if (ret != 0)
		return ret;

	return key1f->key_size - key2f->key_size;
}

static void init_level_locktable(db_descriptor *database, uint8_t level_id)
{
	for (unsigned int i = 0; i < MAX_HEIGHT; ++i) {
		if (posix_memalign((void **)&database->levels[level_id].level_lock_table[i], 4096,
				   sizeof(lock_table) * size_per_height[i]) != 0) {
			log_fatal("memalign failed");
			BUG_ON();
		}

		lock_table *init = database->levels[level_id].level_lock_table[i];

		for (unsigned int j = 0; j < size_per_height[i]; ++j) {
			if (RWLOCK_INIT(&init[j].rx_lock, NULL) != 0) {
				log_fatal("failed to initialize lock_table for level %u lock", level_id);
				BUG_ON();
			}
		}
	}
}

static void calculate_metadata_offsets(uint32_t bitmap_entries, uint32_t slot_array_entries, uint32_t kv_entries,
				       struct leaf_node_metadata *leaf_level)
{
	leaf_level->bitmap_entries = bitmap_entries;
	leaf_level->bitmap_offset = sizeof(struct bt_static_leaf_node);
	leaf_level->slot_array_entries = slot_array_entries;
	leaf_level->slot_array_offset =
		leaf_level->bitmap_offset + (bitmap_entries * sizeof(struct bt_leaf_entry_bitmap));
	leaf_level->kv_entries = kv_entries;
	leaf_level->kv_entries_offset = leaf_level->bitmap_offset +
					(bitmap_entries * sizeof(struct bt_leaf_entry_bitmap)) +
					(slot_array_entries * sizeof(struct bt_static_leaf_slot_array));
}

static void init_leaf_sizes_perlevel(level_descriptor *level)
{
	double kv_leaf_entry =
		get_kv_seperated_splice_size() + sizeof(struct bt_static_leaf_slot_array) + (1 / CHAR_BIT);
	double numentries_without_metadata = 0;
	uint32_t bitmap_entries = 0;
	uint32_t slot_array_entries = 0;
	uint32_t kv_entries = 0;

	numentries_without_metadata = (level->leaf_size - sizeof(struct bt_static_leaf_node)) / kv_leaf_entry;
	bitmap_entries = (numentries_without_metadata / CHAR_BIT) + 1;
	slot_array_entries = numentries_without_metadata;
	kv_entries = (level->leaf_size - sizeof(struct bt_static_leaf_node) - bitmap_entries -
		      (slot_array_entries * sizeof(struct bt_static_leaf_slot_array))) /
		     get_kv_seperated_splice_size();
	calculate_metadata_offsets(bitmap_entries, slot_array_entries, kv_entries, &level->leaf_offsets);
}

static void destroy_level_locktable(db_descriptor *database, uint8_t level_id)
{
	for (uint8_t i = 0; i < MAX_HEIGHT; ++i)
		free(database->levels[level_id].level_lock_table[i]);
}

static void pr_read_log_tail(struct log_tail *tail)
{
	ssize_t bytes_read = 0;
	while (bytes_read < SEGMENT_SIZE) {
		ssize_t bytes =
			pread(tail->fd, &tail->buf[bytes_read], SEGMENT_SIZE - bytes_read, tail->dev_offt + bytes_read);
		if (bytes == -1) {
			log_fatal("Failed to read error code");
			perror("Error");
			BUG_ON();
		}
		bytes_read += bytes;
	}
}

struct bt_kv_log_address bt_get_kv_log_address(struct log_descriptor *log_desc, uint64_t dev_offt)
{
	struct bt_kv_log_address reply = { .addr = NULL, .tail_id = 0, .in_tail = UINT8_MAX, .log_desc = NULL };
	RWLOCK_RDLOCK(&log_desc->log_tail_buf_lock);

	for (int i = 0; i < LOG_TAIL_NUM_BUFS; ++i) {
		if (log_desc->tail[i]->free)
			continue;

		if (dev_offt >= log_desc->tail[i]->start && dev_offt <= log_desc->tail[i]->end) {
			__sync_fetch_and_add(&log_desc->tail[i]->pending_readers, 1);
			reply.in_tail = 1;

			//log_info("KV at tail %d ! offt %llu in the device or %llu inside the segment key size: %u", i,
			//	 dev_offt, dev_offt % SEGMENT_SIZE,
			//	 *(uint32_t *)&log_desc->tail[i]->buf[dev_offt % SEGMENT_SIZE]);

			reply.addr = &(log_desc->tail[i]->buf[dev_offt % SEGMENT_SIZE]);
			reply.tail_id = i;
			reply.log_desc = log_desc;
			RWLOCK_UNLOCK(&log_desc->log_tail_buf_lock);
			return reply;
		}
		// log_info("KV NOT at tail %d! DB: %s offt %llu start %llu end %llu", i,
		// db_desc->db_name, dev_offt,
		//	 db_desc->log_tail_buf[i]->start, db_desc->log_tail_buf[i]->end);
	}

	reply.in_tail = 0;
	RWLOCK_UNLOCK(&log_desc->log_tail_buf_lock);
	reply.addr = REAL_ADDRESS(dev_offt);
	reply.tail_id = UINT8_MAX;
	return reply;
}

void bt_done_with_value_log_address(struct log_descriptor *log_desc, struct bt_kv_log_address *L)
{
	assert(log_desc->tail[L->tail_id]->pending_readers > 0);
	__sync_fetch_and_sub(&log_desc->tail[L->tail_id]->pending_readers, 1);
}

// cppcheck-suppress unusedFunction
struct bt_kv_log_address bt_get_kv_medium_log_address(struct log_descriptor *log_desc, uint64_t dev_offt)
{
	struct bt_kv_log_address reply = { .addr = NULL, .tail_id = 0, .in_tail = UINT8_MAX };
	assert(dev_offt != 0);
	for (int i = 0; i < LOG_TAIL_NUM_BUFS; ++i) {
		if (log_desc->tail[i]->free)
			continue;

		if (dev_offt >= log_desc->tail[i]->start && dev_offt <= log_desc->tail[i]->end) {
			reply.in_tail = 1;
			// log_info("KV at tail! offt %llu in the device or %llu", dev_offt,
			// dev_offt % SEGMENT_SIZE);
			reply.addr = &log_desc->tail[i]->buf[dev_offt % SEGMENT_SIZE];
			reply.tail_id = i;
			return reply;
		}
		// log_info("KV NOT at tail %d! DB: %s offt %llu start %llu end %llu", i,
		// db_desc->db_name, dev_offt,
		//	 db_desc->log_tail_buf[i]->start, db_desc->log_tail_buf[i]->end);
	}

	reply.in_tail = 0;
	reply.addr = REAL_ADDRESS(dev_offt);
	reply.tail_id = UINT8_MAX;
	return reply;
}

// cppcheck-suppress unusedFunction
void init_level_bloom_filters(db_descriptor *db_desc, int level_id, int tree_id)
{
#if ENABLE_BLOOM_FILTERS
	memset(&db_desc->levels[level_id].bloom_filter[tree_id], 0x00, sizeof(struct bloom));
#else
	(void)db_desc;
	(void)level_id;
	(void)tree_id;
#endif
}

static void destroy_log_buffer(struct log_descriptor *log_desc)
{
	for (uint32_t i = 0; i < LOG_TAIL_NUM_BUFS; ++i)
		free(log_desc->tail[i]);
}

void init_log_buffer(struct log_descriptor *log_desc, enum log_type log_type)
{
	// Just update the chunk counters according to the log size
	if (RWLOCK_INIT(&log_desc->log_tail_buf_lock, NULL) != 0) {
		log_fatal("Failed to init lock");
		BUG_ON();
	}

	for (int i = 0; i < LOG_TAIL_NUM_BUFS; ++i) {
		if (posix_memalign((void **)&log_desc->tail[i], SEGMENT_SIZE, sizeof(struct log_tail)) != 0) {
			log_fatal("Failed to allocate log buffer for direct IO");
			BUG_ON();
		}
		memset(log_desc->tail[i], 0x00, sizeof(struct log_tail));
		log_desc->tail[i]->free = 1;
		log_desc->tail[i]->fd = FD;
	}
	log_desc->log_type = log_type;

	// Special action for 0
	log_desc->tail[0]->dev_offt = log_desc->tail_dev_offt;
	log_desc->tail[0]->start = log_desc->tail_dev_offt;
	log_desc->tail[0]->end = log_desc->tail[0]->start + SEGMENT_SIZE;
	log_desc->tail[0]->free = 0;

	// Recover log
	pr_read_log_tail(log_desc->tail[0]);

	// set proper accounting
	uint64_t offt_in_seg = log_desc->size % SEGMENT_SIZE;
	uint32_t n_chunks = offt_in_seg / LOG_CHUNK_SIZE;
	uint32_t i = 0;
	for (; i < n_chunks; ++i) {
		log_desc->tail[0]->bytes_in_chunk[i] = LOG_CHUNK_SIZE;
		++log_desc->tail[0]->IOs_completed_in_tail;
		log_info("bytes_in_chunk[%u] = %u", i, log_desc->tail[0]->bytes_in_chunk[i]);
	}
	if (offt_in_seg > 0 && offt_in_seg % LOG_CHUNK_SIZE != 0) {
		log_desc->tail[0]->bytes_in_chunk[i] = offt_in_seg % LOG_CHUNK_SIZE;
	}
}

static void init_fresh_logs(struct db_descriptor *db_desc)
{
	log_info("Initializing KV logs (small,medium,large) for DB: %s", db_desc->db_superblock->db_name);
	// Large log
	struct segment_header *s = seg_get_raw_log_segment(db_desc, BIG_LOG, 0, 0);
	db_desc->big_log.head_dev_offt = ABSOLUTE_ADDRESS(s);
	db_desc->big_log.tail_dev_offt = db_desc->big_log.head_dev_offt;
	db_desc->big_log.size = 0;
	db_desc->big_log_start_segment_dev_offt = db_desc->big_log.tail_dev_offt;
	db_desc->big_log_start_offt_in_segment = db_desc->big_log.size % SEGMENT_SIZE;
	init_log_buffer(&db_desc->big_log, BIG_LOG);
	log_info("BIG_LOG head %lu", db_desc->big_log.head_dev_offt);

	// Medium log
	db_desc->medium_log.head_dev_offt = 0;
	db_desc->medium_log.tail_dev_offt = 0;
	db_desc->medium_log.size = 0;
#if 0
	s = seg_get_raw_log_segment(db_desc);
	s->segment_id = 0;
	s->next_segment = NULL;
	s->prev_segment = NULL;
	db_desc->medium_log.head_dev_offt = ABSOLUTE_ADDRESS(s);
	db_desc->medium_log.tail_dev_offt = db_desc->medium_log.head_dev_offt;
	db_desc->medium_log.size = sizeof(segment_header);
	init_log_buffer(&db_desc->medium_log, MEDIUM_LOG);
#endif

	// Small log
	s = seg_get_raw_log_segment(db_desc, SMALL_LOG, 0, 0);
	db_desc->small_log.head_dev_offt = ABSOLUTE_ADDRESS(s);
	db_desc->small_log.tail_dev_offt = db_desc->small_log.head_dev_offt;
	db_desc->small_log.size = sizeof(segment_header);
	db_desc->small_log_start_segment_dev_offt = db_desc->small_log.tail_dev_offt;
	db_desc->small_log_start_offt_in_segment = db_desc->small_log.size % SEGMENT_SIZE;

	init_log_buffer(&db_desc->small_log, SMALL_LOG);
	struct segment_header *seg_in_mem = (struct segment_header *)db_desc->small_log.tail[0]->buf;
	seg_in_mem->segment_id = 0;
	seg_in_mem->prev_segment = NULL;
	seg_in_mem->next_segment = NULL;
	db_desc->lsn_factory = lsn_factory_init(0);
}

static void init_fresh_db(struct db_descriptor *db_desc)
{
	struct pr_db_superblock *superblock = db_desc->db_superblock;

	/*init now state for all levels*/
	for (uint8_t level_id = 0; level_id < MAX_LEVELS; ++level_id) {
		db_desc->levels[level_id].level_size[0] = 0;
		db_desc->levels[level_id].level_size[1] = 0;

		for (uint8_t tree_id = 0; tree_id < NUM_TREES_PER_LEVEL; ++tree_id) {
			db_desc->levels[level_id].level_size[tree_id] = 0;
			/*segments info per level*/

			db_desc->levels[level_id].first_segment[tree_id] = 0;
			superblock->first_segment[level_id][tree_id] = 0;

			db_desc->levels[level_id].last_segment[tree_id] = 0;
			superblock->last_segment[level_id][tree_id] = 0;

			db_desc->levels[level_id].offset[tree_id] = 0;
			superblock->offset[level_id][tree_id] = 0;

			/*total keys*/
			db_desc->levels[level_id].level_size[tree_id] = 0;
			superblock->level_size[level_id][tree_id] = 0;
			/*finally the roots*/
			db_desc->levels[level_id].root_r[tree_id] = NULL;
			db_desc->levels[level_id].root_w[tree_id] = NULL;
			superblock->root_r[level_id][tree_id] = 0;
		}
	}

	init_fresh_logs(db_desc);
}

static void recover_logs(db_descriptor *db_desc)
{
	log_info("Recovering KV logs (small,medium,large) for DB: %s", db_desc->db_superblock->db_name);

	// Small log
	db_desc->small_log.head_dev_offt = db_desc->db_superblock->small_log_head_offt;
	db_desc->small_log.tail_dev_offt = db_desc->db_superblock->small_log_tail_offt;
	db_desc->small_log.size = db_desc->db_superblock->small_log_size;
	init_log_buffer(&db_desc->small_log, SMALL_LOG);

	// Medium log
	db_desc->medium_log.head_dev_offt = db_desc->db_superblock->medium_log_head_offt;
	db_desc->medium_log.tail_dev_offt = db_desc->db_superblock->medium_log_tail_offt;
	db_desc->medium_log.size = db_desc->db_superblock->medium_log_size;
	init_log_buffer(&db_desc->medium_log, MEDIUM_LOG);

	// Big log
	db_desc->big_log.head_dev_offt = db_desc->db_superblock->big_log_head_offt;
	db_desc->big_log.tail_dev_offt = db_desc->db_superblock->big_log_tail_offt;
	db_desc->big_log.size = db_desc->db_superblock->big_log_size;
	init_log_buffer(&db_desc->big_log, BIG_LOG);
	int64_t last_lsn_id = get_lsn_id(&db_desc->db_superblock->last_lsn);
	db_desc->lsn_factory = lsn_factory_init(last_lsn_id);
}

static void restore_db(struct db_descriptor *db_desc, uint32_t region_idx)
{
	/*First, calculate superblock offt and read it in memory*/
	db_desc->db_superblock_idx = region_idx;
	pr_read_db_superblock(db_desc);
	db_desc->small_log_start_segment_dev_offt = db_desc->db_superblock->small_log_start_segment_dev_offt;
	db_desc->small_log_start_offt_in_segment = db_desc->db_superblock->small_log_offt_in_start_segment;
	db_desc->big_log_start_segment_dev_offt = db_desc->db_superblock->big_log_start_segment_dev_offt;
	db_desc->big_log_start_offt_in_segment = db_desc->db_superblock->big_log_offt_in_start_segment;

	struct pr_db_superblock *superblock = db_desc->db_superblock;

	/*restore now persistent state of all levels*/
	for (uint8_t level_id = 0; level_id < MAX_LEVELS; level_id++) {
		db_desc->levels[level_id].level_size[0] = 0;
		db_desc->levels[level_id].level_size[1] = 0;

		for (uint8_t tree_id = 0; tree_id < NUM_TREES_PER_LEVEL; tree_id++) {
			db_desc->levels[level_id].level_size[tree_id] = 0;
			db_desc->levels[level_id].epoch[tree_id] = 0;
			/*segments info per level*/
			if (superblock->first_segment[level_id][tree_id] != 0) {
				db_desc->levels[level_id].first_segment[tree_id] =
					(segment_header *)REAL_ADDRESS(superblock->first_segment[level_id][tree_id]);

				db_desc->levels[level_id].last_segment[tree_id] =
					(segment_header *)REAL_ADDRESS(superblock->last_segment[level_id][tree_id]);

				db_desc->levels[level_id].offset[tree_id] = superblock->offset[level_id][tree_id];
				log_info("Superblock of db: %s first_segment dev offt: %lu", superblock->db_name,
					 superblock->first_segment[level_id][tree_id]);
				log_info("Restoring level[%u][%u] first segment %p last segment: %p size: %lu",
					 level_id, tree_id, (void *)db_desc->levels[level_id].first_segment[tree_id],
					 (void *)db_desc->levels[level_id].last_segment[tree_id],
					 db_desc->levels[level_id].offset[tree_id]);
			} else {
				//log_info("Restoring EMPTY level[%u][%u]", level_id, tree_id);
				db_desc->levels[level_id].first_segment[tree_id] = NULL;
				db_desc->levels[level_id].last_segment[tree_id] = NULL;
				db_desc->levels[level_id].offset[tree_id] = 0;
			}
			/*total keys*/
			db_desc->levels[level_id].level_size[tree_id] = superblock->level_size[level_id][tree_id];
			/*finally the roots*/
			if (superblock->root_r[level_id][tree_id] != 0)
				db_desc->levels[level_id].root_r[tree_id] =
					(node_header *)REAL_ADDRESS(superblock->root_r[level_id][tree_id]);
			else
				db_desc->levels[level_id].root_r[tree_id] = NULL;

			db_desc->levels[level_id].root_w[tree_id] = db_desc->levels[level_id].root_r[tree_id];
			if (db_desc->levels[level_id].root_r[tree_id])
				log_info("Restored root[%u][%u] = %p", level_id, tree_id,
					 (void *)db_desc->levels[level_id].root_r[tree_id]);
		}
	}

	recover_logs(db_desc);
}

static db_descriptor *get_db_from_volume(char *volume_name, char *db_name, par_db_initializers create_db)
{
	struct db_descriptor *db_desc = NULL;
	struct volume_descriptor *volume_desc = mem_get_volume_desc(volume_name);
	struct pr_db_superblock *db_superblock = NULL;
	uint8_t new_db = 0;

	//TODO Refactor get_db_superblock -> Takes too much arguments -> create a struct
	db_superblock =
		get_db_superblock(volume_desc, db_name, strlen(db_name) + 1, PAR_CREATE_DB == create_db, &new_db);

	if (db_superblock) {
		int ret = posix_memalign((void **)&db_desc, ALIGNMENT_SIZE, sizeof(struct db_descriptor));
		if (ret) {
			log_fatal("Failed to allocate db_descriptor");
			BUG_ON();
		}
		memset(db_desc, 0x00, sizeof(struct db_descriptor));
		db_desc->db_volume = volume_desc;
		db_desc->db_superblock = db_superblock;

		if (!new_db) {
			log_info("Found DB: %s recovering its allocation log", db_name);
			db_desc->dirty = 0;
			rul_log_init(db_desc);
			restore_db(db_desc, db_desc->db_superblock->id);
		} else {
			db_desc->dirty = 1;
			log_info("Initializing new DB: %s, initializing its allocation log", db_name);
			rul_log_init(db_desc);
			db_desc->levels[0].allocation_txn_id[0] = rul_start_txn(db_desc);

			log_info("Got txn %lu for the initialization of Large and L0_recovery_logs of DB: %s",
				 db_desc->levels[0].allocation_txn_id[0], db_name);

			//init_fresh_db allocates space for the L0_recovery log and large.
			//As a result we need to acquire a txn_id for the L0
			init_fresh_db(db_desc);
		}
	} else
		log_info("DB: %s NOT found", db_name);
	return db_desc;
}

db_handle *internal_db_open(struct volume_descriptor *volume_desc, par_db_options *db_options,
			    const char **error_message)
{
	struct db_handle *handle = NULL;
	const uint32_t leaf_size_per_level[10] = { LEVEL0_LEAF_SIZE, LEVEL1_LEAF_SIZE, LEVEL2_LEAF_SIZE,
						   LEVEL3_LEAF_SIZE, LEVEL4_LEAF_SIZE, LEVEL5_LEAF_SIZE,
						   LEVEL6_LEAF_SIZE, LEVEL7_LEAF_SIZE };
	struct db_descriptor *db = NULL;

	log_info("Using Volume name = %s to open db with name = %s", volume_desc->volume_name, db_options->db_name);

#if DISABLE_LOGGING
	log_set_quiet(true);
#endif
	index_node_get_size();
	_Static_assert(sizeof(struct segment_header) == 4096, "Segment header is not 4 KB");
	db = klist_find_element_with_key(volume_desc->open_databases, (char *)db_options->db_name);

	if (db != NULL) {
		*error_message = "DB already open for volume";
		handle = calloc(1, sizeof(struct db_handle));
		handle->volume_desc = volume_desc;
		handle->db_desc = db;
		//deep copy db_options
		memcpy(&handle->db_options, db_options, sizeof(struct par_db_options));
		++handle->db_desc->reference_count;
		goto exit;
	}

	struct db_descriptor *db_desc =
		get_db_from_volume(volume_desc->volume_name, (char *)db_options->db_name, db_options->create_flag);
	if (!db_desc) {
		handle = NULL;

		if (PAR_CREATE_DB == db_options->create_flag)
			*error_message = "Sorry no room for new DB";

		if (PAR_DONOT_CREATE_DB == db_options->create_flag)
			*error_message = "DB not found instructed not to create a new one";

		goto exit;
	}

	db_desc->level_medium_inplace = db_options->options[LEVEL_MEDIUM_INPLACE].value;
	handle = calloc(1, sizeof(db_handle));
	handle->db_desc = db_desc;
	handle->volume_desc = db_desc->db_volume;
	//deep copy db_options
	memcpy(&handle->db_options, db_options, sizeof(struct par_db_options));

	uint64_t level0_size = handle->db_options.options[LEVEL0_SIZE].value;
	uint64_t growth_factor = handle->db_options.options[GROWTH_FACTOR].value;

	handle->db_desc->levels[0].max_level_size = level0_size;
	/*init soft state for all levels*/
	for (uint8_t level_id = 1; level_id < MAX_LEVELS; level_id++) {
		init_leaf_sizes_perlevel(&handle->db_desc->levels[level_id]);

		handle->db_desc->levels[level_id].max_level_size =
			handle->db_desc->levels[level_id - 1].max_level_size * growth_factor;

		log_info("DB:Level %d max_total_size %lu", level_id, handle->db_desc->levels[level_id].max_level_size);
	}
	handle->db_desc->levels[MAX_LEVELS - 1].max_level_size = UINT64_MAX;
	handle->db_desc->reference_count = 1;

	MUTEX_INIT(&handle->db_desc->compaction_lock, NULL);
	MUTEX_INIT(&handle->db_desc->compaction_structs_lock, NULL);
	MUTEX_INIT(&handle->db_desc->segment_ht_lock, NULL);
	pthread_cond_init(&handle->db_desc->compaction_cond, NULL);
	handle->db_desc->blocked_clients = 0;
	handle->db_desc->compaction_count = 0;
	handle->db_desc->is_compaction_daemon_sleeping = 0;
	handle->db_desc->segment_ht = NULL;
#if MEASURE_MEDIUM_INPLACE
	db_desc->count_medium_inplace = 0;
#endif

	if (sem_init(&handle->db_desc->compaction_sem, 0, 0) != 0) {
		log_fatal("Semaphore cannot be initialized");
		BUG_ON();
	}
	if (sem_init(&handle->db_desc->compaction_daemon_sem, 0, 0) != 0) {
		log_fatal("FATAL semaphore cannot be initialized");
		BUG_ON();
	}

	for (uint8_t level_id = 0; level_id < MAX_LEVELS; ++level_id) {
		RWLOCK_INIT(&handle->db_desc->levels[level_id].guard_of_level.rx_lock, NULL);
		MUTEX_INIT(&handle->db_desc->levels[level_id].level_allocation_lock, NULL);
		init_level_locktable(handle->db_desc, level_id);
		memset(handle->db_desc->levels[level_id].level_size, 0, sizeof(uint64_t) * NUM_TREES_PER_LEVEL);
		handle->db_desc->levels[level_id].medium_log_size = 0;
		handle->db_desc->levels[level_id].active_operations = 0;
		/*check again which tree should be active*/
		handle->db_desc->levels[level_id].active_tree = 0;
		handle->db_desc->levels[level_id].level_id = level_id;
		handle->db_desc->levels[level_id].leaf_size = leaf_size_per_level[level_id];
		handle->db_desc->levels[level_id].scanner_epoch = 0;
#if MEASURE_SST_USED_SPACE
		db_desc->levels[level_id].avg_leaf_used_space = 0;
		db_desc->levels[level_id].leaf_used_space = 0;
		db_desc->levels[level_id].count_leaves = 0;
		db_desc->levels[level_id].count_compactions = 0;
#endif
		for (uint8_t tree_id = 0; tree_id < NUM_TREES_PER_LEVEL; tree_id++) {
			handle->db_desc->levels[level_id].tree_status[tree_id] = NO_COMPACTION;
			handle->db_desc->levels[level_id].epoch[tree_id] = 0;
#if ENABLE_BLOOM_FILTERS
			init_level_bloom_filters(db_desc, level_id, tree_id);
#endif
		}
	}

	_Static_assert(BIG_INLOG < 4, "KV categories number cannot be "
				      "stored in 2 bits, increase "
				      "key_category");
	_Static_assert(sizeof(struct bt_dynamic_leaf_slot_array) == 2,
		       "Dynamic slot array is not 2 bytes, are you sure you want to continue?");
	_Static_assert(sizeof(struct segment_header) == 4096, "Segment header not page aligned!");
	_Static_assert(LOG_TAIL_NUM_BUFS >= 2, "Minimum number of in memory log buffers!");

	MUTEX_INIT(&handle->db_desc->lock_log, NULL);

	klist_add_first(volume_desc->open_databases, handle->db_desc, handle->db_options.db_name, NULL);
	handle->db_desc->db_state = DB_OPEN;

	log_info("Opened DB %s starting its compaction daemon", handle->db_options.db_name);

	sem_init(&handle->db_desc->compaction_daemon_interrupts, PTHREAD_PROCESS_PRIVATE, 0);

	if (pthread_create(&(handle->db_desc->compaction_daemon), NULL, compaction_daemon, (void *)handle) != 0) {
		log_fatal("Failed to start compaction_daemon for db %s", handle->db_options.db_name);
		BUG_ON();
	}

	handle->db_desc->gc_scanning_db = false;
	if (!volume_desc->gc_thread_spawned) {
		if (pthread_create(&(handle->db_desc->gc_thread), NULL, gc_log_entries, (void *)handle) != 0) {
			log_fatal("Failed to start garbage collection thread for db %s", handle->db_options.db_name);
			BUG_ON();
		}
		++volume_desc->gc_thread_spawned;
	}
	assert(volume_desc->gc_thread_spawned <= 1);

	/*get allocation transaction id for level-0*/
	MUTEX_INIT(&handle->db_desc->flush_L0_lock, NULL);
	pr_flush_L0(db_desc, db_desc->levels[0].active_tree);
	db_desc->levels[0].allocation_txn_id[db_desc->levels[0].active_tree] = rul_start_txn(db_desc);
	recover_L0(handle->db_desc);

exit:
	return handle;
}

db_handle *db_open(par_db_options *db_options, const char **error_message)
{
	MUTEX_LOCK(&init_lock);
	struct volume_descriptor *volume_desc = mem_get_volume_desc(db_options->volume_name);
	if (!volume_desc) {
		*error_message = "Failed to open volume %s";
		return NULL;
	}
	assert(volume_desc->open_databases);

	db_handle *handle = internal_db_open(volume_desc, db_options, error_message);

	MUTEX_UNLOCK(&init_lock);
	return handle;
}

const char *db_close(db_handle *handle)
{
	const char *error_message = NULL;
	MUTEX_LOCK(&init_lock);
	/*verify that this is a valid db*/
	int not_valid_db = klist_find_element_with_key(handle->volume_desc->open_databases,
						       handle->db_desc->db_superblock->db_name) == NULL;

	if (not_valid_db) {
		error_message = "Received close for db that is not listed as open";
		goto finish;
	}

	--handle->db_desc->reference_count;
	// We need to wait for the garbage collection thread to stop working on the db
	// otherwise we could leave this db in an undefined state where it will never close.
	// Scenario is -> db_close is called while gc is having a reference to the db and
	// when it decreases the reference the handle is never closed.
	while (handle->db_desc->gc_scanning_db) {
		MUTEX_UNLOCK(&init_lock);
		sleep(1);
		MUTEX_LOCK(&init_lock);
	}
	if (handle->db_desc->reference_count < 0) {
		log_fatal("Negative referece count for DB %s", handle->db_desc->db_superblock->db_name);
		BUG_ON();
	}
	if (handle->db_desc->reference_count > 0) {
		error_message = "Sorry more guys uses this DB";
		MUTEX_UNLOCK(&init_lock);
		return error_message;
	}
	/*Remove so it is not visible by the GC thread*/
	if (!klist_remove_element(handle->volume_desc->open_databases, handle->db_desc)) {
		log_fatal("Failed to remove db_desc of DB %s", handle->db_desc->db_superblock->db_name);
		BUG_ON();
	}

	log_info("Closing DB: %s\n", handle->db_desc->db_superblock->db_name);

	/*New requests will eventually see that db is closing*/
	/*wake up possible clients that are stack due to non-availability of L0*/
	MUTEX_LOCK(&handle->db_desc->client_barrier_lock);
	handle->db_desc->db_state = DB_IS_CLOSING;
	if (pthread_cond_broadcast(&handle->db_desc->client_barrier) != 0) {
		log_fatal("Failed to wake up stopped clients");
		BUG_ON();
	}
	MUTEX_UNLOCK(&handle->db_desc->client_barrier_lock);

	/*stop log appenders*/

	/*stop all writers at all levels and wait for all clients to complete their operations.*/

	for (uint8_t level_id = 0; level_id < MAX_LEVELS; level_id++) {
		RWLOCK_WRLOCK(&handle->db_desc->levels[level_id].guard_of_level.rx_lock);
		spin_loop(&(handle->db_desc->levels[level_id].active_operations), 0);
	}

	handle->db_desc->db_state = DB_TERMINATE_COMPACTION_DAEMON;
	sem_post(&handle->db_desc->compaction_daemon_interrupts);
	while (handle->db_desc->db_state != DB_IS_CLOSING)
		usleep(50);

	log_info("Ok compaction daemon exited continuing the close sequence of DB:%s",
		 handle->db_desc->db_superblock->db_name);

	/* Release the locks for all levels to allow pending compactions to complete. */
	for (uint8_t level_id = 0; level_id < MAX_LEVELS; level_id++)
		RWLOCK_UNLOCK(&handle->db_desc->levels[level_id].guard_of_level.rx_lock);

	/*Level 0 compactions*/
	for (uint8_t i = 0; i < NUM_TREES_PER_LEVEL; ++i) {
		if (handle->db_desc->levels[0].tree_status[i] == COMPACTION_IN_PROGRESS) {
			i = 0;
			usleep(500);
			continue;
		}
	}

	log_info("All L0 compactions done");

	/*wait for all other pending compactions to finish*/
	for (uint8_t i = 1; i < MAX_LEVELS; i++) {
		if (COMPACTION_IN_PROGRESS == handle->db_desc->levels[i].tree_status[0]) {
			i = 1;
			usleep(500);
			continue;
		}
	}
	pr_flush_L0(handle->db_desc, handle->db_desc->levels[0].active_tree);

	log_info("All pending compactions done for DB:%s", handle->db_desc->db_superblock->db_name);

	destroy_log_buffer(&handle->db_desc->big_log);
	destroy_log_buffer(&handle->db_desc->medium_log);
	destroy_log_buffer(&handle->db_desc->small_log);
	rul_log_destroy(handle->db_desc);

	/*free L0*/
	for (uint8_t tree_id = 0; tree_id < NUM_TREES_PER_LEVEL; ++tree_id)
		seg_free_level(handle->db_desc, 0, 0, tree_id);

	for (uint8_t i = 0; i < MAX_LEVELS; ++i) {
		if (pthread_rwlock_destroy(&handle->db_desc->levels[i].guard_of_level.rx_lock)) {
			log_fatal("Failed to destroy guard of level lock");
			BUG_ON();
		}
		destroy_level_locktable(handle->db_desc, i);
	}
	// memset(handle->db_desc, 0x00, sizeof(struct db_descriptor));
	if (pthread_cond_destroy(&handle->db_desc->client_barrier) != 0) {
		log_fatal("Failed to destroy condition variable");
		perror("pthread_cond_destroy() error");
		BUG_ON();
	}

	free(handle->db_desc);
finish:

	MUTEX_UNLOCK(&init_lock);
	free(handle);
	return error_message;
}

/**
 *  When all trees on level 0 are full and compactions cannot keep up with clients
 *  this functions blocks clients from writing in any of the level 0 roots.
 *  Assumes that the caller has acquired rwlock of level 0.
 *  @param level_id The level in the LSM tree.
 *  @param rwlock If 1 locks the guard of level 0 as a read lock. If 0 locks the guard of level 0 as a write lock.
 *  */
void wait_for_available_level0_tree(db_handle *handle, uint8_t level_id, uint8_t rwlock)
{
	if (level_id > 0)
		return;

	int active_tree = handle->db_desc->levels[0].active_tree;

	uint8_t relock = 0;
	while (handle->db_desc->levels[0].level_size[active_tree] > handle->db_desc->levels[0].max_level_size) {
		active_tree = handle->db_desc->levels[0].active_tree;
		if (handle->db_desc->levels[0].level_size[active_tree] > handle->db_desc->levels[0].max_level_size) {
			if (!relock) {
				/* Release the lock of level 0 to allow compactions to progress. */
				RWLOCK_UNLOCK(&handle->db_desc->levels[0].guard_of_level.rx_lock);
				relock = 1;
			}

			MUTEX_LOCK(&handle->db_desc->client_barrier_lock);
			sem_post(&handle->db_desc->compaction_daemon_interrupts);

			if (pthread_cond_wait(&handle->db_desc->client_barrier,
					      &handle->db_desc->client_barrier_lock) != 0) {
				log_fatal("failed to throttle");
				BUG_ON();
			}
		}
		active_tree = handle->db_desc->levels[0].active_tree;
		MUTEX_UNLOCK(&handle->db_desc->client_barrier_lock);
	}

	/* Reacquire the lock of level 0 to access it safely. */
	if (relock) {
		if (rwlock == 1)
			RWLOCK_RDLOCK(&handle->db_desc->levels[0].guard_of_level.rx_lock);
		else
			RWLOCK_WRLOCK(&handle->db_desc->levels[0].guard_of_level.rx_lock);
	}
}

enum kv_category calculate_KV_category(uint32_t key_size, uint32_t value_size, request_type op_type)
{
	assert(op_type == insertOp || op_type == deleteOp);

	if (op_type == deleteOp) {
		assert(key_size && 0 == value_size);
		return SMALL_INPLACE;
	}

	assert(key_size && value_size);
	/*We always use as nominator the smallest value of the pair <key size, value size>*/
	double kv_ratio = ((double)key_size) / value_size;
	if (value_size < key_size)
		kv_ratio = ((double)value_size) / key_size;

	if (key_size + value_size > MAX_KV_IN_PLACE_SIZE)
		kv_ratio = 0; /*Forcefully characterize it as BIG_INLOG*/

	enum kv_category category = SMALL_INPLACE;
	if (kv_ratio >= 0.0 && kv_ratio < 0.02)
		category = BIG_INLOG;
	else if (kv_ratio >= 0.02 && kv_ratio <= 0.2)
		category = MEDIUM_INPLACE;
	return category;
}

static const char *insert_error_handling(db_handle *handle, uint32_t key_size, uint32_t value_size)
{
	const char *error_message = NULL;
	if (DB_IS_CLOSING == handle->db_desc->db_state) {
		error_message = "DB: %s is closing";
		return error_message;
	}

	if (key_size > MAX_KEY_SIZE) {
		error_message = "Provided key %u Keys > %ld bytes are not supported";
		return error_message;
	}

	if (!key_size) {
		error_message = "Trying to enter a zero sized key? Not valid!";
		return error_message;
	}

	uint32_t kv_size = key_size + value_size + get_kv_metadata_size();
	if (kv_size > KV_MAX_SIZE) {
		error_message = "KV size > 4KB buffer overflow!";
		return error_message;
	}

	return NULL;
}

struct par_put_metadata insert_key_value(db_handle *handle, void *key, void *value, int32_t key_size,
					 int32_t value_size, request_type op_type, const char *error_message)
{
	bt_insert_req ins_req = { 0 };
	char kv_pair[KV_MAX_SIZE];

	error_message = insert_error_handling(handle, key_size, value_size);
	if (error_message) {
		// construct an invalid par_put_metadata
		struct par_put_metadata invalid_put_metadata = { .lsn = UINT64_MAX,
								 .offset_in_log = UINT64_MAX,
								 .key_value_category = SMALL_INPLACE };
		return invalid_put_metadata;
	}

	/*prepare the request*/

	ins_req.metadata.put_op_metadata.key_value_category = ins_req.metadata.cat;
	ins_req.metadata.handle = handle;
	ins_req.key_value_buf = kv_pair;
	ins_req.metadata.tombstone = op_type == deleteOp;
	ins_req.metadata.tombstone ? set_tombstone((struct kv_splice *)ins_req.key_value_buf) :
				     set_non_tombstone((struct kv_splice *)ins_req.key_value_buf);
	set_key((struct kv_splice *)kv_pair, key, key_size);
	set_value((struct kv_splice *)kv_pair, value, value_size);
	ins_req.metadata.cat = calculate_KV_category(key_size, value_size, op_type);
	ins_req.metadata.level_id = 0;
	ins_req.metadata.key_format = KV_FORMAT;
	ins_req.metadata.append_to_log = 1;
	ins_req.metadata.gc_request = 0;
	ins_req.metadata.special_split = 0;

	/*
	 * Note for L0 inserts since active_tree changes dynamically we decide which
	 * is the active_tree after acquiring the guard lock of the region.
	 */

	error_message = btree_insert_key_value(&ins_req);
	return ins_req.metadata.put_op_metadata;
}

struct par_put_metadata serialized_insert_key_value(db_handle *handle, const char *serialized_key_value,
						    const char *error_message)
{
	bt_insert_req ins_req = { .metadata.handle = handle,
				  .key_value_buf = (char *)serialized_key_value,
				  .metadata.level_id = 0,
				  .metadata.key_format = KV_FORMAT,
				  .metadata.append_to_log = 1 };

	int32_t key_size = get_key_size((struct kv_splice *)serialized_key_value);
	int32_t value_size = get_value_size((struct kv_splice *)serialized_key_value);

	error_message = insert_error_handling(handle, key_size, value_size);
	if (error_message) {
		// construct an invalid par_put_metadata
		struct par_put_metadata invalid_put_metadata = { .lsn = UINT64_MAX,
								 .offset_in_log = UINT64_MAX,
								 .key_value_category = SMALL_INPLACE };
		return invalid_put_metadata;
	}
	ins_req.metadata.cat = calculate_KV_category(key_size, value_size, insertOp);

	error_message = btree_insert_key_value(&ins_req);
	return ins_req.metadata.put_op_metadata;
}

void extract_keyvalue_size(log_operation *req, metadata_tologop *data_size)
{
	if (req->metadata->key_format == KV_FORMAT) {
		data_size->key_len = get_key_size((struct kv_splice *)req->ins_req->key_value_buf);
		data_size->value_len = get_value_size((struct kv_splice *)req->ins_req->key_value_buf);
		data_size->kv_size = get_kv_size((struct kv_splice *)req->ins_req->key_value_buf);
		return;
	}

	data_size->key_len = get_kv_seperated_key_size((struct kv_seperation_splice *)req->ins_req->key_value_buf);
	data_size->value_len = get_kv_seperated_value_size((struct kv_seperation_splice *)req->ins_req->key_value_buf);
	data_size->kv_size = get_kv_seperated_kv_size((struct kv_seperation_splice *)req->ins_req->key_value_buf);
}

//######################################################################################################
struct pr_log_ticket {
	// in var
	struct log_tail *tail;
	struct log_operation *req;
	struct metadata_tologop *data_size;
	struct lsn lsn;
	uint64_t log_offt;
	// out var
	uint64_t IO_start_offt;
	uint32_t IO_size;
	uint32_t op_size;
};

static void pr_copy_kv_to_tail(struct pr_log_ticket *ticket)
{
	if (!ticket->req) {
		BUG_ON();
	}

	uint64_t offset_in_seg = ticket->log_offt % (uint64_t)SEGMENT_SIZE;
	uint64_t offt = offset_in_seg;
	switch (ticket->req->optype_tolog) {
	case insertOp:
	case deleteOp: {
		// first the lsn
		memcpy(&ticket->tail->buf[offt], &ticket->lsn, get_lsn_size());
		offt += get_lsn_size();
		struct kv_splice *kv_pair_dst = (struct kv_splice *)&ticket->tail->buf[offt];
		struct kv_splice *kv_pair_src = (struct kv_splice *)ticket->req->ins_req->key_value_buf;
		ticket->req->optype_tolog == insertOp ? set_non_tombstone(kv_pair_dst) : set_tombstone(kv_pair_dst);
		set_key(kv_pair_dst, get_key_offset_in_kv(kv_pair_src), get_key_size(kv_pair_src));
		set_value(kv_pair_dst, get_value_offset_in_kv(kv_pair_src, get_key_size(kv_pair_src)),
			  get_value_size(kv_pair_src));
		ticket->op_size = get_lsn_size() + get_kv_size(kv_pair_dst);
		break;
	}
	case paddingOp:
		ticket->op_size = 0;
		if (offset_in_seg) {
			ticket->op_size = (uint64_t)SEGMENT_SIZE - offset_in_seg;
			//log_info("Time for padding for log_offset %llu offt in seg %llu pad bytes %u ",
			//	 ticket->log_offt, offt_in_seg, ticket->op_size);
			memset(&ticket->tail->buf[offset_in_seg], 0, ticket->op_size);
		}
		break;

	default:
		log_fatal("Unknown op");
		BUG_ON();
	}

	uint32_t remaining = ticket->op_size;
	uint32_t curr_offt_in_seg = offset_in_seg;
	while (remaining > 0) {
		uint32_t chunk_id = curr_offt_in_seg / LOG_CHUNK_SIZE;
		int64_t offt_in_chunk = curr_offt_in_seg - (chunk_id * LOG_CHUNK_SIZE);
		int64_t bytes = (uint64_t)LOG_CHUNK_SIZE - offt_in_chunk;
		if (remaining < bytes)
			bytes = remaining;

		__sync_fetch_and_add(&ticket->tail->bytes_in_chunk[chunk_id], bytes);
		assert(ticket->tail->bytes_in_chunk[chunk_id] <= LOG_CHUNK_SIZE);
		//log_info("Charged %u bytes for chunk id %u op size %u bytes now %u", bytes, chunk_id,
		// ticket->op_size, ticket->tail->bytes_in_chunk[chunk_id]);
		remaining -= bytes;
		curr_offt_in_seg += bytes;
	}
}

static void pr_do_log_chunk_IO(struct pr_log_ticket *ticket)
{
	uint64_t offt_in_seg = ticket->log_offt % SEGMENT_SIZE;
	uint32_t chunk_offt = offt_in_seg % LOG_CHUNK_SIZE;
	uint32_t chunk_id = offt_in_seg / LOG_CHUNK_SIZE;
	uint32_t num_chunks = SEGMENT_SIZE / LOG_CHUNK_SIZE;
	int do_IO;

	(void)num_chunks;
	assert(chunk_id != num_chunks);

	if (chunk_offt + ticket->op_size >= LOG_CHUNK_SIZE) {
		ticket->IO_start_offt = chunk_id * LOG_CHUNK_SIZE;
		ticket->IO_size = LOG_CHUNK_SIZE;
		do_IO = 1;
	} else {
		ticket->IO_start_offt = 0;
		ticket->IO_size = 0;
		do_IO = 0;
	}

	if (!do_IO)
		return;

	// log_info("Checking if all data for chunk id %u are there currently are %u",
	// chunk_id,
	// Can I set new segment for the others to proceed?
	//	 ticket->tail->bytes_written_in_log_chunk[chunk_id]);
	// wait until all pending bytes are written
	wait_for_value(&ticket->tail->bytes_in_chunk[chunk_id], LOG_CHUNK_SIZE);
	// do the IO finally
	ssize_t total_bytes_written = 0;
	ssize_t size = LOG_CHUNK_SIZE;
	// log_info("IO time, start %llu size %llu segment dev_offt %llu offt in seg
	// %llu", total_bytes_written, size,
	//	 ticket->tail->dev_segment_offt, ticket->IO_start_offt);
	while (total_bytes_written < size) {
		ssize_t bytes_written = pwrite(ticket->tail->fd,
					       &ticket->tail->buf[ticket->IO_start_offt + total_bytes_written],
					       size - total_bytes_written,
					       ticket->tail->dev_offt + ticket->IO_start_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to write LOG_CHUNK reason follows");
			perror("Reason");
			BUG_ON();
		}
		total_bytes_written += bytes_written;
	}
	__sync_fetch_and_add(&ticket->tail->IOs_completed_in_tail, 1);

	assert(ticket->tail->IOs_completed_in_tail <= num_chunks);
}

static void pr_do_log_IO(struct pr_log_ticket *ticket)
{
	uint64_t log_offt = ticket->log_offt;
	uint32_t op_size = ticket->op_size;
	uint32_t remaining = op_size;
	uint64_t c_log_offt = log_offt;

	while (remaining > 0) {
		ticket->log_offt = c_log_offt;

		if (remaining >= LOG_CHUNK_SIZE)
			ticket->op_size = LOG_CHUNK_SIZE;
		else
			ticket->op_size = remaining;

		pr_do_log_chunk_IO(ticket);
		remaining -= ticket->op_size;
		c_log_offt += ticket->op_size;
	}

	ticket->log_offt = log_offt;
	ticket->op_size = op_size;
}

static void bt_add_segment_to_log(struct db_descriptor *db_desc, struct log_descriptor *log_desc, uint8_t level_id,
				  uint8_t tree_id)
{
	uint32_t curr_tail_id = log_desc->curr_tail_id;
	uint32_t next_tail_id = curr_tail_id + 1;
	struct segment_header *new_segment = seg_get_raw_log_segment(db_desc, log_desc->log_type, level_id, tree_id);

	if (!new_segment) {
		log_fatal("Cannot allocate memory from the device!");
		BUG_ON();
	}
	uint64_t next_tail_seg_offt = ABSOLUTE_ADDRESS(new_segment);

	if (!next_tail_seg_offt) {
		log_fatal("No space for new segment");
		BUG_ON();
	}

	struct segment_header *curr_tail_seg =
		(struct segment_header *)log_desc->tail[curr_tail_id % LOG_TAIL_NUM_BUFS]->buf;

	//parse_log_segment(curr_tail_seg);
	struct log_tail *next_tail = log_desc->tail[next_tail_id % LOG_TAIL_NUM_BUFS];
	struct segment_header *next_tail_seg =
		(struct segment_header *)log_desc->tail[next_tail_id % LOG_TAIL_NUM_BUFS]->buf;

	next_tail_seg->segment_id = curr_tail_seg->segment_id + 1;
	//log_info("Curr tail: %u next_tail: %u Segment_id is now %llu db %s", curr_tail_id, next_tail_id,
	//	 next_tail_seg->segment_id, db_desc->db_superblock->db_name);
	next_tail_seg->next_segment = NULL;
	next_tail_seg->prev_segment = (void *)log_desc->tail_dev_offt;
	log_desc->tail_dev_offt = next_tail_seg_offt;
	/*position the log to the newly added block*/
	log_desc->size += sizeof(segment_header);
	// Reset tail for new use
	for (int j = 0; j < (SEGMENT_SIZE / LOG_CHUNK_SIZE); ++j)
		next_tail->bytes_in_chunk[j] = 0;

	next_tail->IOs_completed_in_tail = 0;
	next_tail->start = next_tail_seg_offt;
	next_tail->end = next_tail->start + SEGMENT_SIZE;
	next_tail->dev_offt = next_tail_seg_offt;
	next_tail->bytes_in_chunk[0] = sizeof(struct segment_header);
	next_tail->free = 0;
	log_desc->curr_tail_id = next_tail_id;
}

static void bt_add_blob(struct db_descriptor *db_desc, struct log_descriptor *log_desc, uint8_t level_id,
			uint8_t tree_id)
{
	uint32_t curr_tail_id = log_desc->curr_tail_id;
	uint32_t next_tail_id = ++curr_tail_id;

	struct segment_header *next_tail_seg = seg_get_raw_log_segment(db_desc, log_desc->log_type, level_id, tree_id);

	if (!next_tail_seg) {
		log_fatal("No space for new segment");
		BUG_ON();
	}

	//struct segment_header *curr_tail_seg =
	//	(struct segment_header *)log_desc->tail[curr_tail_id % LOG_TAIL_NUM_BUFS]->buf;
	struct log_tail *next_tail = log_desc->tail[next_tail_id % LOG_TAIL_NUM_BUFS];
	//next_tail_seg->segment_id = curr_tail_seg->segment_id + 1;
	//next_tail_seg->next_segment = NULL;
	//next_tail_seg->prev_segment = (void *)ABSOLUTE_ADDRESS(curr_tail_seg);
	log_desc->tail_dev_offt = ABSOLUTE_ADDRESS(next_tail_seg);

	// Reset tail for new use
	for (int j = 0; j < (SEGMENT_SIZE / LOG_CHUNK_SIZE); ++j)
		next_tail->bytes_in_chunk[j] = 0;

	next_tail->IOs_completed_in_tail = 0;
	next_tail->start = ABSOLUTE_ADDRESS(next_tail_seg);
	next_tail->end = next_tail->start + SEGMENT_SIZE;
	next_tail->dev_offt = ABSOLUTE_ADDRESS(next_tail_seg);
	next_tail->free = 0;
	log_desc->curr_tail_id = next_tail_id;
}

static void *bt_append_to_log_direct_IO(struct log_operation *req, struct log_towrite *log_metadata,
					struct metadata_tologop *data_size)
{
	db_handle *handle = req->metadata->handle;

	struct pr_log_ticket log_kv_entry_ticket = { .log_offt = 0, .IO_start_offt = 0, .IO_size = 0 };
	struct pr_log_ticket pad_ticket = { .log_offt = 0, .IO_start_offt = 0, .IO_size = 0 };
	char *addr_inlog = NULL;
	uint32_t available_space_in_log = 0;
	uint32_t reserve_needed_space = get_lsn_size() + data_size->kv_size;

	MUTEX_LOCK(&handle->db_desc->lock_log);

	/*append data part in the data log*/
	if (log_metadata->log_desc->size == 0)
		available_space_in_log = SEGMENT_SIZE;
	else if (log_metadata->log_desc->size % SEGMENT_SIZE != 0)
		available_space_in_log = SEGMENT_SIZE - (log_metadata->log_desc->size % SEGMENT_SIZE);

	uint32_t num_chunks = SEGMENT_SIZE / LOG_CHUNK_SIZE;
	int segment_change = 0;
	//log_info("Direct IO in log kv size is %u log size %u avail space %u", data_size->kv_size,
	//	 log_metadata->log_desc->size, available_space_in_log);
	if (req->metadata->tombstone)
		reserve_needed_space = get_lsn_size() + sizeof(struct bt_delete_marker) + data_size->key_len;

	if (available_space_in_log < reserve_needed_space) {
		uint32_t curr_tail_id = log_metadata->log_desc->curr_tail_id;
		//log_info("Segment change avail space %u kv size %u",available_space_in_log,data_size->kv_size);
		// pad with zeroes remaining bytes in segment
		if (available_space_in_log > 0) {
			log_operation pad_op = { .metadata = NULL, .optype_tolog = paddingOp, .ins_req = NULL };
			pad_ticket.req = &pad_op;
			pad_ticket.data_size = NULL;
			pad_ticket.tail = log_metadata->log_desc->tail[curr_tail_id % LOG_TAIL_NUM_BUFS];
			pad_ticket.log_offt = log_metadata->log_desc->size;
			pr_copy_kv_to_tail(&pad_ticket);
		}

		// log_info("Resetting segment start %llu end %llu ...",
		// ticket->tail->start, ticket->tail->end);
		// Wait for all chunk IOs to finish to characterize it free
		uint32_t next_tail_id = ++curr_tail_id;
		struct log_tail *next_tail = log_metadata->log_desc->tail[next_tail_id % LOG_TAIL_NUM_BUFS];

		if (!next_tail->free)
			wait_for_value(&next_tail->IOs_completed_in_tail, num_chunks);
		RWLOCK_WRLOCK(&log_metadata->log_desc->log_tail_buf_lock);
		wait_for_value(&next_tail->pending_readers, 0);

		log_metadata->log_desc->size += available_space_in_log;

		switch (log_metadata->log_desc->log_type) {
		case BIG_LOG:
			bt_add_blob(handle->db_desc, log_metadata->log_desc, req->metadata->level_id,
				    req->metadata->tree_id);
			break;
		case MEDIUM_LOG:
		case SMALL_LOG:
			bt_add_segment_to_log(handle->db_desc, log_metadata->log_desc, req->metadata->level_id,
					      req->metadata->tree_id);
			break;
		default:
			log_fatal("Unknown category");
			BUG_ON();
		}

		segment_change = 1;
		RWLOCK_UNLOCK(&log_metadata->log_desc->log_tail_buf_lock);
	}

	uint32_t tail_id = log_metadata->log_desc->curr_tail_id;
	log_kv_entry_ticket.req = req;
	log_kv_entry_ticket.data_size = data_size;
	log_kv_entry_ticket.tail = log_metadata->log_desc->tail[tail_id % LOG_TAIL_NUM_BUFS];
	log_kv_entry_ticket.log_offt = log_metadata->log_desc->size;

	log_kv_entry_ticket.lsn = increase_lsn(&handle->db_desc->lsn_factory);
	/*Where we *will* store it on the device*/
	struct segment_header *device_location = REAL_ADDRESS(log_metadata->log_desc->tail_dev_offt);
	addr_inlog = (void *)((uint64_t)device_location + (log_metadata->log_desc->size % SEGMENT_SIZE));

	req->metadata->log_offset = log_metadata->log_desc->size;
	req->metadata->put_op_metadata.offset_in_log = req->metadata->log_offset;
	req->metadata->put_op_metadata.lsn = get_lsn_id(&log_kv_entry_ticket.lsn);
	log_metadata->log_desc->size += reserve_needed_space;
	MUTEX_UNLOCK(&handle->db_desc->lock_log);

	if (segment_change && available_space_in_log > 0) {
		// do the padding IO as well
		pr_do_log_IO(&pad_ticket);
	}
	pr_copy_kv_to_tail(&log_kv_entry_ticket);
	pr_do_log_IO(&log_kv_entry_ticket);

	return addr_inlog + get_lsn_size();
}

void *append_key_value_to_log(log_operation *req)
{
	struct log_towrite log_metadata = { .level_id = req->metadata->level_id, .status = req->metadata->cat };
	struct metadata_tologop data_size = { 0 };
	db_handle *handle = req->metadata->handle;

	extract_keyvalue_size(req, &data_size);

	switch (log_metadata.status) {
	case SMALL_INPLACE:
		log_metadata.log_desc = &handle->db_desc->small_log;
		return bt_append_to_log_direct_IO(req, &log_metadata, &data_size);
	case MEDIUM_INPLACE: {
		uint8_t level_id = req->metadata->level_id;
		if (level_id) {
			log_fatal("Append for MEDIUM_INPLACE for level_id > 0 ? Not allowed");
			BUG_ON();
		} else {
			log_metadata.log_desc = &handle->db_desc->small_log;
			return bt_append_to_log_direct_IO(req, &log_metadata, &data_size);
		}
	}
	case MEDIUM_INLOG: {
		uint8_t level_id = req->metadata->level_id;
		if (level_id == 0) {
			log_fatal("MEDIUM_INLOG not allowed for level_id 0!");
			BUG_ON();
		} else {
			log_metadata.log_desc = &handle->db_desc->medium_log;
			return bt_append_to_log_direct_IO(req, &log_metadata, &data_size);
		}
	}
	case BIG_INLOG:
		log_metadata.log_desc = &handle->db_desc->big_log;
		return bt_append_to_log_direct_IO(req, &log_metadata, &data_size);
	default:
		log_fatal("Unknown category %u", log_metadata.status);
		BUG_ON();
	}
}

const char *btree_insert_key_value(bt_insert_req *ins_req)
{
	ins_req->metadata.handle->db_desc->dirty = 1;

	if (writers_join_as_readers(ins_req) == PAR_SUCCESS)
		;
	else if (concurrent_insert(ins_req) != PAR_SUCCESS)
		ins_req->metadata.error_message = "Insert failed";

	return ins_req->metadata.error_message;
}

// cppcheck-suppress unusedFunction
int find_key_in_bloom_filter(db_descriptor *db_desc, int level_id, char *key)
{
#if ENABLE_BLOOM_FILTERS
	char prefix_key[PREFIX_SIZE];
	if (get_key_size((struct splice *)key) < PREFIX_SIZE) {
		memset(prefix_key, 0x00, PREFIX_SIZE);
		memcpy(prefix_key, get_key_offset_in_kv((struct splice *)key), get_key_size((struct splice *)key));
		return bloom_check(&db_desc->levels[level_id].bloom_filter[0], prefix_key, PREFIX_SIZE);
	} else
		return bloom_check(&db_desc->levels[level_id].bloom_filter[0],
				   get_key_offset_in_kv((struct splice *)key), PREFIX_SIZE);
#else
	(void)db_desc;
	(void)level_id;
	(void)key;
#endif
	return -1;
}

static inline void lookup_in_tree(struct lookup_operation *get_op, int level_id, int tree_id)
{
	node_header *son_node = NULL;
	char *key_addr_in_leaf = NULL;
	struct find_result ret_result;
	lock_table *prev = NULL;
	lock_table *curr = NULL;
	struct node_header *root = NULL;
	struct db_descriptor *db_desc = get_op->db_desc;
	struct key_splice *search_key_buf = (struct key_splice *)get_op->key_buf;

	if (db_desc->levels[level_id].root_w[tree_id] == NULL && db_desc->levels[level_id].root_r[tree_id] == NULL) {
		get_op->found = 0;
		return;
	}

	root = db_desc->levels[level_id].root_r[tree_id];

	if (db_desc->levels[level_id].root_w[tree_id] != NULL)
		root = db_desc->levels[level_id].root_w[tree_id];

#if ENABLE_BLOOM_FILTERS
	if (level_id > 0) {
		int check = find_key_in_bloom_filter(db_desc, level_id, key);

		if (0 == check)
			return rep;
		else if (-1 != check) {
			BUG_ON();
		}
	}
#endif

	/* TODO: (@geostyl) do we need this if here? i think its reduntant*/
	node_header *curr_node = root;
	if (curr_node->type == leafRootNode) {
		curr = _find_position((const lock_table **)db_desc->levels[level_id].level_lock_table, curr_node);

		if (RWLOCK_RDLOCK(&curr->rx_lock) != 0)
			BUG_ON();

		uint32_t key_size = get_key_splice_key_size(search_key_buf);
		void *key = get_key_splice_key_offset(search_key_buf);
		ret_result = find_key_in_dynamic_leaf((struct bt_dynamic_leaf_node *)curr_node, db_desc, key, key_size,
						      level_id);
		get_op->tombstone = ret_result.tombstone;
		goto deser;
	}

	while (curr_node && curr_node->type != leafNode) {
		curr = _find_position((const lock_table **)db_desc->levels[level_id].level_lock_table, curr_node);

		if (RWLOCK_RDLOCK(&curr->rx_lock) != 0)
			BUG_ON();

		if (prev)
			if (RWLOCK_UNLOCK(&prev->rx_lock) != 0)
				BUG_ON();

		uint64_t child_offset =
			index_binary_search((struct index_node *)curr_node, (char *)search_key_buf, KEY_TYPE);
		son_node = (void *)REAL_ADDRESS(child_offset);

		prev = curr;
		curr_node = son_node;
	}

	if (curr_node == NULL) {
		log_fatal("Encountered NULL node in index");
		BUG_ON();
	}

	prev = curr;
	curr = _find_position((const lock_table **)db_desc->levels[level_id].level_lock_table, curr_node);
	if (RWLOCK_RDLOCK(&curr->rx_lock) != 0) {
		BUG_ON();
	}

	if (RWLOCK_UNLOCK(&prev->rx_lock) != 0)
		BUG_ON();

	int32_t key_size = get_key_splice_key_size(search_key_buf);
	void *key = get_key_splice_key_offset(search_key_buf);
	ret_result =
		find_key_in_dynamic_leaf((struct bt_dynamic_leaf_node *)curr_node, db_desc, key, key_size, level_id);
	get_op->tombstone = ret_result.tombstone;

// TODO The meaning of deser is not clear enough, rename accordingly
deser:
	if (!ret_result.kv) {
		get_op->found = 0;
		goto exit;
	}
	get_op->found = 1;
	struct bt_kv_log_address kv_pair = { .addr = NULL, .tail_id = UINT8_MAX, .in_tail = 0 };
	get_op->key_device_address = NULL;

	if (ret_result.key_type != KV_INPLACE && ret_result.key_type != KV_INLOG) {
		log_fatal("Corrupted KV location");
		BUG_ON();
	}

	if (ret_result.key_type == KV_INPLACE) {
		kv_pair.addr = REAL_ADDRESS(ret_result.kv);
		get_op->key_device_address = ret_result.kv;
	} else if (ret_result.key_type == KV_INLOG) {
		key_addr_in_leaf = (char *)REAL_ADDRESS(*(uint64_t *)ret_result.kv);
		if (key_addr_in_leaf == NULL) {
			log_fatal("Encountered NULL pointer from KV in leaf");
			BUG_ON();
		}

		kv_pair.addr = key_addr_in_leaf;
		if (!level_id)
			kv_pair = bt_get_kv_log_address(&db_desc->big_log, ABSOLUTE_ADDRESS(key_addr_in_leaf));

		get_op->key_device_address = (char *)ABSOLUTE_ADDRESS(kv_pair.addr);
	}

	assert(kv_pair.addr);
	struct kv_splice *kv_buf = (struct kv_splice *)kv_pair.addr;
	int32_t value_size = get_value_size(kv_buf);
	if (get_op->retrieve && !get_op->buffer_to_pack_kv) {
		get_op->buffer_to_pack_kv = malloc(value_size);
		get_op->size = value_size;
	}

	if (get_op->retrieve && get_op->size > value_size)
		get_op->buffer_overflow = 1;

	if (get_op->retrieve && get_op->size <= value_size) {
		memcpy(get_op->buffer_to_pack_kv, get_value_offset_in_kv(kv_buf, get_key_size(kv_buf)), value_size);
		get_op->buffer_overflow = 0;
	}

	if (get_op->tombstone)
		get_op->key_device_address = NULL;

	if (kv_pair.in_tail)
		bt_done_with_value_log_address(&db_desc->big_log, &kv_pair);

exit:
	if (RWLOCK_UNLOCK(&curr->rx_lock) != 0)
		BUG_ON();

	__sync_fetch_and_sub(&db_desc->levels[level_id].active_operations, 1);
}

void find_key(struct lookup_operation *get_op)
{
	if (DB_IS_CLOSING == get_op->db_desc->db_state) {
		log_warn("Sorry DB: %s is closing", get_op->db_desc->db_superblock->db_name);
		get_op->found = 0;
		return;
	}

	struct db_descriptor *db_desc = get_op->db_desc;
	/*again special care for L0*/
	// Acquiring guard lock for level 0
	if (RWLOCK_RDLOCK(&db_desc->levels[0].guard_of_level.rx_lock) != 0)
		BUG_ON();
	__sync_fetch_and_add(&db_desc->levels[0].active_operations, 1);
	uint8_t tree_id = db_desc->levels[0].active_tree;
	uint8_t base = tree_id;

	while (1) {
		/*first look the current active tree of the level*/
		get_op->found = 0;
		get_op->tombstone = 0;
		lookup_in_tree(get_op, 0, tree_id);

		if (get_op->found) {
			if (RWLOCK_UNLOCK(&db_desc->levels[0].guard_of_level.rx_lock) != 0)
				BUG_ON();
			__sync_fetch_and_sub(&db_desc->levels[0].active_operations, 1);

			goto finish;
		}
		++tree_id;
		if (tree_id >= NUM_TREES_PER_LEVEL)
			tree_id = 0;
		if (tree_id == base)
			break;
	}
	if (RWLOCK_UNLOCK(&db_desc->levels[0].guard_of_level.rx_lock) != 0)
		BUG_ON();
	__sync_fetch_and_sub(&db_desc->levels[0].active_operations, 1);
	/*search the rest trees of the level*/
	for (uint8_t level_id = 1; level_id < MAX_LEVELS; ++level_id) {
		if (RWLOCK_RDLOCK(&db_desc->levels[level_id].guard_of_level.rx_lock) != 0)
			BUG_ON();
		__sync_fetch_and_add(&db_desc->levels[level_id].active_operations, 1);

		get_op->found = 0;
		get_op->tombstone = 0;
		lookup_in_tree(get_op, level_id, 0);
		if (get_op->found) {
			if (RWLOCK_UNLOCK(&db_desc->levels[level_id].guard_of_level.rx_lock) != 0)
				BUG_ON();
			__sync_fetch_and_sub(&db_desc->levels[level_id].active_operations, 1);

			goto finish;
		}
		if (RWLOCK_UNLOCK(&db_desc->levels[level_id].guard_of_level.rx_lock) != 0)
			BUG_ON();
		__sync_fetch_and_sub(&db_desc->levels[level_id].active_operations, 1);
	}

finish:
	if (get_op->found && get_op->tombstone)
		get_op->found = 0;
}

int insert_KV_at_leaf(bt_insert_req *ins_req, node_header *leaf)
{
	db_descriptor *db_desc = ins_req->metadata.handle->db_desc;
	enum kv_category cat = ins_req->metadata.cat;
	int append_tolog = ins_req->metadata.append_to_log;
	int ret = -1;
	uint8_t level_id = ins_req->metadata.level_id;
	uint8_t tree_id = ins_req->metadata.tree_id;

	ins_req->kv_dev_offt = 0;
	if (append_tolog) {
		log_operation append_op = { .metadata = &ins_req->metadata,
					    .optype_tolog = insertOp,
					    .ins_req = ins_req };

		if (ins_req->metadata.tombstone == 1)
			append_op.optype_tolog = deleteOp;

		switch (ins_req->metadata.cat) {
		case SMALL_INPLACE:
		case MEDIUM_INPLACE:
			append_key_value_to_log(&append_op);
			break;
		case BIG_INLOG: {
			void *addr = append_key_value_to_log(&append_op);
			ins_req->kv_dev_offt = ABSOLUTE_ADDRESS(addr);
			assert(ins_req->kv_dev_offt != 0);
			break;
		}
		default:
			ins_req->key_value_buf = append_key_value_to_log(&append_op);
			break;
		}
	}

	ret = insert_in_dynamic_leaf((struct bt_dynamic_leaf_node *)leaf, ins_req, &db_desc->levels[level_id]);

	if (ret == INSERT) {
		int measure_level_used_space = cat == BIG_INLOG;
		int medium_inlog = cat == MEDIUM_INLOG && level_id != db_desc->level_medium_inplace;

		if (cat == MEDIUM_INPLACE && level_id == 0) {
			__sync_fetch_and_add(&(ins_req->metadata.handle->db_desc->levels[level_id].level_size[tree_id]),
					     get_kv_seperated_splice_size());
		} else if (measure_level_used_space || medium_inlog) {
			__sync_fetch_and_add(&(ins_req->metadata.handle->db_desc->levels[level_id].level_size[tree_id]),
					     get_kv_seperated_splice_size());
		} else {
			__sync_fetch_and_add(&(ins_req->metadata.handle->db_desc->levels[level_id].level_size[tree_id]),
					     get_kv_size((struct kv_splice *)ins_req->key_value_buf));
		}
	}

	return ret;
}

struct bt_rebalance_result split_leaf(bt_insert_req *req, leaf_node *node)
{
	split_dl *split_functions[1] = { split_dynamic_leaf };
	int level_id = req->metadata.level_id;

	uint32_t leaf_size = req->metadata.handle->db_desc->levels[level_id].leaf_size;
	// cppcheck-suppress legacyUninitvar
	return split_functions[req->metadata.special_split]((struct bt_dynamic_leaf_node *)node, leaf_size, req);
}

uint64_t par_hash(uint64_t x)
{
	x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
	x = x ^ (x >> 31);
	return x;
}

lock_table *_find_position(const lock_table **table, node_header *node)
{
	assert(node);
	if (node->height < 0 || node->height >= MAX_HEIGHT) {
		log_fatal("MAX_HEIGHT exceeded %d rearrange values in size_per_height array ", node->height);
		assert(0);
		BUG_ON();
	}

	unsigned long position = par_hash((uint64_t)node) % size_per_height[node->height];
	// log_info("node %llu height %d position %lu size of height %d", node,
	// node->height, position, size_per_height[node->height]);
	const lock_table *node_lock = table[node->height];
	return (lock_table *)&node_lock[position];
}

void _unlock_upper_levels(lock_table *node[], unsigned size, unsigned release)
{
	unsigned i;
	for (i = release; i < size; ++i)
		if (RWLOCK_UNLOCK(&node[i]->rx_lock) != 0) {
			log_fatal("ERROR unlocking");
			BUG_ON();
		}
}

int is_split_needed(void *node, bt_insert_req *req, uint32_t leaf_size)
{
	assert(node);
	node_header *header = (node_header *)node;
	uint32_t height = header->height;
	enum kv_category cat = req->metadata.cat;
	uint8_t level_id = req->metadata.level_id;

	if (height != 0)
		return index_is_split_needed((struct index_node *)node, MAX_KEY_SIZE);

	enum kv_entry_location key_type = KV_INPLACE;

	if ((cat == MEDIUM_INLOG && level_id != req->metadata.handle->db_desc->level_medium_inplace) ||
	    cat == BIG_INLOG)
		key_type = KV_INLOG;

	struct split_level_leaf split_metadata = { .leaf = node,
						   .leaf_size = leaf_size,
						   .kv_size = get_kv_size((struct kv_splice *)req->key_value_buf),
						   .level_id = req->metadata.level_id,
						   .level_medium_inplace =
							   req->metadata.handle->db_desc->level_medium_inplace,
						   .key_type = key_type,
						   .cat = cat };
	return is_dynamic_leaf_full(split_metadata);
}

static uint8_t concurrent_insert(bt_insert_req *ins_req)
{
	/*The array with the locks that belong to this thread from upper levels*/
	lock_table *upper_level_nodes[MAX_HEIGHT];
	struct bt_rebalance_result split_res;
	lock_table *lock = NULL;

	db_descriptor *db_desc = ins_req->metadata.handle->db_desc;
	uint8_t level_id = ins_req->metadata.level_id;
	lock_table *guard_of_level = &(db_desc->levels[level_id].guard_of_level);
	int64_t *num_level_writers = &db_desc->levels[level_id].active_operations;

	unsigned release = 0;
	unsigned size = 0;

	int retry = 0;
release_and_retry:

	if (retry) {
		retry = 0;
		_unlock_upper_levels(upper_level_nodes, size, release);
		__sync_fetch_and_sub(num_level_writers, 1);
	}

	retry = 1;
	size = 0;
	release = 0;
	if (RWLOCK_WRLOCK(&guard_of_level->rx_lock)) {
		log_fatal("Failed to acquire guard lock for level %u", level_id);
		BUG_ON();
	}

	wait_for_available_level0_tree(ins_req->metadata.handle, level_id, 0);
	/*now look which is the active_tree of L0*/
	if (ins_req->metadata.level_id == 0)
		ins_req->metadata.tree_id = ins_req->metadata.handle->db_desc->levels[0].active_tree;

	/*level's guard lock aquired*/
	upper_level_nodes[size++] = guard_of_level;
	/*mark your presence*/
	__sync_fetch_and_add(num_level_writers, 1);

	node_header *son = NULL;
	node_header *father = NULL;

	if (db_desc->levels[level_id].root_w[ins_req->metadata.tree_id] == NULL) {
		if (db_desc->levels[level_id].root_r[ins_req->metadata.tree_id] == NULL) {
			/*we are allocating a new tree*/

			log_debug("Allocating new active tree %d for level id %d", ins_req->metadata.tree_id, level_id);

			leaf_node *t = seg_get_leaf_node(ins_req->metadata.handle->db_desc, level_id,
							 ins_req->metadata.tree_id);

			t->header.type = leafRootNode;
			db_desc->levels[level_id].root_w[ins_req->metadata.tree_id] = (node_header *)t;
		}
	}
	/*acquiring lock of the current root*/
	lock = _find_position((const lock_table **)db_desc->levels[level_id].level_lock_table,
			      db_desc->levels[level_id].root_w[ins_req->metadata.tree_id]);
	if (RWLOCK_WRLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR locking");
		BUG_ON();
	}

	upper_level_nodes[size++] = lock;
	son = db_desc->levels[level_id].root_w[ins_req->metadata.tree_id];

	while (1) {
		/*Check if father is safe it should be*/
		if (is_split_needed(son, ins_req, db_desc->levels[level_id].leaf_size)) {
			/*Overflow split for index nodes*/
			if (son->height > 0) {
				split_res = index_split_node((struct index_node *)son, ins_req);
				/*node has splitted, free it*/
				seg_free_index_node(ins_req->metadata.handle->db_desc, level_id,
						    ins_req->metadata.tree_id, (struct index_node *)son);
				// free_logical_node(&(req->allocator_desc), son);
			} else if (0 == son->height) {
				if (reorganize_dynamic_leaf((struct bt_dynamic_leaf_node *)son,
							    db_desc->levels[level_id].leaf_size, ins_req))
					goto release_and_retry;
				split_res = split_leaf(ins_req, (leaf_node *)son);
			} else {
				log_fatal("Negative height? come on");
				BUG_ON();
			}

			if (NULL == father) {
				/*Root was splitted*/
				struct index_node *new_root = (struct index_node *)seg_get_index_node(
					ins_req->metadata.handle->db_desc, level_id, ins_req->metadata.tree_id, -1);

				index_init_node(ADD_GUARD, new_root, rootNode);

				struct node_header *new_root_header = index_node_get_header(new_root);
				new_root_header->height = db_desc->levels[ins_req->metadata.level_id]
								  .root_w[ins_req->metadata.tree_id]
								  ->height +
							  1;

				struct pivot_pointer left = { .child_offt = ABSOLUTE_ADDRESS(split_res.left_child) };
				struct pivot_pointer right = { .child_offt = ABSOLUTE_ADDRESS(split_res.right_child) };
				struct insert_pivot_req ins_pivot_req = {
					.node = new_root,
					.left_child = &left,
					.key = (struct pivot_key *)split_res.middle_key,
					.right_child = &right
				};
				if (!index_insert_pivot(&ins_pivot_req)) {
					log_fatal("Cannot insert pivot!");
					_exit(EXIT_FAILURE);
				}
				/*new write root of the tree*/
				db_desc->levels[level_id].root_w[ins_req->metadata.tree_id] = (node_header *)new_root;
				goto release_and_retry;
			}
			/*Insert pivot at father*/
			struct pivot_pointer left = { .child_offt = ABSOLUTE_ADDRESS(split_res.left_child) };
			struct pivot_pointer right = { .child_offt = ABSOLUTE_ADDRESS(split_res.right_child) };
			struct insert_pivot_req ins_pivot_req = { .node = (struct index_node *)father,
								  .left_child = &left,
								  .key = (struct pivot_key *)split_res.middle_key,
								  .right_child = &right };
			if (!index_insert_pivot(&ins_pivot_req)) {
				log_fatal("Cannot insert pivot! pivot is %u",
					  get_key_size((struct kv_splice *)ins_pivot_req.key));
				_exit(EXIT_FAILURE);
			}
			goto release_and_retry;
		}

		if (son->height == 0)
			break;

		struct index_node *n_son = (struct index_node *)son;

		struct pivot_pointer *son_pivot =
			index_search_get_pivot(n_son, ins_req->key_value_buf, ins_req->metadata.key_format);

		father = son;
		son = REAL_ADDRESS(son_pivot->child_offt);
		assert(son);

		/*Take the lock of the next node before its traversal*/
		lock = _find_position(
			(const lock_table **)ins_req->metadata.handle->db_desc->levels[level_id].level_lock_table, son);

		upper_level_nodes[size++] = lock;
		if (RWLOCK_WRLOCK(&lock->rx_lock) != 0) {
			log_fatal("ERROR unlocking reason follows rc");
			BUG_ON();
		}

		/*Node lock acquired */
		ins_req->metadata.reorganized_leaf_pos_INnode = (uint64_t *)son_pivot;

		/*if the node is not safe hold its ancestor's lock else release locks from
    ancestors */

		if (!is_split_needed(son, ins_req, db_desc->levels[level_id].leaf_size)) {
			_unlock_upper_levels(upper_level_nodes, size - 1, release);
			release = size - 1;
		}
	}
	/*Succesfully reached a bin (bottom internal node)*/
	if (son->type != leafRootNode)
		assert((size - 1) - release == 0);

	if (son->height != 0) {
		log_fatal("FATAL son corrupted");
		BUG_ON();
	}

	insert_KV_at_leaf(ins_req, son);
	/*Unlock remaining locks*/
	_unlock_upper_levels(upper_level_nodes, size, release);
	__sync_fetch_and_sub(num_level_writers, 1);
	return PAR_SUCCESS;
}

static uint8_t writers_join_as_readers(bt_insert_req *ins_req)
{
	/*The array with the locks that belong to this thread from upper levels*/
	lock_table *upper_level_nodes[MAX_HEIGHT];
	node_header *son = NULL;
	lock_table *lock = NULL;

	db_descriptor *db_desc = ins_req->metadata.handle->db_desc;
	uint32_t level_id = ins_req->metadata.level_id;
	lock_table *guard_of_level = &db_desc->levels[level_id].guard_of_level;
	int64_t *num_level_writers = &db_desc->levels[level_id].active_operations;

	unsigned size = 0;
	unsigned release = 0;

	/*
* Caution no retry here, we just optimistically try to insert,
* if we donot succeed we try with concurrent_insert
*/
	/*Acquire read guard lock*/

	if (RWLOCK_RDLOCK(&guard_of_level->rx_lock) != 0) {
		log_fatal("Failed to acquire guard lock for db: %s", db_desc->db_superblock->db_name);
		perror("Reason: ");
		BUG_ON();
	}

	wait_for_available_level0_tree(ins_req->metadata.handle, level_id, 1);
	/*now look which is the active_tree of L0*/
	if (ins_req->metadata.level_id == 0)
		ins_req->metadata.tree_id = ins_req->metadata.handle->db_desc->levels[0].active_tree;

	/*mark your presence*/
	__sync_fetch_and_add(num_level_writers, 1);
	upper_level_nodes[size++] = guard_of_level;

	if (db_desc->levels[level_id].root_w[ins_req->metadata.tree_id] == NULL ||
	    db_desc->levels[level_id].root_w[ins_req->metadata.tree_id]->type == leafRootNode) {
		_unlock_upper_levels(upper_level_nodes, size, release);
		__sync_fetch_and_sub(num_level_writers, 1);
		return PAR_FAILURE;
	}

	/*acquire read lock of the current root*/
	lock = _find_position((const lock_table **)db_desc->levels[level_id].level_lock_table,
			      db_desc->levels[level_id].root_w[ins_req->metadata.tree_id]);

	if (RWLOCK_RDLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR locking");
		BUG_ON();
	}

	upper_level_nodes[size++] = lock;
	son = db_desc->levels[level_id].root_w[ins_req->metadata.tree_id];
	assert(son->height);
	while (1) {
		if (is_split_needed(son, ins_req, db_desc->levels[level_id].leaf_size)) {
			/*failed needs split*/
			_unlock_upper_levels(upper_level_nodes, size, release);
			__sync_fetch_and_sub(num_level_writers, 1);
			return PAR_FAILURE;
		}

		uint64_t child_offt = index_binary_search((struct index_node *)son, ins_req->key_value_buf,
							  ins_req->metadata.key_format);
		son = (node_header *)REAL_ADDRESS(child_offt);
		assert(son);

		if (son->height == 0)
			break;
		/*Acquire the lock of the next node before its traversal*/
		lock = _find_position((const lock_table **)db_desc->levels[level_id].level_lock_table, son);
		upper_level_nodes[size++] = lock;

		if (RWLOCK_RDLOCK(&lock->rx_lock) != 0) {
			log_fatal("ERROR unlocking");
			BUG_ON();
		}
		/*lock of node acquired */
		_unlock_upper_levels(upper_level_nodes, size - 1, release);
		release = size - 1;
	}

	lock = _find_position((const lock_table **)db_desc->levels[level_id].level_lock_table, son);
	upper_level_nodes[size++] = lock;

	if (RWLOCK_WRLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR unlocking");
		BUG_ON();
	}

	if (is_split_needed(son, ins_req, db_desc->levels[level_id].leaf_size)) {
		_unlock_upper_levels(upper_level_nodes, size, release);
		__sync_fetch_and_sub(num_level_writers, 1);
		return PAR_FAILURE;
	}

	/*Succesfully reached a bin (bottom internal node)*/
	if (son->height != 0) {
		log_fatal("FATAL son corrupted");
		BUG_ON();
	}

	insert_KV_at_leaf(ins_req, son);
	/*Unlock remaining locks*/
	_unlock_upper_levels(upper_level_nodes, size, release);
	__sync_fetch_and_sub(num_level_writers, 1);
	return PAR_SUCCESS;
}

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
#include "../common/common.h"
#include "conf.h"
#include "dynamic_leaf.h"
#include "gc.h"
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

int32_t index_order = -1;

pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_spinlock_t log_buffer_lock;

/*number of locks per level*/
const uint32_t size_per_height[MAX_HEIGHT] = { 8192, 4096, 2048, 1024, 512, 256, 128, 64, 32 };

static uint8_t writers_join_as_readers(bt_insert_req *ins_req);
static uint8_t concurrent_insert(bt_insert_req *ins_req);

void assert_index_node(node_header *node);

static struct bt_rebalance_result split_index(node_header *node, bt_insert_req *ins_req);

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
		key_cmp->key_size = *(uint32_t *)key_buf;
		key_cmp->key = (char *)key_buf + sizeof(uint32_t);
		key_cmp->key_format = KV_FORMAT;
	} else if (key_format == KV_PREFIX) {
		key_cmp->key_size = PREFIX_SIZE;
		key_cmp->key = ((struct bt_leaf_entry *)key_buf)->prefix;
		key_cmp->kv_dev_offt = ((struct bt_leaf_entry *)key_buf)->dev_offt;
		key_cmp->key_format = KV_PREFIX;
	} else {
		log_fatal("Unknown key category, exiting");
		BUG_ON();
	}
}

/**
 * @param   index_key: address of the index_key
 * @param   index_key_len: length of the index_key in encoded form first 2
 * significant bytes row_key_size least 2 significant bytes quallifier size
 * @param   query_key: address of query_key
 * @param   query_key_len: query_key length again in encoded form
 */

int64_t key_cmp(struct key_compare *key1, struct key_compare *key2)
{
	int64_t ret;
	uint32_t size;
	/*we need the left most entry*/
	if (key2->is_NIL == 1)
		return 1;

	if (key1->is_NIL == 1)
		return -1;

	if (key1->key_format == KV_FORMAT && key2->key_format == KV_FORMAT) {
		size = key1->key_size;
		if (size > key2->key_size)
			size = key2->key_size;

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
		if (ret == 0) {
			/*we have a tie, prefix didn't help, fetch query_key form KV log*/
			struct kv_format *key2f = (struct kv_format *)key2->kv_dev_offt;

			size = key1->key_size;
			if (size > key2f->key_size)
				size = key2f->key_size;

			ret = memcmp(key1->key, key2f->key_buf, size);

			if (ret != 0)
				return ret;

			return key1->key_size - key2f->key_size;
		}
		return ret;
	}

	if (key1->key_format == KV_PREFIX && key2->key_format == KV_FORMAT) {
		if (key2->key_size >= PREFIX_SIZE)
			ret = prefix_compare(key1->key, key2->key, PREFIX_SIZE);
		else // check here TODO
			ret = prefix_compare(key1->key, key2->key, key2->key_size);

		if (ret == 0) {
			/* we have a tie, prefix didn't help, fetch query_key form KV log*/
			struct kv_format *key1f = (struct kv_format *)key1->kv_dev_offt;

			size = key2->key_size;
			if (size > key1f->key_size)
				size = key1f->key_size;

			ret = memcmp(key1f->key_buf, key2->key, size);
			if (ret != 0)
				return ret;

			return key1f->key_size - key2->key_size;
		}
		return ret;
	}

	/*KV_PREFIX and KV_PREFIX*/
	ret = prefix_compare(key1->key, key2->key, PREFIX_SIZE);
	if (ret != 0)
		return ret;
	/*full comparison*/
	struct kv_format *key1f = (struct kv_format *)key1->kv_dev_offt;
	struct kv_format *key2f = (struct kv_format *)key2->kv_dev_offt;

	size = key2f->key_size;
	if (size > key1f->key_size) {
		size = key1f->key_size;
	}

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
	double kv_leaf_entry = sizeof(struct bt_leaf_entry) + sizeof(struct bt_static_leaf_slot_array) + (1 / CHAR_BIT);
	double numentries_without_metadata;
	uint32_t bitmap_entries;
	uint32_t slot_array_entries;
	uint32_t kv_entries;

	numentries_without_metadata = (level->leaf_size - sizeof(struct bt_static_leaf_node)) / kv_leaf_entry;
	bitmap_entries = (numentries_without_metadata / CHAR_BIT) + 1;
	slot_array_entries = numentries_without_metadata;
	kv_entries = (level->leaf_size - sizeof(struct bt_static_leaf_node) - bitmap_entries -
		      (slot_array_entries * sizeof(struct bt_static_leaf_slot_array))) /
		     sizeof(struct bt_leaf_entry);
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
	struct bt_kv_log_address reply = { .addr = NULL, .tail_id = 0, .in_tail = UINT8_MAX };
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
	uint32_t i;
	for (i = 0; i < n_chunks; ++i) {
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
	db_desc->lsn = 0;
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
	db_desc->lsn = db_desc->db_superblock->lsn;
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

static db_descriptor *get_db_from_volume(char *volume_name, char *db_name, char create_db)
{
	struct db_descriptor *db_desc = NULL;
	struct volume_descriptor *volume_desc = mem_get_volume_desc(volume_name);
	struct pr_db_superblock *db_superblock = NULL;
	uint8_t new_db = 0;

	if (CREATE_DB == create_db)
		db_superblock = get_db_superblock(volume_desc, db_name, strlen(db_name) + 1, 1, &new_db);
	else
		db_superblock = get_db_superblock(volume_desc, db_name, strlen(db_name) + 1, 0, &new_db);

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
			/*
     * init_fresh_db allocates space for the L0_recovery log and large.
     * As a result we need to acquire a txn_id for the L0
    */

			log_info("Got txn %lu for the initialization of Large and L0_recovery_logs of DB: %s",
				 db_desc->levels[0].allocation_txn_id[0], db_name);
			init_fresh_db(db_desc);
		}
	} else
		log_info("DB: %s NOT found", db_name);
	return db_desc;
}
/*</new_persistent_design>*/

db_handle *internal_db_open(struct volume_descriptor *volume_desc, uint64_t start, uint64_t size, char *db_name,
			    char CREATE_FLAG)
{
	struct db_handle *handle = NULL;
	const uint32_t leaf_size_per_level[10] = { LEVEL0_LEAF_SIZE, LEVEL1_LEAF_SIZE, LEVEL2_LEAF_SIZE,
						   LEVEL3_LEAF_SIZE, LEVEL4_LEAF_SIZE, LEVEL5_LEAF_SIZE,
						   LEVEL6_LEAF_SIZE, LEVEL7_LEAF_SIZE };
	struct db_descriptor *db = NULL;
	struct lib_option *dboptions = NULL;

	fprintf(stderr, "\n%s[%s:%s:%d](\"%s\", %" PRIu64 ", %" PRIu64 ", %s);%s\n", "\033[0;32m", __FILE__, __func__,
		__LINE__, volume_desc->volume_name, start, size, db_name, "\033[0m");

	parse_options(&dboptions);
#if DISABLE_LOGGING
	log_set_quiet(true);
#endif
	index_order = IN_LENGTH;
	_Static_assert(sizeof(struct index_node) == 4096, "Index node is not page aligned");
	_Static_assert(sizeof(struct segment_header) == 4096, "Segment header is not 4 KB");
	db = klist_find_element_with_key(volume_desc->open_databases, db_name);

	if (db != NULL) {
		log_info("DB %s already open for volume", db_name);
		handle = calloc(1, sizeof(struct db_handle));
		memset(handle, 0x00, sizeof(db_handle));
		handle->volume_desc = volume_desc;
		handle->db_desc = db;
		++handle->db_desc->reference_count;
		goto exit;
	}

	uint64_t level0_size;
	uint64_t growth_factor;
	uint64_t level_medium_inplace;

	struct lib_option *option;

	check_option(dboptions, "level0_size", &option);
	level0_size = MB(option->value.count);

	check_option(dboptions, "growth_factor", &option);
	growth_factor = option->value.count;

	check_option(dboptions, "level_medium_inplace", &option);
	level_medium_inplace = option->value.count;

	struct db_descriptor *db_desc = get_db_from_volume(volume_desc->volume_name, db_name, CREATE_FLAG);
	if (!db_desc) {
		if (CREATE_DB == CREATE_FLAG) {
			log_warn("Sorry no room for new DB %s", db_name);
			handle = NULL;
			goto exit;
		}
		log_warn("DB %s not found instructed not to create a new one", db_name);
		handle = NULL;
		goto exit;
	}

	db_desc->level_medium_inplace = level_medium_inplace;
	handle = calloc(1, sizeof(db_handle));
	if (!handle) {
		log_fatal("calloc failed");
		BUG_ON();
	}

	/*Remove later*/
	handle->db_desc = db_desc;
	handle->volume_desc = db_desc->db_volume;

	/*init soft state for all levels*/
	for (uint8_t level_id = 0; level_id < MAX_LEVELS; level_id++) {
		init_leaf_sizes_perlevel(&handle->db_desc->levels[level_id]);

		if (level_id != 0)
			handle->db_desc->levels[level_id].max_level_size =
				handle->db_desc->levels[level_id - 1].max_level_size * growth_factor;
		else
			handle->db_desc->levels[level_id].max_level_size = level0_size;

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

	klist_add_first(volume_desc->open_databases, handle->db_desc, db_name, NULL);
	handle->db_desc->stat = DB_OPEN;

	log_info("Opened DB %s starting its compaction daemon", db_name);

	sem_init(&handle->db_desc->compaction_daemon_interrupts, PTHREAD_PROCESS_PRIVATE, 0);

	if (pthread_create(&(handle->db_desc->compaction_daemon), NULL, compaction_daemon, (void *)handle) != 0) {
		log_fatal("Failed to start compaction_daemon for db %s", db_name);
		BUG_ON();
	}

	if (!volume_desc->gc_thread_spawned) {
		if (pthread_create(&(handle->db_desc->gc_thread), NULL, gc_log_entries, (void *)handle) != 0) {
			log_fatal("Failed to start garbage collection thread for db %s", db_name);
			BUG_ON();
		}
		++volume_desc->gc_thread_spawned;
	}
	assert(volume_desc->gc_thread_spawned <= 1);

	/*get allocation transaction id for level-0*/
	MUTEX_INIT(&handle->db_desc->flush_L0_lock, NULL);
	//db_desc->levels[0].allocation_txn_id[db_desc->levels[0].active_tree] = rul_start_txn(db_desc);
	pr_flush_L0(db_desc, db_desc->levels[0].active_tree);
	db_desc->levels[0].allocation_txn_id[db_desc->levels[0].active_tree] = rul_start_txn(db_desc);
	recover_L0(handle->db_desc);

exit:
	destroy_options(dboptions);
	dboptions = NULL;
	return handle;
}

db_handle *db_open(char *volumeName, uint64_t start, uint64_t size, char *db_name, char CREATE_FLAG)
{
	MUTEX_LOCK(&init_lock);

	struct volume_descriptor *volume_desc = mem_get_volume_desc(volumeName);
	if (!volume_desc) {
		log_fatal("Failed to open volume %s", volumeName);
		BUG_ON();
	}
	assert(volume_desc->open_databases);
	/*retrieve gc db*/

	db_handle *handle = internal_db_open(volume_desc, start, size, db_name, CREATE_FLAG);

	MUTEX_UNLOCK(&init_lock);
	return handle;
}

enum parallax_status db_close(db_handle *handle)
{
	MUTEX_LOCK(&init_lock);
	/*verify that this is a valid db*/
	int not_valid_db = klist_find_element_with_key(handle->volume_desc->open_databases,
						       handle->db_desc->db_superblock->db_name) == NULL;

	if (not_valid_db) {
		log_warn("Received close for db: %s that is not listed as open",
			 handle->db_desc->db_superblock->db_name);
		goto finish;
	}

	--handle->db_desc->reference_count;

	if (handle->db_desc->reference_count < 0) {
		log_fatal("Negative referece count for DB %s", handle->db_desc->db_superblock->db_name);
		BUG_ON();
	}
	if (handle->db_desc->reference_count > 0) {
		log_warn("Sorry more guys uses this DB: %s", handle->db_desc->db_superblock->db_name);
		MUTEX_UNLOCK(&init_lock);
		return PARALLAX_SUCCESS;
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
	handle->db_desc->stat = DB_IS_CLOSING;
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

	handle->db_desc->stat = DB_TERMINATE_COMPACTION_DAEMON;
	sem_post(&handle->db_desc->compaction_daemon_interrupts);
	while (handle->db_desc->stat != DB_IS_CLOSING)
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
	return PARALLAX_SUCCESS;
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

uint8_t insert_key_value(db_handle *handle, void *key, void *value, uint32_t key_size, uint32_t value_size,
			 request_type op_type)
{
	bt_insert_req ins_req;
	char __tmp[KV_MAX_SIZE];
	char *key_buf = __tmp;
	double kv_ratio;
	uint32_t kv_size;

	if (DB_IS_CLOSING == handle->db_desc->stat) {
		log_warn("Sorry DB: %s is closing", handle->db_desc->db_superblock->db_name);
		return PARALLAX_FAILURE;
	}

	if (key_size > MAX_KEY_SIZE) {
		log_info("Keys > %d bytes are not supported!", MAX_KEY_SIZE);
		return PARALLAX_FAILURE;
	}

	kv_size = sizeof(uint32_t) + key_size + sizeof(uint32_t) + value_size /* + sizeof(uint64_t) */;
	kv_ratio = ((double)key_size) / value_size;

	if (kv_size > KV_MAX_SIZE) {
		log_fatal("Key buffer overflow %u", kv_size);
		BUG_ON();
	}

	/*prepare the request*/
	*(uint32_t *)key_buf = key_size;
	memcpy(key_buf + sizeof(uint32_t), key, key_size);
	*(uint32_t *)(key_buf + sizeof(uint32_t) + key_size) = value_size;
	memcpy(key_buf + sizeof(uint32_t) + key_size + sizeof(uint32_t), value, value_size);
	ins_req.metadata.handle = handle;
	ins_req.key_value_buf = key_buf;
	ins_req.metadata.kv_size = kv_size;
	ins_req.metadata.level_id = 0;
	ins_req.metadata.key_format = KV_FORMAT;
	ins_req.metadata.append_to_log = 1;
	ins_req.metadata.gc_request = 0;
	ins_req.metadata.special_split = 0;
	ins_req.metadata.tombstone = op_type == deleteOp;

	if (kv_ratio >= 0.0 && kv_ratio < 0.02) {
		ins_req.metadata.cat = BIG_INLOG;
	} else if (kv_ratio >= 0.02 && kv_ratio <= 0.2) {
#if MEDIUM_LOG_UNSORTED
		ins_req.metadata.cat = MEDIUM_INLOG;
#else
		ins_req.metadata.cat = MEDIUM_INPLACE;
#endif
	} else {
		ins_req.metadata.cat = SMALL_INPLACE;
	}

	if (op_type == deleteOp)
		ins_req.metadata.cat = SMALL_INPLACE;

	/*
* Note for L0 inserts since active_tree changes dynamically we decide which
* is the active_tree after
* acquiring the guard lock of the region
* */

	return _insert_key_value(&ins_req);
}

/**
 * Inserts a serialized key value pair by using the buffer provided by the user.
 * @param serialized_key_value is a buffer containing the serialized key value pair.
 * The format of the key value pair is | key_size | key | value_size | value |, where {key,value}_size is uint32_t.
 * */

uint8_t serialized_insert_key_value(db_handle *handle, const char *serialized_key_value)
{
	bt_insert_req ins_req = { .metadata.handle = handle,
				  .key_value_buf = (char *)serialized_key_value,
				  .metadata.level_id = 0,
				  .metadata.key_format = KV_FORMAT,
				  .metadata.append_to_log = 1 };

	if (DB_IS_CLOSING == handle->db_desc->stat) {
		log_warn("Sorry DB: %s is closing", handle->db_desc->db_superblock->db_name);
		return PARALLAX_FAILURE;
	}

	uint32_t key_size = KEY_SIZE(serialized_key_value);
	if (key_size > MAX_KEY_SIZE) {
		log_info("Keys > %d bytes are not supported!", MAX_KEY_SIZE);
		return PARALLAX_FAILURE;
	}
	uint32_t value_size = VALUE_SIZE(serialized_key_value + key_size + sizeof(key_size));
	uint32_t kv_size = sizeof(uint32_t) + key_size + sizeof(uint32_t) + value_size;
	double kv_ratio = ((double)key_size) / value_size;

	if (kv_size > KV_MAX_SIZE) {
		log_fatal("Key buffer overflow %u", kv_size);
		BUG_ON();
	}

	ins_req.metadata.kv_size = kv_size;

	if (kv_ratio >= 0.0 && kv_ratio < 0.02) {
		ins_req.metadata.cat = BIG_INLOG;
	} else if (kv_ratio >= 0.02 && kv_ratio <= 0.2) {
#if MEDIUM_LOG_UNSORTED
		ins_req.metadata.cat = MEDIUM_INLOG;
#else
		ins_req.metadata.cat = MEDIUM_INPLACE;
#endif
	} else {
		ins_req.metadata.cat = SMALL_INPLACE;
	}

	return _insert_key_value(&ins_req);
}

void extract_keyvalue_size(log_operation *req, metadata_tologop *data_size)
{
	switch (req->optype_tolog) {
	case insertOp:
		if (req->metadata->key_format == KV_FORMAT) {
			data_size->key_len = *(uint32_t *)req->ins_req->key_value_buf;
			data_size->value_len =
				*(uint32_t *)(req->ins_req->key_value_buf + sizeof(uint32_t) + (data_size->key_len));
			data_size->kv_size = req->metadata->kv_size;
		} else {
			data_size->key_len = *(uint32_t *)*(uint64_t *)(req->ins_req->key_value_buf + PREFIX_SIZE);
			data_size->value_len =
				*(uint32_t *)((char *)(*(uint64_t *)(req->ins_req->key_value_buf + PREFIX_SIZE)) +
					      sizeof(uint32_t) + (data_size->key_len));
			data_size->kv_size = data_size->key_len + data_size->value_len + sizeof(data_size->key_len) * 2;
		}
		break;
	case deleteOp:
		data_size->key_len = *(uint32_t *)req->ins_req->key_value_buf;
		data_size->value_len = 0;
		data_size->kv_size = sizeof(struct bt_delete_marker) + data_size->key_len;
		break;
	default:
		log_fatal("Trying to append unknown operation in log! ");
		BUG_ON();
	}
}

//######################################################################################################
struct pr_log_ticket {
	// in var
	struct log_tail *tail;
	struct log_operation *req;
	struct metadata_tologop *data_size;
	struct log_sequence_number lsn;
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

	uint64_t offset_in_seg = ticket->log_offt % SEGMENT_SIZE;
	uint64_t offt = offset_in_seg;
	switch (ticket->req->optype_tolog) {
	case insertOp: {
		// first the lsn
		memcpy(&ticket->tail->buf[offt], &ticket->lsn, sizeof(struct log_sequence_number));
		offt += sizeof(struct log_sequence_number);

		ticket->op_size = sizeof(ticket->data_size->key_len) + ticket->data_size->key_len +
				  sizeof(ticket->data_size->value_len) + ticket->data_size->value_len;
		// log_info("Copying ta log offt %llu in buf %u bytes %u", ticket->log_offt,
		// offt_in_seg, ticket->op_size);

		memcpy(&ticket->tail->buf[offt], ticket->req->ins_req->key_value_buf, ticket->op_size);
		ticket->op_size += sizeof(struct log_sequence_number);
		break;
	}
	case deleteOp: {
		struct bt_delete_marker dm = { .marker_id = BT_DELETE_MARKER_ID,
					       .key_size = ticket->data_size->key_len };

		// Append the LSN + the delete marker
		memcpy(&ticket->tail->buf[offt], &ticket->lsn, sizeof(struct log_sequence_number));
		offt += sizeof(struct log_sequence_number);
		memcpy(&ticket->tail->buf[offt], &dm, sizeof(struct bt_delete_marker));
		offt += sizeof(struct bt_delete_marker);
		ticket->op_size = sizeof(struct log_sequence_number) + sizeof(struct bt_delete_marker);

		// Append the deleted key
		memcpy(&ticket->tail->buf[offt], ticket->req->ins_req->key_value_buf + sizeof(uint32_t), dm.key_size);
		ticket->op_size += ticket->data_size->key_len;
		break;
	}
	case paddingOp: {
		if (offset_in_seg == 0)
			ticket->op_size = 0;
		else {
			ticket->op_size = SEGMENT_SIZE - offset_in_seg;
			//log_info("Time for padding for log_offset %llu offt in seg %llu pad bytes %u ",
			//	 ticket->log_offt, offt_in_seg, ticket->op_size);
			memset(&ticket->tail->buf[offset_in_seg], 0, ticket->op_size);
		}
		break;
	}
	default:
		log_fatal("Unknown op");
		BUG_ON();
	}

	uint32_t remaining = ticket->op_size;
	uint32_t curr_offt_in_seg = offset_in_seg;
	while (remaining > 0) {
		uint32_t chunk_id = curr_offt_in_seg / LOG_CHUNK_SIZE;
		int64_t offt_in_chunk = curr_offt_in_seg - (chunk_id * LOG_CHUNK_SIZE);
		int64_t bytes = LOG_CHUNK_SIZE - offt_in_chunk;
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
	uint32_t available_space_in_log;
	uint32_t reserve_needed_space = sizeof(struct log_sequence_number) + data_size->kv_size;

	MUTEX_LOCK(&handle->db_desc->lock_log);

	/*append data part in the data log*/
	if (log_metadata->log_desc->size == 0)
		available_space_in_log = SEGMENT_SIZE;
	else if (log_metadata->log_desc->size % SEGMENT_SIZE != 0)
		available_space_in_log = SEGMENT_SIZE - (log_metadata->log_desc->size % SEGMENT_SIZE);
	else
		available_space_in_log = 0;

	uint32_t num_chunks = SEGMENT_SIZE / LOG_CHUNK_SIZE;
	int segment_change = 0;
	//log_info("Direct IO in log kv size is %u log size %u avail space %u", data_size->kv_size,
	//	 log_metadata->log_desc->size, available_space_in_log);
	if (req->metadata->tombstone) {
		reserve_needed_space =
			sizeof(struct log_sequence_number) + sizeof(struct bt_delete_marker) + data_size->key_len;
	}

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
	log_kv_entry_ticket.lsn.id = __sync_fetch_and_add(&handle->db_desc->lsn, 1);

	/*Where we *will* store it on the device*/
	struct segment_header *device_location = REAL_ADDRESS(log_metadata->log_desc->tail_dev_offt);
	addr_inlog = (void *)((uint64_t)device_location + (log_metadata->log_desc->size % SEGMENT_SIZE));

	req->metadata->log_offset = log_metadata->log_desc->size;
	log_metadata->log_desc->size += reserve_needed_space;
	MUTEX_UNLOCK(&handle->db_desc->lock_log);

	if (segment_change && available_space_in_log > 0) {
		// do the padding IO as well
		pr_do_log_IO(&pad_ticket);
	}
	pr_copy_kv_to_tail(&log_kv_entry_ticket);
	pr_do_log_IO(&log_kv_entry_ticket);

	return addr_inlog + sizeof(struct log_sequence_number);
}

void *append_key_value_to_log(log_operation *req)
{
	struct log_towrite log_metadata;
	struct metadata_tologop data_size;
	db_handle *handle = req->metadata->handle;

	log_metadata.level_id = req->metadata->level_id;
	log_metadata.status = req->metadata->cat;
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
#if MEDIUM_LOG_UNSORTED
		if (level_id) {
			log_fatal("KV separation allowed for medium only for L0!");
			BUG_ON();
		} else {
			log_metadata.log_desc = &handle->db_desc->medium_log;
			return bt_append_to_log_direct_IO(req, &log_metadata, &data_size);
		}
#else
		if (level_id == 0) {
			log_fatal("MEDIUM_INLOG not allowed for level_id 0!");
			BUG_ON();
		} else {
			log_metadata.log_desc = &handle->db_desc->medium_log;
			return bt_append_to_log_direct_IO(req, &log_metadata, &data_size);
		}
#endif
	}
	case BIG_INLOG:
		log_metadata.log_desc = &handle->db_desc->big_log;
		return bt_append_to_log_direct_IO(req, &log_metadata, &data_size);
	default:
		log_fatal("Unknown category %u", log_metadata.status);
		BUG_ON();
	}
}

uint8_t _insert_key_value(bt_insert_req *ins_req)
{
	ins_req->metadata.handle->db_desc->dirty = 1;
	uint8_t rc = PARALLAX_SUCCESS;

	if (writers_join_as_readers(ins_req) == PARALLAX_SUCCESS) {
		rc = PARALLAX_SUCCESS;
	} else if (concurrent_insert(ins_req) != PARALLAX_SUCCESS) {
		log_warn("insert failed!");
		rc = PARALLAX_FAILURE;
	}

	return rc;
}

// cppcheck-suppress unusedFunction
int find_key_in_bloom_filter(db_descriptor *db_desc, int level_id, char *key)
{
#if ENABLE_BLOOM_FILTERS
	char prefix_key[PREFIX_SIZE];
	if (*(uint32_t *)key < PREFIX_SIZE) {
		memset(prefix_key, 0x00, PREFIX_SIZE);
		memcpy(prefix_key, key + sizeof(uint32_t), *(uint32_t *)key);
		return bloom_check(&db_desc->levels[level_id].bloom_filter[0], prefix_key, PREFIX_SIZE);
	} else
		return bloom_check(&db_desc->levels[level_id].bloom_filter[0], key + sizeof(uint32_t), PREFIX_SIZE);
#else
	(void)db_desc;
	(void)level_id;
	(void)key;
#endif
	return -1;
}

static inline void lookup_in_tree(struct lookup_operation *get_op, int level_id, int tree_id)
{
	node_header *curr_node, *son_node = NULL;
	char *key_addr_in_leaf = NULL;
	struct find_result ret_result;
	void *next_addr;
	lock_table *prev = NULL, *curr = NULL;
	struct node_header *root = NULL;

	struct db_descriptor *db_desc = get_op->db_desc;
	if (db_desc->levels[level_id].root_w[tree_id] != NULL) {
		/* log_info("Level %d with tree_id %d has root_w",level_id,tree_id); */
		root = db_desc->levels[level_id].root_w[tree_id];
	} else if (db_desc->levels[level_id].root_r[tree_id] != NULL) {
		/* log_info("Level %d with tree_id %d has root_w",level_id,tree_id); */
		root = db_desc->levels[level_id].root_r[tree_id];
	} else {
		/* log_info("Level %d is empty with tree_id %d",level_id,tree_id); */
		/* if (RWLOCK_UNLOCK(&curr->rx_lock) != 0) */
		/* 	BUG_ON(); */
		get_op->found = 0;
		return;
	}

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

	curr_node = root;
	if (curr_node->type == leafRootNode) {
		curr = _find_position((const lock_table **)db_desc->levels[level_id].level_lock_table, curr_node);

		if (RWLOCK_RDLOCK(&curr->rx_lock) != 0)
			BUG_ON();

		ret_result = find_key_in_dynamic_leaf((struct bt_dynamic_leaf_node *)curr_node, db_desc,
						      get_op->kv_buf + sizeof(uint32_t), *(uint32_t *)get_op->kv_buf,
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

#ifdef NEW_INDEX_NODE_LAYOUT
		uint64_t child_offset =
			new_index_node_binary_search((struct new_index_node *)curr_node, get_op->kv_buf, KV_FORMAT);
		son_node = (void *)REAL_ADDRESS(child_offset);
#else
		next_addr = _index_node_binary_search((struct index_node *)curr_node, get_op->kv_buf, KV_FORMAT);
		son_node = (void *)REAL_ADDRESS(*(uint64_t *)next_addr);
#endif

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

	ret_result = find_key_in_dynamic_leaf((struct bt_dynamic_leaf_node *)curr_node, db_desc,
					      get_op->kv_buf + sizeof(uint32_t), *(uint32_t *)get_op->kv_buf, level_id);
	get_op->tombstone = ret_result.tombstone;

deser:
	if (ret_result.kv) {
		struct bt_kv_log_address kv = { .addr = NULL, .tail_id = UINT8_MAX, .in_tail = 0 };
		get_op->key_device_address = NULL;

		if (ret_result.key_type == KV_INPLACE) {
			kv.addr = REAL_ADDRESS(ret_result.kv);
			get_op->key_device_address = ret_result.kv;
		} else if (ret_result.key_type == KV_INLOG) {
			key_addr_in_leaf = (char *)REAL_ADDRESS(*(uint64_t *)ret_result.kv);
			if (key_addr_in_leaf == NULL) {
				log_fatal("Encountered NULL pointer from KV in leaf");
				BUG_ON();
			}

			if (!level_id)
				kv = bt_get_kv_log_address(&db_desc->big_log, ABSOLUTE_ADDRESS(key_addr_in_leaf));
			else
				kv.addr = key_addr_in_leaf;

			get_op->key_device_address = (char *)ABSOLUTE_ADDRESS(kv.addr);
		} else {
			log_fatal("Corrupted KV location");
			BUG_ON();
		}
		assert(kv.addr);
		uint32_t *value_size = (uint32_t *)(kv.addr + sizeof(uint32_t) + KEY_SIZE(kv.addr));
		if (get_op->retrieve && !get_op->buffer_to_pack_kv) {
			get_op->buffer_to_pack_kv = malloc(*value_size);

			if (!get_op->buffer_to_pack_kv) {
				log_fatal("Malloc failed");
				BUG_ON();
			}

			get_op->size = *value_size;
		}

		//log_info("key size: %u key: %s value size: %u", KEY_SIZE(L.addr), L.addr + 4, *value_size);
		//log_info("In tail?: %u which tail?: %u value size %u offt in buf: %llu", L.in_tail, L.tail_id,
		//	 *value_size, ABSOLUTE_ADDRESS(get_op->value_device_address) % SEGMENT_SIZE);

		if (get_op->retrieve && get_op->size <= *value_size) {
			/*check if enough*/
			memcpy(get_op->buffer_to_pack_kv,
			       kv.addr + sizeof(uint32_t) + KEY_SIZE(kv.addr) + sizeof(uint32_t), *value_size);
			get_op->buffer_overflow = 0;
		} else
			get_op->buffer_overflow = *value_size;

		get_op->found = 1;
		if (get_op->tombstone)
			get_op->key_device_address = NULL;

		if (kv.in_tail)
			bt_done_with_value_log_address(&db_desc->big_log, &kv);
	} else {
		get_op->found = 0;
	}

	if (RWLOCK_UNLOCK(&curr->rx_lock) != 0)
		BUG_ON();

	__sync_fetch_and_sub(&db_desc->levels[level_id].active_operations, 1);
}

void find_key(struct lookup_operation *get_op)
{
	if (DB_IS_CLOSING == get_op->db_desc->stat) {
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

/**
 * @param   node:
 * @param   left_child:
 * @param   right_child:
 * @param   key:
 * @param   key_len:
 |block_header|pointer_to_node|pointer_to_key|pointer_to_node |
 pointer_to_key|...
*/
int8_t update_index(struct index_node *node, node_header *left_child, node_header *right_child, void *key_buf)
{
	assert(0);
	char *addr;
	uint64_t entry_val = 0;
	struct key_compare key1_cmp, key2_cmp;

	addr = (char *)node + sizeof(node_header);

	if (node->header.num_entries > 0) {
		int32_t middle;
		int32_t start_idx = 0;
		int32_t end_idx = node->header.num_entries - 1;
		while (1) {
			middle = (start_idx + end_idx) / 2;
			addr = ((char *)node) + sizeof(node_header) + sizeof(uint64_t) +
			       (middle * 2 * sizeof(uint64_t));
			char *index_key_buf = REAL_ADDRESS(*(uint64_t *)addr);
			/*key1 and key2 are KV_FORMATed*/
			init_key_cmp(&key1_cmp, index_key_buf, KV_FORMAT);
			init_key_cmp(&key2_cmp, key_buf, KV_FORMAT);
			int64_t ret = key_cmp(&key1_cmp, &key2_cmp);
			if (ret > 0) {
				end_idx = middle - 1;
				if (start_idx > end_idx)
					// addr is the same
					break;
			} else if (ret == 0) {
				log_fatal("key already present index_key %s key_buf %s", (char *)(index_key_buf + 4),
					  (char *)key_buf + 4);
				BUG_ON();
			} else {
				start_idx = middle + 1;
				if (start_idx > end_idx) {
					middle++;
					if (middle >= (int64_t)node->header.num_entries) {
						middle = node->header.num_entries;
						addr = ((char *)node) + sizeof(node_header) +
						       (middle * 2 * sizeof(uint64_t)) + sizeof(uint64_t);
					} else
						addr += (2 * sizeof(uint64_t));
					break;
				}
			}
		}

		void *dest_addr = addr + (2 * sizeof(uint64_t));
		size_t num_of_bytes = (node->header.num_entries - middle) * 2 * sizeof(uint64_t);
		memmove(dest_addr, addr, num_of_bytes);
		addr -= sizeof(uint64_t);
	} else
		addr = (char *)node + sizeof(node_header);

	/*update the entry*/
	if (left_child != 0)
		entry_val = (uint64_t)ABSOLUTE_ADDRESS(left_child);
	else
		entry_val = 0;

	memcpy(addr, &entry_val, sizeof(uint64_t));
	addr += sizeof(uint64_t);
	entry_val = (uint64_t)ABSOLUTE_ADDRESS(key_buf);
	memcpy(addr, &entry_val, sizeof(uint64_t));

	addr += sizeof(uint64_t);
	if (right_child != 0)
		entry_val = (uint64_t)ABSOLUTE_ADDRESS(right_child);
	else
		entry_val = 0;

	memcpy(addr, &entry_val, sizeof(uint64_t));
	return 1;
}

/**
 * @param   handle: database handle
 * @param   node: address of the index node where the key should be inserted
 * @param   left_child: address to the left child (full not absolute)
 * @param   right_child: address to the left child (full not absolute)
 * @param   key: address of the key to be inserted
 * @param   key_len: size of the key
 */
void insert_key_at_index(bt_insert_req *ins_req, struct index_node *node, node_header *left_child,
			 node_header *right_child, void *key_buf)
{
	void *key_addr = NULL;
	struct db_handle *handle = ins_req->metadata.handle;
	IN_log_header *d_header = NULL;
	IN_log_header *last_d_header = NULL;

	// assert_index_node(node);
	uint32_t avail_space = 0;
	if (node->header.key_log_size % KEY_BLOCK_SIZE != 0)
		avail_space = (int32_t)KEY_BLOCK_SIZE - (node->header.key_log_size % KEY_BLOCK_SIZE);

	uint32_t key_len = *(uint32_t *)key_buf;
	uint32_t req_space = (key_len + sizeof(uint32_t));

	if (avail_space < req_space) {
		/*room not sufficient get new block*/
		uint32_t allocated_space = (req_space + sizeof(IN_log_header)) / KEY_BLOCK_SIZE;
		if ((req_space + sizeof(IN_log_header)) % KEY_BLOCK_SIZE != 0)
			allocated_space++;
		allocated_space *= KEY_BLOCK_SIZE;

		if (allocated_space > KEY_BLOCK_SIZE) {
			log_fatal("Allocation request %d key block %d", allocated_space, KEY_BLOCK_SIZE);
			log_fatal("Cannot host index key larger than KEY_BLOCK_SIZE");
			BUG_ON();
		}

		d_header = seg_get_IN_log_block(handle->db_desc, ins_req->metadata.level_id, ins_req->metadata.tree_id);

		d_header->next = NULL;
		last_d_header = (IN_log_header *)REAL_ADDRESS(node->header.last_IN_log_header);
		last_d_header->next = (void *)ABSOLUTE_ADDRESS(d_header);
		node->header.last_IN_log_header = last_d_header->next;
		node->header.key_log_size +=
			(avail_space + sizeof(IN_log_header)); /* position the log to the newly added block*/
	}
	/* put the KV now */
	key_addr = (void *)REAL_ADDRESS((uint64_t)node->header.last_IN_log_header +
					(uint64_t)(node->header.key_log_size % KEY_BLOCK_SIZE));
	memcpy(key_addr, key_buf, sizeof(uint32_t) + key_len);

	uint8_t ret = update_index(node, left_child, right_child, key_addr);

	node->header.key_log_size += (sizeof(uint32_t) + key_len);

	if (ret)
		++node->header.num_entries;
	// assert_index_node(node);
}

/**
 * gesalous 05/06/2014 17:30
 * added method for splitting an index node
 * @ struct btree_hanlde * handle: The handle of the B+ tree
 * @ node_header * req->node: Node to be splitted
 * @ void * key : pointer to key
 */
static struct bt_rebalance_result split_index(node_header *node, bt_insert_req *ins_req)
{
	struct bt_rebalance_result result;
	node_header *tmp_index;
	char *full_addr;
	uint32_t i = 0;
	// assert_index_node(node);
	result.left_child = (node_header *)seg_get_index_node(
		ins_req->metadata.handle->db_desc, ins_req->metadata.level_id, ins_req->metadata.tree_id, INDEX_SPLIT);

	result.right_child = (node_header *)seg_get_index_node(
		ins_req->metadata.handle->db_desc, ins_req->metadata.level_id, ins_req->metadata.tree_id, INDEX_SPLIT);

	/*initialize*/
	full_addr = (char *)node + (uint64_t)sizeof(node_header);
	/*set node heights*/
	result.left_child->height = node->height;
	result.right_child->height = node->height;

	for (i = 0; i < node->num_entries; i++) {
		if (i < node->num_entries / 2)
			tmp_index = result.left_child;
		else
			tmp_index = result.right_child;

		node_header *left_child = (node_header *)REAL_ADDRESS(*(uint64_t *)full_addr);

		full_addr += sizeof(uint64_t);
		char *key_buf = (char *)REAL_ADDRESS(*(uint64_t *)full_addr);
		full_addr += sizeof(uint64_t);
		node_header *right_child = (node_header *)REAL_ADDRESS(*(uint64_t *)full_addr);

		if (i == node->num_entries / 2) {
			KEY_SIZE(result.middle_key) = KEY_SIZE(key_buf);
			memcpy(&result.middle_key[4], key_buf + 4, KEY_SIZE(result.middle_key));
			continue; /*middle key not needed, is going to the upper level*/
		}

		insert_key_at_index(ins_req, (struct index_node *)tmp_index, left_child, right_child, key_buf);
	}

	result.stat = INDEX_NODE_SPLITTED;
	// result.left_child->v2++; /*lamport counter*/
	// result.right_child->v2++; /*lamport counter*/
	// assert_index_node(result.left_child);
	// assert_index_node(result.right_child);
	return result;
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
#if !MEDIUM_LOG_UNSORTED
		assert(ins_req->metadata.cat != MEDIUM_INLOG);
#endif

		log_operation append_op = { .metadata = &ins_req->metadata,
					    .optype_tolog = insertOp,
					    .ins_req = ins_req };

		if (ins_req->metadata.tombstone == 1)
			append_op.optype_tolog = deleteOp;

		switch (ins_req->metadata.cat) {
		case SMALL_INPLACE:
			append_key_value_to_log(&append_op);
			break;
		case MEDIUM_INPLACE:
			append_key_value_to_log(&append_op);
			break;
#if MEDIUM_LOG_UNSORTED
		case MEDIUM_INLOG: {
			void *addr = append_key_value_to_log(&append_op);
			ins_req->kv_dev_offt = ABSOLUTE_ADDRESS(addr);
			assert(ins_req->kv_dev_offt != 0);
			break;
		}
#endif
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
					     sizeof(struct bt_leaf_entry));
		} else if (measure_level_used_space || medium_inlog) {
			__sync_fetch_and_add(&(ins_req->metadata.handle->db_desc->levels[level_id].level_size[tree_id]),
					     sizeof(struct bt_leaf_entry));
		} else {
			__sync_fetch_and_add(&(ins_req->metadata.handle->db_desc->levels[level_id].level_size[tree_id]),
					     ins_req->metadata.kv_size);
		}
	}

	return ret;
}

struct bt_rebalance_result split_leaf(bt_insert_req *req, leaf_node *node)
{
	split_dl *split_functions[2] = { split_dynamic_leaf, special_split_dynamic_leaf };
	int level_id = req->metadata.level_id;

	uint32_t leaf_size = req->metadata.handle->db_desc->levels[level_id].leaf_size;
	// cppcheck-suppress uninitvar
	return split_functions[req->metadata.special_split]((struct bt_dynamic_leaf_node *)node, leaf_size, req);
}

/*
 * performs a binary search at an index(root, internal node) and returns the
 * index. We have a separate search function for index and leaves due to their
 * different format
 */
void *_index_node_binary_search(struct index_node *node, void *key_buf, char query_key_format)
{
	void *addr = NULL;
	int32_t middle = 0;
	int32_t start_idx = 0;
	int32_t end_idx = node->header.num_entries - 1;
	int32_t numberOfEntriesInNode = node->header.num_entries;
	struct key_compare key1_cmp, key2_cmp;

	while (numberOfEntriesInNode > 0) {
		middle = (start_idx + end_idx) / 2;

		if (numberOfEntriesInNode > index_order || middle < 0 || middle >= numberOfEntriesInNode)
			return NULL;

		addr = &(node->p[middle].pivot);
		void *index_key_buf = (void *)REAL_ADDRESS(*(uint64_t *)addr);
		/*key1 is KV_FORMATED key2 is query_key_format*/
		init_key_cmp(&key1_cmp, index_key_buf, KV_FORMAT);
		init_key_cmp(&key2_cmp, key_buf, query_key_format);
		int64_t ret = key_cmp(&key1_cmp, &key2_cmp);
		if (ret == 0) {
			// log_debug("I passed from this corner case1 %s",
			// (char*)(index_key_buf+4));
			addr = &node->p[middle + 1].left;
			break;
		} else if (ret > 0) {
			end_idx = middle - 1;
			if (start_idx > end_idx) {
				// log_debug("I passed from this corner case2 %s",
				// (char*)(index_key_buf+4));
				addr = &node->p[middle].left;
				middle--;
				break;
			}
		} else { /* ret < 0 */
			start_idx = middle + 1;
			if (start_idx > end_idx) {
				// log_debug("I passed from this corner case3 %s",
				// (char*)(index_key_buf+4));
				addr = &node->p[++middle].left;
				break;
			}
		}
	}

	if (middle < 0) {
		// log_debug("I passed from this corner case4 %s",
		// (char*)(index_key_buf+4));
		addr = &(node->p[0].left);
	} else if (middle >= (int64_t)node->header.num_entries) {
		// log_debug("I passed from this corner case5 %s",
		// (char*)(index_key_buf+4));
		/* log_debug("I passed from this corner case2 %s",
* (char*)(index_key_buf+4)); */
		addr = &node->p[node->header.num_entries].left;
	}
	// log_debug("END");
	return addr;
}

/*functions used for debugging*/
// cppcheck-suppress unusedFunction
void assert_index_node(node_header *node)
{
	uint32_t k;
	char *key_tmp;
	char *key_tmp_prev = NULL;
	char *addr;
	node_header *child;
	struct key_compare key1_cmp, key2_cmp;

	addr = (char *)node + sizeof(node_header);
	if (node->num_entries == 0)
		return;
	//	if(node->height > 1)
	//	log_info("Checking node of height %lu\n",node->height);
	for (k = 0; k < node->num_entries; k++) {
		/*check child type*/
		child = (node_header *)REAL_ADDRESS(*(uint64_t *)addr);
		assert(child);
		if (child->type != rootNode && child->type != internalNode && child->type != leafNode &&
		    child->type != leafRootNode) {
			log_fatal("corrupted child at index for child %llu type is %d\n",
				  (long long unsigned)ABSOLUTE_ADDRESS(child), child->type);
			BUG_ON();
		}
		addr += sizeof(uint64_t);
		key_tmp = REAL_ADDRESS(*(uint64_t *)addr);
		// log_info("key %s\n", (char *)key_tmp + sizeof(int32_t));

		if (key_tmp_prev != NULL) {
			/*key1 and key2 are KV_FORMATed*/
			init_key_cmp(&key1_cmp, key_tmp_prev, KV_FORMAT);
			init_key_cmp(&key2_cmp, key_tmp, KV_FORMAT);
			if (key_cmp(&key1_cmp, &key2_cmp) >= 0) {
				log_fatal("corrupted index %d:%s something else %d:%s\n", *(uint32_t *)key_tmp_prev,
					  key_tmp_prev + 4, *(uint32_t *)key_tmp, (char *)(key_tmp + 4));
				BUG_ON();
			}
		}
		if (key_tmp_prev)
			log_fatal("corrupted index %*s something else %*s\n", *(uint32_t *)key_tmp_prev,
				  key_tmp_prev + 4, *(uint32_t *)key_tmp, key_tmp + 4);

		key_tmp_prev = key_tmp;
		addr += sizeof(uint64_t);
	}
	child = (node_header *)REAL_ADDRESS(*(uint64_t *)addr);
	assert(child);
	if (child->type != rootNode && child->type != internalNode && child->type != leafNode &&
	    child->type != leafRootNode) {
		log_fatal("Corrupted last child at index");
		BUG_ON();
	}
}

uint64_t hash(uint64_t x)
{
	x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
	x = x ^ (x >> 31);
	return x;
}

lock_table *_find_position(const lock_table **table, node_header *node)
{
	unsigned long position;
	const lock_table *node_lock;

	assert(node);
	if (node->height < 0 || node->height >= MAX_HEIGHT) {
		log_fatal("MAX_HEIGHT exceeded %d rearrange values in size_per_height array ", node->height);
		BUG_ON();
	}

	position = hash((uint64_t)node) % size_per_height[node->height];
	// log_info("node %llu height %d position %lu size of height %d", node,
	// node->height, position, size_per_height[node->height]);
	node_lock = table[node->height];
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
	int64_t num_entries = header->num_entries;
	uint32_t height = header->height;
	enum kv_category cat = req->metadata.cat;
	uint8_t level_id = req->metadata.level_id;

	if (height != 0) {
		uint8_t split_index_node = num_entries >= index_order;
		return split_index_node;
	}

	int key_type;

	if ((cat == MEDIUM_INLOG && level_id != req->metadata.handle->db_desc->level_medium_inplace) ||
	    cat == BIG_INLOG)
		key_type = KV_INLOG;
	else
		key_type = KV_INPLACE;

	struct split_level_leaf split_metadata = { .leaf = node,
						   .leaf_size = leaf_size,
						   .kv_size = req->metadata.kv_size,
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
	lock_table *lock;

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
	void *next_addr = NULL;

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
		if (father) {
			int32_t father_order = index_order;
			if (father->type == leafNode || father->type == leafRootNode)
				father_order = db_desc->levels[level_id].leaf_offsets.kv_entries;

			assert(father->num_entries < father_order);
		}

		if (is_split_needed(son, ins_req, db_desc->levels[level_id].leaf_size)) {
			/*Overflow split*/
			if (son->height > 0) {
#ifdef NEW_INDEX_NODE_LAYOUT
				split_res = split_new_index_node(son, ins_req);
#else
				split_res = split_index(son, ins_req);
#endif
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

			/*Insert pivot at father*/
			if (father != NULL) {
				insert_key_at_index(ins_req, (struct index_node *)father, split_res.left_child,
						    split_res.right_child, split_res.middle_key);
			} else {
				/*Root was splitted*/
#ifdef NEW_INDEX_NODE_LAYOUT
				struct new_index_node *new_root = seg_get_and_init_new_root_node(
					ins_req->metadata.handle->db_desc, level_id, ins_req->metadata.tree_id);
				new_root->header.height = db_desc->levels[ins_req->metadata.level_id]
								  .root_w[ins_req->metadata.tree_id]
								  ->height +
							  1;
				insert_key_at_index(ins_req, (struct index_node *)new_root, split_res.left_child,
						    split_res.right_child, split_res.middle_key);
				/*new write root of the tree*/
				db_desc->levels[level_id].root_w[ins_req->metadata.tree_id] = (node_header *)new_root;
#else
				struct index_node *new_index_node =
					seg_get_index_node(ins_req->metadata.handle->db_desc, level_id,
							   ins_req->metadata.tree_id, NEW_ROOT);
				new_index_node->header.height = db_desc->levels[ins_req->metadata.level_id]
									.root_w[ins_req->metadata.tree_id]
									->height +
								1;

				new_index_node->header.type = rootNode;
				insert_key_at_index(ins_req, new_index_node, split_res.left_child,
						    split_res.right_child, split_res.middle_key);

				/*new write root of the tree*/
				db_desc->levels[level_id].root_w[ins_req->metadata.tree_id] =
					(node_header *)new_index_node;
#endif
			}
			goto release_and_retry;
		}

		if (son->height == 0)
			break;

#ifdef NEW_INDEX_NODE_LAYOUT
		uint8_t exact_match = 0;
		//TO REMOVE
		struct new_index_node *n_son = (struct new_index_node *)son;
		int32_t child_position = new_index_node_binary_search_get_pos(
			n_son, ins_req->key_value_buf, ins_req->metadata.key_format, &exact_match);
		father = son;
		son = (node_header *)REAL_ADDRESS(n_son->children_offt[child_position]);
		assert(son);
		next_addr = (void *)UINT64_MAX;

		/*Take the lock of the next node before its traversal*/
		lock = _find_position(
			(const lock_table **)ins_req->metadata.handle->db_desc->levels[level_id].level_lock_table, son);

		upper_level_nodes[size++] = lock;
		if (RWLOCK_WRLOCK(&lock->rx_lock) != 0) {
			log_fatal("ERROR unlocking reason follows rc");
			BUG_ON();
		}
		/*Node lock acquired */
		ins_req->metadata.reorganized_leaf_pos_INnode = &n_son->children_offt[child_position];

		/*if the node is not safe hold its ancestor's lock else release locks from
    ancestors */

		if (!is_split_needed(son, ins_req, db_desc->levels[level_id].leaf_size)) {
			_unlock_upper_levels(upper_level_nodes, size - 1, release);
			release = size - 1;
		}
#else
		next_addr = _index_node_binary_search((struct index_node *)son, ins_req->key_value_buf,
						      ins_req->metadata.key_format);

		father = son;
		/*Take the lock of the next node before its traversal*/
		lock = _find_position(
			(const lock_table **)ins_req->metadata.handle->db_desc->levels[level_id].level_lock_table,
			(node_header *)REAL_ADDRESS(*(uint64_t *)next_addr));
		upper_level_nodes[size++] = lock;
		if (RWLOCK_WRLOCK(&lock->rx_lock) != 0) {
			log_fatal("ERROR unlocking reason follows rc");
			BUG_ON();
		}
		/*Node acquired */
		ins_req->metadata.reorganized_leaf_pos_INnode = next_addr;
		son = (node_header *)REAL_ADDRESS(*(uint64_t *)next_addr);
		assert(son);
		/*if the node is not safe hold its ancestor's lock else release locks from
    ancestors */

		if (!is_split_needed(son, ins_req, db_desc->levels[level_id].leaf_size)) {
			_unlock_upper_levels(upper_level_nodes, size - 1, release);
			release = size - 1;
		}
#endif
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
	return PARALLAX_SUCCESS;
}

static uint8_t writers_join_as_readers(bt_insert_req *ins_req)
{
	/*The array with the locks that belong to this thread from upper levels*/
	lock_table *upper_level_nodes[MAX_HEIGHT];
	void *next_addr;
	db_descriptor *db_desc;
	node_header *son;
	lock_table *lock;

	unsigned size; /*Size of upper_level_nodes*/
	unsigned release; /*Counter to know the position that releasing should begin*/
	// remove some warnings here
	uint32_t level_id;
	lock_table *guard_of_level;
	int64_t *num_level_writers;

	db_desc = ins_req->metadata.handle->db_desc;
	level_id = ins_req->metadata.level_id;
	guard_of_level = &db_desc->levels[level_id].guard_of_level;
	num_level_writers = &db_desc->levels[level_id].active_operations;

	size = 0;
	release = 0;

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
		return PARALLAX_FAILURE;
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
	while (1) {
		if (is_split_needed(son, ins_req, db_desc->levels[level_id].leaf_size)) {
			/*failed needs split*/
			_unlock_upper_levels(upper_level_nodes, size, release);
			__sync_fetch_and_sub(num_level_writers, 1);
			return PARALLAX_FAILURE;
		}

#ifdef NEW_INDEX_NODE_LAYOUT
		uint64_t child_offt = new_index_node_binary_search((struct new_index_node *)son, ins_req->key_value_buf,
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
#else
		next_addr = _index_node_binary_search((struct index_node *)son, ins_req->key_value_buf,
						      ins_req->metadata.key_format);
		son = (node_header *)REAL_ADDRESS(*(uint64_t *)next_addr);

		assert(son);

		if (son->height == 0)
			break;
		/*Acquire the lock of the next node before its traversal*/
		lock = _find_position((const lock_table **)db_desc->levels[level_id].level_lock_table,
				      (node_header *)REAL_ADDRESS(*(uint64_t *)next_addr));
		upper_level_nodes[size++] = lock;

		if (RWLOCK_RDLOCK(&lock->rx_lock) != 0) {
			log_fatal("ERROR unlocking");
			BUG_ON();
		}
		/*lock of node acquired */
		_unlock_upper_levels(upper_level_nodes, size - 1, release);
		release = size - 1;
#endif
	}

#ifdef NEW_INDEX_NODE_LAYOUT
	lock = _find_position((const lock_table **)db_desc->levels[level_id].level_lock_table, son);
#else
	lock = _find_position((const lock_table **)db_desc->levels[level_id].level_lock_table,
			      (node_header *)REAL_ADDRESS(*(uint64_t *)next_addr));
#endif
	upper_level_nodes[size++] = lock;

	if (RWLOCK_WRLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR unlocking");
		BUG_ON();
	}

	if (is_split_needed(son, ins_req, db_desc->levels[level_id].leaf_size)) {
		_unlock_upper_levels(upper_level_nodes, size, release);
		__sync_fetch_and_sub(num_level_writers, 1);
		return PARALLAX_FAILURE;
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
	return PARALLAX_SUCCESS;
}

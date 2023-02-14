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
#include "bloom_filter.h"
#include "btree_node.h"
#include "compaction_daemon.h"
#include "conf.h"
#include "dynamic_leaf.h"
#include "gc.h"
#include "index_node.h"
#include "key_splice.h"
#include "lsn.h"
#include "segment_allocator.h"

#include "../allocator/persistent_operations.h"
#include "../parallax_callbacks/parallax_callbacks.h"
#include <assert.h>
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

void assert_index_node(struct node_header *node);

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
	log_debug("Initializing KV logs (small,medium,large) for DB: %s", db_desc->db_superblock->db_name);
	// Large log
	struct segment_header *s = seg_get_raw_log_segment(db_desc, BIG_LOG, 0, 0);
	db_desc->big_log.head_dev_offt = ABSOLUTE_ADDRESS(s);
	db_desc->big_log.tail_dev_offt = db_desc->big_log.head_dev_offt;
	db_desc->big_log.size = 0;
	db_desc->big_log_start_segment_dev_offt = db_desc->big_log.tail_dev_offt;
	db_desc->big_log_start_offt_in_segment = db_desc->big_log.size % SEGMENT_SIZE;
	init_log_buffer(&db_desc->big_log, BIG_LOG);
	log_debug("BIG_LOG head %lu", db_desc->big_log.head_dev_offt);

	s = seg_get_raw_log_segment(db_desc, MEDIUM_LOG, 0, 0);
	db_desc->medium_log.head_dev_offt = ABSOLUTE_ADDRESS(s);
	db_desc->medium_log.tail_dev_offt = db_desc->medium_log.head_dev_offt;
	db_desc->medium_log.size = sizeof(segment_header);
	init_log_buffer(&db_desc->medium_log, MEDIUM_LOG);

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
			db_desc->levels[level_id].root[tree_id] = NULL;
			superblock->root_r[level_id][tree_id] = 0;
		}
	}

	init_fresh_logs(db_desc);
}

static void recover_logs(db_descriptor *db_desc)
{
	log_debug("Recovering KV logs (small,medium,large) for DB: %s", db_desc->db_superblock->db_name);

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
			db_desc->levels[level_id].root[tree_id] = NULL;
			if (superblock->root_r[level_id][tree_id]) {
				db_desc->levels[level_id].root[tree_id] =
					(struct node_header *)REAL_ADDRESS(superblock->root_r[level_id][tree_id]);
				log_debug("Level[%u] tree [%u] root is at %p offt in the device is %lu", level_id,
					  tree_id, (void *)db_desc->levels[level_id].root[tree_id],
					  superblock->root_r[level_id][tree_id]);
			}
		}
	}

	recover_logs(db_desc);
}

static void db_recover_bloom_filters(struct db_handle *database_desc)
{
	for (int i = 1; i < MAX_LEVELS; i++) {
		for (int j = 0; j < NUM_TREES_PER_LEVEL; j++) {
			if (0 == database_desc->db_desc->db_superblock->bloom_filter_valid[i][j]) {
				database_desc->db_desc->levels[i].bloom_desc[j] = NULL;
				continue;
			}
			database_desc->db_desc->levels[i].bloom_desc[j] = pbf_recover_bloom_filter(
				database_desc, i, j, database_desc->db_desc->db_superblock->bloom_filter_hash[i][j]);
		}
	}
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
			log_debug("Found DB: %s recovering its allocation log", db_name);
			db_desc->dirty = 0;
			rul_log_init(db_desc);
			restore_db(db_desc, db_desc->db_superblock->id);
		} else {
			db_desc->dirty = 1;
			log_debug("Initializing new DB: %s, initializing its allocation log", db_name);
			rul_log_init(db_desc);
			db_desc->levels[0].allocation_txn_id[0] = rul_start_txn(db_desc);

			log_debug("Got txn %lu for the initialization of Large and L0_recovery_logs of DB: %s",
				  db_desc->levels[0].allocation_txn_id[0], db_name);

			//init_fresh_db allocates space for the L0_recovery log and large.
			//As a result we need to acquire a txn_id for the L0
			init_fresh_db(db_desc);
		}
	} else {
		log_warn("DB: %s NOT found", db_name);
	}

	return db_desc;
}

void bt_set_db_status(struct db_descriptor *db_desc, enum level_compaction_status comp_status, uint8_t level_id,
		      uint8_t tree_id)
{
	db_desc->levels[level_id].tree_status[tree_id] = comp_status;
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
		*error_message = "DB already open";
		handle = calloc(1UL, sizeof(struct db_handle));
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
	handle = calloc(1UL, sizeof(db_handle));
	handle->db_desc = db_desc;
	handle->volume_desc = db_desc->db_volume;
	//deep copy db_options
	memcpy(&handle->db_options, db_options, sizeof(struct par_db_options));

	uint64_t level0_size = handle->db_options.options[LEVEL0_SIZE].value;
	uint64_t growth_factor = handle->db_options.options[GROWTH_FACTOR].value;
	uint64_t primary_mode = handle->db_options.options[PRIMARY_MODE].value;
	uint64_t replica_mode = handle->db_options.options[REPLICA_MODE].value;
	uint64_t replica_build_index = handle->db_options.options[REPLICA_BUILD_INDEX].value;
	uint64_t replica_send_index = handle->db_options.options[REPLICA_SEND_INDEX].value;
	if (primary_mode == replica_mode) {
		*error_message = "A DB must be set to either primary or replica mode";
		free(handle);
		handle = NULL;
		return NULL;
	}
	if (replica_mode && replica_build_index && replica_send_index) {
		*error_message = "A replica DB must be set to build_index or send_index mode";
		free(handle);
		handle = NULL;
		return NULL;
	}

	/*if the db is a replica, the gc must be scheduled by the primary*/
	if (replica_mode)
		disable_gc();

	handle->db_desc->levels[0].max_level_size = level0_size;
	/*init soft state for all levels*/
	for (uint8_t level_id = 1; level_id < MAX_LEVELS; level_id++) {
		handle->db_desc->levels[level_id].max_level_size =
			handle->db_desc->levels[level_id - 1].max_level_size * growth_factor;

		log_info("DB:Level %d max_total_size %lu", level_id, handle->db_desc->levels[level_id].max_level_size);
	}
	handle->db_desc->levels[MAX_LEVELS - 1].max_level_size = UINT64_MAX;
	handle->db_desc->reference_count = 1;
	handle->db_desc->blocked_clients = 0;
	handle->db_desc->compaction_count = 0;
	handle->db_desc->is_compaction_daemon_sleeping = 0;
	handle->db_desc->segment_ht = NULL;
#if MEASURE_MEDIUM_INPLACE
	db_desc->count_medium_inplace = 0;
#endif

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
			bt_set_db_status(handle->db_desc, BT_NO_COMPACTION, level_id, tree_id);
			handle->db_desc->levels[level_id].epoch[tree_id] = 0;
		}
	}

	_Static_assert(BIG_INLOG < 4, "KV categories number cannot be "
				      "stored in 2 bits, increase "
				      "key_category");

	_Static_assert(sizeof(struct segment_header) == 4096, "Segment header not page aligned!");
	_Static_assert(LOG_TAIL_NUM_BUFS >= 2, "Minimum number of in memory log buffers!");

	MUTEX_INIT(&handle->db_desc->lock_log, NULL);

	klist_add_first(volume_desc->open_databases, handle->db_desc, handle->db_options.db_name, NULL);
	handle->db_desc->db_state = DB_OPEN;

	log_info("Opened DB %s starting its compaction daemon", handle->db_options.db_name);
	handle->db_desc->compactiond = compactiond_create(handle, false);
	compactiond_start(handle->db_desc->compactiond, &handle->db_desc->compactiond_cnxt);

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
	db_recover_bloom_filters(handle);
	pr_recover_L0(handle->db_desc);

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
	if (!handle)
		return "NULL db_handle are you serious?";
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
		error_message = "Sorry more guys use this DB";
		MUTEX_UNLOCK(&init_lock);
		return error_message;
	}
	/*Remove so it is not visible by the GC thread*/
	if (!klist_remove_element(handle->volume_desc->open_databases, handle->db_desc)) {
		log_fatal("Failed to remove db_desc of DB %s", handle->db_desc->db_superblock->db_name);
		BUG_ON();
	}

	log_warn("Closing DB: %s\n", handle->db_desc->db_superblock->db_name);

	/*New requests will eventually see that db is closing*/
	/*wake up possible clients that are stack due to non-availability of L0*/
	handle->db_desc->db_state = DB_IS_CLOSING;
	compactiond_notify_all(handle->db_desc->compactiond);

	/*stop all writers at all levels and wait for all clients to complete their operations.*/

	for (uint8_t level_id = 0; level_id < MAX_LEVELS; level_id++) {
		RWLOCK_WRLOCK(&handle->db_desc->levels[level_id].guard_of_level.rx_lock);
		spin_loop(&(handle->db_desc->levels[level_id].active_operations), 0);
	}

	handle->db_desc->db_state = DB_TERMINATE_COMPACTION_DAEMON;
	compactiond_interrupt(handle->db_desc->compactiond);

	while (handle->db_desc->db_state != DB_IS_CLOSING)
		usleep(50);

	log_info("Ok compaction daemon exited continuing the close sequence of DB:%s",
		 handle->db_desc->db_superblock->db_name);

	/* Release the locks for all levels to allow pending compactions to complete. */
	for (uint8_t level_id = 0; level_id < MAX_LEVELS; level_id++)
		RWLOCK_UNLOCK(&handle->db_desc->levels[level_id].guard_of_level.rx_lock);

	/*Level 0 compactions*/
	for (uint8_t i = 0; i < NUM_TREES_PER_LEVEL; ++i) {
		// if (handle->db_desc->levels[0].tree_status[i] == COMPACTION_IN_PROGRESS) {
		while (BT_NO_COMPACTION != handle->db_desc->levels[0].tree_status[i]) {
			log_debug("Compaction pending for level: %u tree_id: %u", 0, i);
			usleep(50);
		}
	}

	log_debug("All L0 compactions done");

	/*wait for all other pending compactions to finish*/
	for (uint8_t i = 1; i < MAX_LEVELS; i++) {
		// if (COMPACTION_IN_PROGRESS == handle->db_desc->levels[i].tree_status[0]) {
		while (BT_NO_COMPACTION != handle->db_desc->levels[i].tree_status[0]) {
			log_debug("Compaction pending for level: %u tree_id: %u", i, 0);
			usleep(500);
		}
	}

	log_warn("All pending compactions done for DB:%s", handle->db_desc->db_superblock->db_name);
	log_debug("Flushing L0 ....");
	pr_flush_L0(handle->db_desc, handle->db_desc->levels[0].active_tree);
	log_debug("Flushing L0 ....");

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

	compactiond_close(handle->db_desc->compactiond);
	handle->db_desc->compactiond = NULL;

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
 *  @param block if set to true the context of the thread blocks on the semaphore.
 *  If set to false it does not block and returns PAR_FAILURE
 *  @param rwlock If 1 locks the guard of level 0 as a read lock. If 0 locks the guard of level 0 as a write lock.
 *  */
static bool is_level0_available(struct db_descriptor *db_desc, uint8_t level_id, bool abort_on_compaction,
				uint8_t rwlock)
{
	if (level_id > 0)
		return true;

	int active_tree = db_desc->levels[0].active_tree;

	uint8_t relock = 0;
	while (db_desc->levels[0].level_size[active_tree] > db_desc->levels[0].max_level_size) {
		active_tree = db_desc->levels[0].active_tree;
		if (db_desc->levels[0].level_size[active_tree] > db_desc->levels[0].max_level_size) {
			if (!relock) {
				/* Release the lock of level 0 to allow compactions to progress. */
				RWLOCK_UNLOCK(&db_desc->levels[0].guard_of_level.rx_lock);
				relock = 1;
			}

			compactiond_interrupt(db_desc->compactiond);
			if (abort_on_compaction)
				return false;
			compactiond_wait(db_desc->compactiond);
		}
		active_tree = db_desc->levels[0].active_tree;
	}

	/* Reacquire the lock of level 0 to access it safely. */
	if (relock)
		rwlock == 1 ? RWLOCK_RDLOCK(&db_desc->levels[0].guard_of_level.rx_lock) :
				    RWLOCK_WRLOCK(&db_desc->levels[0].guard_of_level.rx_lock);

	return true;
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
		error_message = "DB: is closing";
		return error_message;
	}

	if (key_size > MAX_KEY_SIZE) {
		error_message = "Provided key bigger than the MAX_KEY_SIZE Parallax support";
		return error_message;
	}

	if (!key_size) {
		error_message = "Trying to enter a zero sized key? Not valid!";
		return error_message;
	}

	uint32_t kv_size = key_size + value_size + kv_splice_get_metadata_size();
	if (kv_size > KV_MAX_SIZE) {
		error_message = "KV size > 4KB buffer overflow!";
		return error_message;
	}

	return NULL;
}

struct par_put_metadata insert_key_value(db_handle *handle, void *key, void *value, int32_t key_size,
					 int32_t value_size, request_type op_type, const char **error_message)
{
	*error_message = insert_error_handling(handle, key_size, value_size);
	if (*error_message) {
		// construct an invalid par_put_metadata
		struct par_put_metadata invalid_put_metadata = { .lsn = UINT64_MAX,
								 .offset_in_log = UINT64_MAX,
								 .key_value_category = SMALL_INPLACE };
		return invalid_put_metadata;
	}

	bt_insert_req ins_req = { .metadata.handle = handle,
				  .metadata.tombstone = op_type == deleteOp,
				  .metadata.put_op_metadata.key_value_category = ins_req.metadata.cat,
				  .metadata.cat = calculate_KV_category(key_size, value_size, op_type),
				  .metadata.key_format = KV_FORMAT,
				  .metadata.level_id = 0,
				  .metadata.append_to_log = 1,
				  .metadata.gc_request = 0 };

	char kv_pair_buf[KV_MAX_SIZE];
	struct kv_splice *kv_pair = (struct kv_splice *)kv_pair_buf;
	kv_splice_set_key((struct kv_splice *)kv_pair, key, key_size);

	if (ins_req.metadata.tombstone)
		kv_splice_set_tombstone(kv_pair);
	else {
		kv_splice_set_non_tombstone(kv_pair);
		kv_splice_set_value((struct kv_splice *)kv_pair, value, value_size);
	}

	struct kv_splice_base splice_base = { .kv_type = KV_FORMAT,
					      .kv_cat = ins_req.metadata.cat,
					      .kv_splice = kv_pair };

	ins_req.splice_base = &splice_base;

	// Note for L0 inserts since active_tree changes dynamically we decide which
	// is the active_tree after acquiring the guard lock of the region.

	*error_message = btree_insert_key_value(&ins_req);
	return ins_req.metadata.put_op_metadata;
}

struct par_put_metadata serialized_insert_key_value(db_handle *handle, struct kv_splice_base *splice_base,
						    bool append_to_log, request_type op_type, bool abort_on_compaction,
						    const char **error_message)
{
	bt_insert_req ins_req = { .metadata.handle = handle,
				  .splice_base = splice_base,
				  .metadata.tombstone = op_type == deleteOp,
				  .metadata.level_id = 0,
				  .metadata.key_format = KV_FORMAT,
				  .metadata.append_to_log = append_to_log,
				  .abort_on_compaction = abort_on_compaction };

	int32_t key_size = kv_splice_base_get_key_size(ins_req.splice_base);
	int32_t value_size = kv_splice_base_get_value_size(ins_req.splice_base);

	*error_message = insert_error_handling(handle, key_size, value_size);
	if (*error_message) {
		// construct an invalid par_put_metadata
		struct par_put_metadata invalid_put_metadata = { .lsn = UINT64_MAX,
								 .offset_in_log = UINT64_MAX,
								 .key_value_category = SMALL_INPLACE };
		return invalid_put_metadata;
	}
	ins_req.metadata.cat = calculate_KV_category(key_size, value_size, op_type);
	ins_req.metadata.put_op_metadata.key_value_category = ins_req.metadata.cat;
	ins_req.metadata.put_op_metadata.log_type = L0_RECOVERY;
	ins_req.metadata.put_op_metadata.flush_segment_event = 0;
	ins_req.metadata.put_op_metadata.flush_segment_offt = UINT64_MAX;

	// Even if the user requested not to append to log, if the KV belongs to the big category
	// the system will break if we do not append so we force it here.
	if (BIG_INLOG == ins_req.metadata.cat) {
		ins_req.metadata.append_to_log = 1;
	}

	*error_message = btree_insert_key_value(&ins_req);
	return ins_req.metadata.put_op_metadata;
}

void extract_keyvalue_size(struct log_operation *req, metadata_tologop *data_size)
{
	if (req->ins_req->splice_base->kv_type != KV_FORMAT) {
		log_fatal("Cannot handle this type of format");
		_exit(EXIT_FAILURE);
	}
	data_size->key_len = kv_splice_get_key_size((struct kv_splice *)req->ins_req->splice_base->kv_splice);
	data_size->value_len = kv_splice_get_value_size((struct kv_splice *)req->ins_req->splice_base->kv_splice);
	data_size->kv_size = kv_splice_get_kv_size((struct kv_splice *)req->ins_req->splice_base->kv_splice);
}

struct pr_log_ticket {
	// in var
	struct log_tail *tail;
	struct log_operation *req;
	struct metadata_tologop *data_size;
	struct lsn lsn;
	struct db_descriptor *db_desc;
	uint64_t log_offt;
	uint32_t tail_id;
	enum log_type log_type;
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
	case deleteOp:
		// first the lsn
		memcpy(&ticket->tail->buf[offt], &ticket->lsn, get_lsn_size());
		offt += get_lsn_size();
		if (ticket->req->ins_req->splice_base->kv_type != KV_FORMAT) {
			log_fatal("Appending KV_PREFIX staff in logs is not allowed!");
			_exit(EXIT_FAILURE);
		}
		struct kv_splice *kv_pair_dst = (struct kv_splice *)&ticket->tail->buf[offt];
		struct kv_splice *kv_pair_src = ticket->req->ins_req->splice_base->kv_splice;
		ticket->req->optype_tolog == insertOp ? kv_splice_set_non_tombstone(kv_pair_dst) :
							      kv_splice_set_tombstone(kv_pair_dst);
		kv_splice_set_key(kv_pair_dst, kv_splice_get_key_offset_in_kv(kv_pair_src),
				  kv_splice_get_key_size(kv_pair_src));
		kv_splice_set_value(kv_pair_dst,
				    kv_splice_get_value_offset_in_kv(kv_pair_src, kv_splice_get_key_size(kv_pair_src)),
				    kv_splice_get_value_size(kv_pair_src));
		ticket->op_size = get_lsn_size() + kv_splice_get_kv_size(kv_pair_dst);
		break;

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
	parallax_callbacks_t par_callbacks = ticket->db_desc->parallax_callbacks;
	if (are_parallax_callbacks_set(par_callbacks) && ticket->log_type == MEDIUM_LOG) {
		struct parallax_callback_funcs par_cb = parallax_get_callbacks(par_callbacks);
		void *context = parallax_get_context(par_callbacks);
		par_cb.segment_is_full_cb(context, ticket->tail->dev_offt, ticket->IO_start_offt, size, chunk_id,
					  ticket->tail_id);
	}

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
	par_callbacks = ticket->db_desc->parallax_callbacks;
	if (are_parallax_callbacks_set(par_callbacks) && ticket->log_type == MEDIUM_LOG) {
		struct parallax_callback_funcs par_cb = parallax_get_callbacks(par_callbacks);
		void *context = parallax_get_context(par_callbacks);
		par_cb.spin_for_medium_log_flush(context, ticket->tail_id);
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

uint64_t allocate_segment_for_log(struct db_descriptor *db_desc, struct log_descriptor *log_desc, uint8_t level_id,
				  uint8_t tree_id)
{
	assert(db_desc && log_desc);
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
	return next_tail_seg_offt;
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

	if (available_space_in_log < reserve_needed_space) {
		if (log_metadata->log_desc->log_type == SMALL_LOG || log_metadata->log_desc->log_type == BIG_LOG) {
			req->ins_req->metadata.put_op_metadata.flush_segment_event = 1;
			req->ins_req->metadata.put_op_metadata.flush_segment_offt =
				log_metadata->log_desc->tail_dev_offt;
			enum log_category log_type = L0_RECOVERY;
			if (log_metadata->log_desc->log_type == BIG_LOG)
				log_type = BIG;
			req->ins_req->metadata.put_op_metadata.log_type = log_type;
		}

		uint32_t curr_tail_id = log_metadata->log_desc->curr_tail_id;
		//log_info("Segment change avail space %u kv size %u",available_space_in_log,data_size->kv_size);
		// pad with zeroes remaining bytes in segment
		if (available_space_in_log > 0) {
			struct log_operation pad_op = { .metadata = NULL, .optype_tolog = paddingOp, .ins_req = NULL };
			pad_ticket.req = &pad_op;
			pad_ticket.data_size = NULL;
			pad_ticket.tail = log_metadata->log_desc->tail[curr_tail_id % LOG_TAIL_NUM_BUFS];
			pad_ticket.tail_id = curr_tail_id % LOG_TAIL_NUM_BUFS;
			pad_ticket.log_type = log_metadata->log_desc->log_type;
			pad_ticket.log_offt = log_metadata->log_desc->size;
			pad_ticket.db_desc = handle->db_desc;
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
	log_kv_entry_ticket.tail_id = tail_id % LOG_TAIL_NUM_BUFS;
	log_kv_entry_ticket.log_type = log_metadata->log_desc->log_type;
	log_kv_entry_ticket.db_desc = handle->db_desc;

	if (req->is_medium_log_append)
		log_kv_entry_ticket.lsn = get_max_lsn();
	else
		log_kv_entry_ticket.lsn = increase_lsn(&handle->db_desc->lsn_factory);

	/*Where we *will* store it on the device*/
	struct segment_header *device_location = REAL_ADDRESS(log_metadata->log_desc->tail_dev_offt);
	addr_inlog = (void *)((uint64_t)device_location + (log_metadata->log_desc->size % SEGMENT_SIZE));

	req->metadata->log_offset = log_metadata->log_desc->size;
	req->metadata->put_op_metadata.offset_in_log = req->metadata->log_offset;
	if (req->is_medium_log_append) {
		struct lsn max_lsn = get_max_lsn();
		req->metadata->put_op_metadata.lsn = get_lsn_id(&max_lsn);
	} else
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

void *append_key_value_to_log(struct log_operation *req)
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
		return "Could not append even after using the coarse grained protocol!";

	return NULL;
}

static inline void lookup_in_tree(struct lookup_operation *get_op, int level_id, int tree_id)
{
	struct node_header *son_node = NULL;

	struct db_descriptor *db_desc = get_op->db_desc;
	struct key_splice *search_key_buf = get_op->key_splice;

	struct node_header *root = db_desc->levels[level_id].root[tree_id];
	if (!root) {
		get_op->found = 0;
		return;
	}

	if (!pbf_check(db_desc->levels[level_id].bloom_desc[0], key_splice_get_key_offset(get_op->key_splice),
		       key_splice_get_key_size(get_op->key_splice)))
		return;

	lock_table *prev = NULL;
	lock_table *curr = NULL;
	struct node_header *curr_node = root;

	while (curr_node) {
		if (curr_node->type == leafNode || curr_node->type == leafRootNode)
			break;

		curr = find_lock_position((const lock_table **)db_desc->levels[level_id].level_lock_table, curr_node);
		if (RWLOCK_RDLOCK(&curr->rx_lock) != 0)
			BUG_ON();

		if (prev && RWLOCK_UNLOCK(&prev->rx_lock) != 0)
			BUG_ON();

		uint64_t child_offset = index_binary_search((struct index_node *)curr_node,
							    key_splice_get_key_offset(search_key_buf),
							    key_splice_get_key_size(search_key_buf));

		son_node = (void *)REAL_ADDRESS(child_offset);

		prev = curr;
		curr_node = son_node;
	}

	// prev = curr;
	curr = find_lock_position((const lock_table **)db_desc->levels[level_id].level_lock_table, curr_node);
	if (RWLOCK_RDLOCK(&curr->rx_lock) != 0) {
		BUG_ON();
	}

	if (prev && RWLOCK_UNLOCK(&prev->rx_lock) != 0)
		BUG_ON();

	int32_t key_size = key_splice_get_key_size(search_key_buf);
	void *key = key_splice_get_key_offset(search_key_buf);
	const char *error = NULL;
	struct kv_splice_base splice = dl_find_kv_in_dynamic_leaf((struct leaf_node *)curr_node, key, key_size, &error);
	if (error != NULL) {
		// log_debug("Key %.*s not found with error message %s", key_size, (char *)key, error);
		get_op->found = 0;
		goto release_leaf_lock;
	}

	get_op->found = 1;
	get_op->key_device_address = NULL;
	get_op->tombstone = splice.is_tombstone;
	struct bt_kv_log_address kv_pair = { .addr = NULL, .tail_id = UINT8_MAX, .in_tail = 0 };

	kv_pair.addr = (char *)splice.kv_splice;
	if (splice.kv_cat == MEDIUM_INLOG || splice.kv_cat == BIG_INLOG) {
		uint64_t value_offt = kv_sep2_get_value_offt(splice.kv_sep2);
		if (level_id > 0)
			kv_pair.addr = REAL_ADDRESS(value_offt);
		else
			kv_pair = bt_get_kv_log_address(&db_desc->big_log, value_offt);
	}

	int32_t value_size = kv_splice_get_value_size((struct kv_splice *)kv_pair.addr);

	get_op->buffer_overflow = 0;
	if (get_op->tombstone) {
		get_op->key_device_address = NULL;
		goto check_if_done_with_value_log;
	}

	if (!get_op->retrieve)
		goto check_if_done_with_value_log;

	if (get_op->buffer_to_pack_kv && value_size > get_op->size) {
		get_op->buffer_overflow = 1;
		goto check_if_done_with_value_log;
	}

	if (!get_op->buffer_to_pack_kv)
		get_op->buffer_to_pack_kv = calloc(1UL, value_size);

	memcpy(get_op->buffer_to_pack_kv,
	       kv_splice_get_value_offset_in_kv((struct kv_splice *)kv_pair.addr,
						kv_splice_get_key_size((struct kv_splice *)kv_pair.addr)),
	       value_size);
	get_op->size = value_size;

check_if_done_with_value_log:
	if (kv_pair.in_tail)
		bt_done_with_value_log_address(&db_desc->big_log, &kv_pair);

release_leaf_lock:
	if (curr && RWLOCK_UNLOCK(&curr->rx_lock) != 0)
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

int insert_KV_at_leaf(bt_insert_req *ins_req, struct node_header *leaf)
{
	uint8_t level_id = ins_req->metadata.level_id;
	uint8_t tree_id = ins_req->metadata.tree_id;

	char *log_address = NULL;
	if (ins_req->metadata.append_to_log) {
		struct log_operation append_op = { .metadata = &ins_req->metadata,
						   .optype_tolog = insertOp,
						   .ins_req = ins_req,
						   .is_medium_log_append = false };
		if (ins_req->metadata.tombstone)
			append_op.optype_tolog = deleteOp;
		log_address = append_key_value_to_log(&append_op);
	}

	//cppcheck-suppress variableScope
	char kv_sep2_buf[KV_SEP2_MAX_SIZE];

	if (ins_req->splice_base->kv_cat == BIG_INLOG && ins_req->splice_base->kv_type == KV_FORMAT &&
	    ins_req->metadata.append_to_log) {
		uint64_t value_offt = ABSOLUTE_ADDRESS(log_address);
		ins_req->splice_base->kv_sep2 =
			kv_sep2_create(kv_splice_get_key_size(ins_req->splice_base->kv_splice),
				       kv_splice_get_key_offset_in_kv(ins_req->splice_base->kv_splice), value_offt,
				       kv_sep2_buf, KV_SEP2_MAX_SIZE);

		ins_req->splice_base->kv_type = KV_PREFIX;
	}
	assert(kv_splice_base_get_key_size(ins_req->splice_base) > 0);

	bool exact_match = false;
	if (!dl_insert_in_dynamic_leaf((struct leaf_node *)leaf, ins_req->splice_base, ins_req->metadata.tombstone,
				       &exact_match)) {
		log_fatal("Inserting at leaf failed probably due to overflow");
		assert(0);
		BUG_ON();
	}

	if (exact_match)
		return -1;
	int32_t kv_size = kv_splice_base_get_size(ins_req->splice_base);
	__sync_fetch_and_add(&(ins_req->metadata.handle->db_desc->levels[level_id].level_size[tree_id]), kv_size);
	return INSERT;
}

static uint64_t get_lock_position(uint64_t address)
{
	address = (address ^ (address >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	address = (address ^ (address >> 27)) * UINT64_C(0x94d049bb133111eb);
	address = address ^ (address >> 31);
	return address;
}

lock_table *find_lock_position(const lock_table **table, struct node_header *node)
{
	if (unlikely(!node)) {
		log_fatal("Provided NULL node to acquire lock!");
		BUG_ON();
	}
	if (unlikely(node->height < 0 || node->height >= MAX_HEIGHT)) {
		log_fatal("MAX_HEIGHT exceeded %d rearrange values in size_per_height array ", node->height);
		assert(0);
		BUG_ON();
	}

	unsigned long position = get_lock_position((uint64_t)node) % size_per_height[node->height];
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

static bool bt_reorganize_leaf(struct leaf_node *leaf, bt_insert_req *ins_req)
{
	if (!dl_is_reorganize_possible(leaf, kv_splice_base_calculate_size(ins_req->splice_base)))
		return false;
	struct leaf_node *target =
		calloc(1UL, ins_req->metadata.handle->db_desc->levels[ins_req->metadata.level_id].leaf_size);
	dl_init_leaf_node(target, ins_req->metadata.handle->db_desc->levels[ins_req->metadata.level_id].leaf_size);
	dl_set_leaf_node_type(target, dl_get_leaf_node_type(leaf));
	dl_reorganize_dynamic_leaf(leaf, target);
	memcpy(leaf, target, ins_req->metadata.handle->db_desc->levels[ins_req->metadata.level_id].leaf_size);
	free(target);
	return true;
}

static void bt_split_leaf(struct leaf_node *leaf, bt_insert_req *req, struct bt_rebalance_result *split_result)
{
	split_result->left_leaf_child =
		seg_get_dynamic_leaf_node(req->metadata.handle->db_desc, req->metadata.level_id, req->metadata.tree_id);
	split_result->right_leaf_child =
		seg_get_dynamic_leaf_node(req->metadata.handle->db_desc, req->metadata.level_id, req->metadata.tree_id);

	dl_init_leaf_node(split_result->left_leaf_child,
			  req->metadata.handle->db_desc->levels[req->metadata.level_id].leaf_size);
	dl_init_leaf_node(split_result->right_leaf_child,
			  req->metadata.handle->db_desc->levels[req->metadata.level_id].leaf_size);
	struct kv_splice_base splice =
		dl_split_dynamic_leaf(leaf, split_result->left_leaf_child, split_result->right_leaf_child);

	bool malloced = false;
	struct key_splice *pivot_splice = key_splice_create(kv_splice_base_get_key_buf(&splice),
							    kv_splice_base_get_key_size(&splice),
							    split_result->middle_key, MAX_PIVOT_SIZE, &malloced);

	if (NULL == pivot_splice) {
		log_fatal("Probably corrupted kv category");
		BUG_ON();
	}
	if (malloced) {
		log_fatal("pivot key larger than MAX_PIVOT_SIZE, seems like corruption");
		BUG_ON();
	}
}

int is_split_needed(void *node, bt_insert_req *ins_req)
{
	assert(node);
	struct node_header *header = (struct node_header *)node;
	uint32_t height = header->height;

	if (height != 0)
		return index_is_split_needed((struct index_node *)node, MAX_KEY_SPLICE_SIZE);

	uint32_t kv_size = kv_splice_base_calculate_size(ins_req->splice_base);
	return dl_is_leaf_full(node, kv_size);
}

static uint8_t concurrent_insert(bt_insert_req *ins_req)
{
	/*The array with the locks that belong to this thread from upper levels*/
	lock_table *upper_level_nodes[MAX_HEIGHT];

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

	bool avail = is_level0_available(ins_req->metadata.handle->db_desc, level_id, ins_req->abort_on_compaction, 0);
	if (ins_req->abort_on_compaction && !avail)
		return PAR_FAILURE;
	if (!avail)
		log_fatal("Failue cannot write to Level-0");

	/*now look which is the active_tree of L0*/
	if (ins_req->metadata.level_id == 0)
		ins_req->metadata.tree_id = ins_req->metadata.handle->db_desc->levels[0].active_tree;

	/*level's guard lock aquired*/
	upper_level_nodes[size++] = guard_of_level;
	/*mark your presence*/
	__sync_fetch_and_add(num_level_writers, 1);

	struct node_header *son = NULL;
	struct node_header *father = NULL;

	if (db_desc->levels[level_id].root[ins_req->metadata.tree_id] == NULL) {
		/*we are allocating a new tree*/

		log_debug("Allocating new active tree %d for level id %d", ins_req->metadata.tree_id, level_id);

		struct leaf_node *new_leaf =
			seg_get_leaf_node(ins_req->metadata.handle->db_desc, level_id, ins_req->metadata.tree_id);
		dl_init_leaf_node(new_leaf, ins_req->metadata.handle->db_desc->levels[level_id].leaf_size);
		dl_set_leaf_node_type(new_leaf, leafRootNode);
		db_desc->levels[level_id].root[ins_req->metadata.tree_id] = (struct node_header *)new_leaf;
	}
	/*acquiring lock of the current root*/
	lock = find_lock_position((const lock_table **)db_desc->levels[level_id].level_lock_table,
				  db_desc->levels[level_id].root[ins_req->metadata.tree_id]);
	if (RWLOCK_WRLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR locking");
		BUG_ON();
	}
	upper_level_nodes[size++] = lock;
	son = db_desc->levels[level_id].root[ins_req->metadata.tree_id];

	while (1) {
		/*Check if father is safe it should be*/
		if (is_split_needed(son, ins_req)) {
			struct bt_rebalance_result split_res = { 0 };
			/*Overflow split for index nodes*/
			if (son->height > 0) {
				split_res.left_child = (struct node_header *)seg_get_index_node(
					ins_req->metadata.handle->db_desc, ins_req->metadata.level_id,
					ins_req->metadata.tree_id, 0);

				split_res.right_child = (struct node_header *)seg_get_index_node(
					ins_req->metadata.handle->db_desc, ins_req->metadata.level_id,
					ins_req->metadata.tree_id, 0);

				struct index_node_split_request index_split_req = {
					.node = (struct index_node *)son,
					.left_child = (struct index_node *)split_res.left_child,
					.right_child = (struct index_node *)split_res.right_child
				};
				struct index_node_split_reply index_split_rep = { .pivot_buf = split_res.middle_key,
										  .pivot_buf_size = MAX_PIVOT_SIZE };
				index_split_node(&index_split_req, &index_split_rep);
				/*node has splitted, free it*/
				seg_free_index_node(ins_req->metadata.handle->db_desc, level_id,
						    ins_req->metadata.tree_id, (struct index_node *)son);
				// free_logical_node(&(req->allocator_desc), son);
			} else if (0 == son->height) {
				if (bt_reorganize_leaf((struct leaf_node *)son, ins_req))
					goto release_and_retry;

				bt_split_leaf((struct leaf_node *)son, ins_req, &split_res);
			} else {
				log_fatal("Negative height? come on");
				BUG_ON();
			}

			if (NULL == father) {
				/*Root was splitted*/
				struct index_node *new_root = seg_get_index_node(
					ins_req->metadata.handle->db_desc, level_id, ins_req->metadata.tree_id, -1);

				index_init_node(ADD_GUARD, new_root, rootNode);

				struct node_header *new_root_header = index_node_get_header(new_root);
				new_root_header->height = db_desc->levels[ins_req->metadata.level_id]
								  .root[ins_req->metadata.tree_id]
								  ->height +
							  1;

				struct pivot_pointer left = { .child_offt = ABSOLUTE_ADDRESS(split_res.left_child) };
				struct pivot_pointer right = { .child_offt = ABSOLUTE_ADDRESS(split_res.right_child) };
				struct insert_pivot_req ins_pivot_req = {
					.node = new_root,
					.left_child = &left,
					.key_splice = (struct key_splice *)split_res.middle_key,
					.right_child = &right
				};
				if (!index_insert_pivot(&ins_pivot_req)) {
					log_fatal("Cannot insert pivot!");
					_exit(EXIT_FAILURE);
				}
				/*new write root of the tree*/
				db_desc->levels[level_id].root[ins_req->metadata.tree_id] =
					(struct node_header *)new_root;
				goto release_and_retry;
			}
			/*Insert pivot at father*/
			struct pivot_pointer left = { .child_offt = ABSOLUTE_ADDRESS(split_res.left_child) };
			struct pivot_pointer right = { .child_offt = ABSOLUTE_ADDRESS(split_res.right_child) };
			struct insert_pivot_req ins_pivot_req = { .node = (struct index_node *)father,
								  .left_child = &left,
								  .key_splice =
									  (struct key_splice *)split_res.middle_key,
								  .right_child = &right };
			if (!index_insert_pivot(&ins_pivot_req)) {
				log_fatal("Cannot insert pivot! pivot is %u",
					  key_splice_get_key_size(ins_pivot_req.key_splice));
				_exit(EXIT_FAILURE);
			}
			goto release_and_retry;
		}

		if (son->height == 0) {
			assert(son->type == leafNode || son->type == leafRootNode);
			break;
		}

		struct index_node *n_son = (struct index_node *)son;

		struct kv_splice_base *splice_base = ins_req->splice_base;
		struct pivot_pointer *son_pivot = index_search_get_pivot(n_son, kv_splice_base_get_key_buf(splice_base),
									 kv_splice_base_get_key_size(splice_base));

		father = son;
		son = REAL_ADDRESS(son_pivot->child_offt);
		assert(son);

		/*Take the lock of the next node before its traversal*/
		lock = find_lock_position(
			(const lock_table **)ins_req->metadata.handle->db_desc->levels[level_id].level_lock_table, son);

		if (RWLOCK_WRLOCK(&lock->rx_lock) != 0) {
			log_fatal("ERROR unlocking reason follows rc");
			BUG_ON();
		}
		upper_level_nodes[size++] = lock;

		// /*Node lock acquired */

		/*if the node is not safe hold its ancestor's lock else release locks from
    ancestors */

		if (!is_split_needed(son, ins_req)) {
			_unlock_upper_levels(upper_level_nodes, size - 1, release);
			release = size - 1;
		}
	}
	/*Succesfully reached a bin (bottom internal node)*/
	if (son->type != leafRootNode) {
		assert((size - 1) - release == 0);
	}

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
	struct node_header *son = NULL;
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

	bool avail = is_level0_available(ins_req->metadata.handle->db_desc, level_id, ins_req->abort_on_compaction, 1);
	if (ins_req->abort_on_compaction && !avail)
		return PAR_FAILURE;
	if (!avail)
		log_fatal("Failue cannot write to Level-0");
	/*now look which is the active_tree of L0*/
	if (ins_req->metadata.level_id == 0)
		ins_req->metadata.tree_id = ins_req->metadata.handle->db_desc->levels[0].active_tree;

	/*mark your presence*/
	__sync_fetch_and_add(num_level_writers, 1);
	upper_level_nodes[size++] = guard_of_level;

	if (db_desc->levels[level_id].root[ins_req->metadata.tree_id] == NULL ||
	    db_desc->levels[level_id].root[ins_req->metadata.tree_id]->type == leafRootNode) {
		_unlock_upper_levels(upper_level_nodes, size, release);
		__sync_fetch_and_sub(num_level_writers, 1);
		return PAR_FAILURE;
	}

	/*acquire read lock of the current root*/
	lock = find_lock_position((const lock_table **)db_desc->levels[level_id].level_lock_table,
				  db_desc->levels[level_id].root[ins_req->metadata.tree_id]);

	if (RWLOCK_RDLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR locking");
		BUG_ON();
	}

	upper_level_nodes[size++] = lock;
	son = db_desc->levels[level_id].root[ins_req->metadata.tree_id];
	assert(son->height > 0);
	while (1) {
		if (is_split_needed(son, ins_req)) {
			/*failed needs split*/
			_unlock_upper_levels(upper_level_nodes, size, release);
			__sync_fetch_and_sub(num_level_writers, 1);
			return PAR_FAILURE;
		}

		struct kv_splice_base *splice_base = ins_req->splice_base;
		uint64_t child_offt = index_binary_search((struct index_node *)son,
							  kv_splice_base_get_key_buf(splice_base),
							  kv_splice_base_get_key_size(splice_base));
		son = (struct node_header *)REAL_ADDRESS(child_offt);
		assert(son);

		if (son->height == 0)
			break;
		/*Acquire the lock of the next node before its traversal*/
		lock = find_lock_position((const lock_table **)db_desc->levels[level_id].level_lock_table, son);
		upper_level_nodes[size++] = lock;

		if (RWLOCK_RDLOCK(&lock->rx_lock) != 0) {
			log_fatal("ERROR unlocking");
			BUG_ON();
		}
		/*lock of node acquired */
		_unlock_upper_levels(upper_level_nodes, size - 1, release);
		release = size - 1;
	}

	lock = find_lock_position((const lock_table **)db_desc->levels[level_id].level_lock_table, son);
	upper_level_nodes[size++] = lock;

	if (RWLOCK_WRLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR unlocking");
		BUG_ON();
	}

	assert(son->height == 0);
	if (is_split_needed(son, ins_req)) {
		_unlock_upper_levels(upper_level_nodes, size, release);
		__sync_fetch_and_sub(num_level_writers, 1);
		return PAR_FAILURE;
	}

	insert_KV_at_leaf(ins_req, son);
	/*Unlock remaining locks*/
	_unlock_upper_levels(upper_level_nodes, size, release);
	__sync_fetch_and_sub(num_level_writers, 1);
	return PAR_SUCCESS;
}

struct log_descriptor *db_desc_get_log_desc(struct db_descriptor *db_desc, enum log_type type)
{
	assert(db_desc);
	if (type == SMALL_LOG)
		return &db_desc->small_log;
	if (type == MEDIUM_LOG)
		return &db_desc->medium_log;
	if (type == BIG_LOG)
		return &db_desc->big_log;

	log_fatal("Corrupted log type");
	_exit(EXIT_FAILURE);
}

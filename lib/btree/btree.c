/** @file btree.c
 *  @brief kreon system implementation
 *
 *  @TODO Extended Summary
 *	@author Giorgos Saloustros (gesalous@ics.forth.gr)
 *	@author Anastasios Papagiannis (apapag@ics.forth.gr)
 *	@author Pilar Gonzalez-ferez (pilar@ics.forth.gr)
 *	@author Giorgos Xanthakis (gxanth@ics.forth.gr)
 *	@author Angelos Bilas (bilas@ics.forth.gr)
 **/
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <assert.h>
#include <sys/types.h>
#include <log.h>
#include <list.h>
#include <spin_loop.h>
#include <uthash.h>
#include "btree.h"
#include "gc.h"
#include "segment_allocator.h"
#include "dynamic_leaf.h"
#include "set_options.h"
#include "conf.h"
#include "../allocator/allocator.h"

#define PREFIX_STATISTICS_NO
#define MIN(x, y) ((x > y) ? (y) : (x))

#define DEVICE_BLOCK_SIZE 4096
#define COULD_NOT_FIND_DB 0x02

int32_t index_order = -1;
extern char *pointer_to_kv_in_log;

uint64_t countgoto = 0;
pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_spinlock_t log_buffer_lock;
sem_t gc_daemon_interrupts;

/*number of locks per level*/
uint32_t size_per_height[MAX_HEIGHT] = { 8192, 4096, 2048, 1024, 512, 256, 128, 64, 32 };

static uint8_t writers_join_as_readers(bt_insert_req *ins_req);
static uint8_t concurrent_insert(bt_insert_req *ins_req);

void assert_index_node(node_header *node);

#ifdef PREFIX_STATISTICS
static inline void update_leaf_index_stats(char key_format)
{
	if (key_format == KV_FORMAT)
		__sync_fetch_and_add(&ins_prefix_miss_l0, 1);
	else
		__sync_fetch_and_add(&ins_prefix_miss_l1, 1);
}
#endif

static struct bt_rebalance_result split_index(node_header *node, bt_insert_req *ins_req);

struct bt_rebalance_result split_leaf(bt_insert_req *req, leaf_node *node);

/*functions used for debugging*/

int prefix_compare(char *l, char *r, size_t prefix_size)
{
	return memcmp(l, r, prefix_size);
}

/**
 * @param   index_key: address of the index_key
 * @param   index_key_len: length of the index_key in encoded form first 2
 * significant bytes row_key_size least 2 significant bytes quallifier size
 * @param   query_key: address of query_key
 * @param   query_key_len: query_key length again in encoded form
 */

int64_t key_cmp(void *key1, void *key2, char key1_format, char key2_format)
{
	int64_t ret;
	uint32_t size;
	/*we need the left most entry*/
	if (key2 == NULL)
		return 1;

	struct kv_format *key1f = NULL;
	struct kv_format *key2f = NULL;
	struct bt_leaf_entry *key1p = NULL;
	struct bt_leaf_entry *key2p = NULL;

	if (key1_format == KV_FORMAT && key2_format == KV_FORMAT) {
		key1f = (struct kv_format *)key1;
		key1p = NULL;
		key2f = (struct kv_format *)key2;
		key2p = NULL;

		size = key1f->key_size;
		if (size > key2f->key_size)
			size = key2f->key_size;

		ret = memcmp(key1f->key_buf, key2f->key_buf, size);
		if (ret != 0)
			return ret;
		else {
			/*finally larger key wins*/
			if (key1f->key_size < key2f->key_size)
				return -1;
			else if (key1f->key_size > key2f->key_size)
				return 1;
			else
				/*equal*/
				return 0;
		}
	} else if (key1_format == KV_FORMAT && key2_format == KV_PREFIX) {
		key1f = (struct kv_format *)key1;
		key1p = NULL;
		key2f = NULL;
		key2p = (struct bt_leaf_entry *)key2;

		if (key1f->key_size >= PREFIX_SIZE)
			ret = prefix_compare(key1f->key_buf, key2p->prefix, PREFIX_SIZE);
		else
			ret = prefix_compare(key1f->key_buf, key2p->prefix, key1f->key_size);
		if (ret == 0) {
			/*we have a tie, prefix didn't help, fetch query_key form KV log*/
			key2f = (struct kv_format *)key2p->pointer;
			key2p = NULL;

			size = key1f->key_size;
			if (size > key2f->key_size)
				size = key2f->key_size;

			ret = memcmp(key1f->key_buf, key2f->key_buf, size);

			if (ret != 0)
				return ret;
			else {
				/*finally larger key wins*/
				if (key1f->key_size < key2f->key_size)
					return -1;
				else if (key1f->key_size > key2f->key_size)
					return 1;
				else
					/*equal*/
					return 0;
			}
		} else
			return ret;
	} else if (key1_format == KV_PREFIX && key2_format == KV_FORMAT) {
		key1f = NULL;
		key1p = (struct bt_leaf_entry *)key1;
		key2f = (struct kv_format *)key2;
		key2p = NULL;

		if (key2f->key_size >= PREFIX_SIZE)
			ret = prefix_compare(key1p->prefix, key2f->key_buf, PREFIX_SIZE);
		else // check here TODO
			ret = prefix_compare(key1p->prefix, key2f->key_buf, key2f->key_size);

		if (ret == 0) {
			/* we have a tie, prefix didn't help, fetch query_key form KV log*/
			key1f = (struct kv_format *)key1p->pointer;
			key1p = NULL;

			size = key2f->key_size;
			if (size > key1f->key_size)
				size = key1f->key_size;

			ret = memcmp(key1f->key_buf, key2f->key_buf, size);
			if (ret != 0)
				return ret;
			else {
				/*finally larger key wins*/
				if (key1f->key_size < key2f->key_size)
					return -1;
				else if (key1f->key_size > key2f->key_size)
					return 1;
				else
					/*equal*/
					return 0;
			}
		} else
			return ret;
	} else {
		/*KV_PREFIX and KV_PREFIX*/
		key1f = NULL;
		key1p = (struct bt_leaf_entry *)key1;
		key2f = NULL;
		key2p = (struct bt_leaf_entry *)key2;
		ret = prefix_compare(key1p->prefix, key2p->prefix, PREFIX_SIZE);
		if (ret != 0)
			return ret;
		/*full comparison*/
		key1f = (struct kv_format *)key1p->pointer;
		// key1p = NULL;
		key2f = (struct kv_format *)key2p->pointer;
		// key2p = NULL;

		size = key2f->key_size;
		if (size > key1f->key_size) {
			size = key1f->key_size;
		}

		ret = memcmp(key1f->key_buf, key2f->key_buf, size);
		if (ret != 0)
			return ret;
		/*finally larger key wins*/
		if (key1f->key_size < key2f->key_size)
			return -1;
		else if (key1f->key_size > key2f->key_size)
			return 1;
		else
			/*equal*/
			return 0;
	}
	return 0;
}

static void init_level_locktable(db_descriptor *database, uint8_t level_id)
{
	unsigned int i, j;
	lock_table *init;

	for (i = 0; i < MAX_HEIGHT; ++i) {
		if (posix_memalign((void **)&database->levels[level_id].level_lock_table[i], 4096,
				   sizeof(lock_table) * size_per_height[i]) != 0) {
			log_fatal("memalign failed");
			exit(EXIT_FAILURE);
		}

		init = database->levels[level_id].level_lock_table[i];

		for (j = 0; j < size_per_height[i]; ++j) {
			if (RWLOCK_INIT(&init[j].rx_lock, NULL) != 0) {
				log_fatal("failed to initialize lock_table for level %u lock", level_id);
				exit(EXIT_FAILURE);
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
	for (int i = 0; i < MAX_HEIGHT; ++i)
		free(&database->levels[level_id].level_lock_table[i]);
}

static void pr_read_log_tail(struct log_tail *tail)
{
	ssize_t bytes = 0;
	ssize_t bytes_read = 0;
	while (bytes_read < SEGMENT_SIZE) {
		bytes = pread(tail->fd, &tail->buf[bytes_read], SEGMENT_SIZE - bytes_read, tail->dev_offt + bytes_read);
		if (bytes == -1) {
			log_fatal("Failed to read error code");
			perror("Error");
			assert(0);
			exit(EXIT_FAILURE);
		}
		bytes_read += bytes;
	}
}

struct bt_kv_log_address bt_get_kv_log_address(struct bt_log_descriptor *log_desc, uint64_t dev_offt)
{
	struct bt_kv_log_address reply = { .addr = NULL, .tail_id = 0, .in_tail = UINT8_MAX };
	RWLOCK_RDLOCK(&log_desc->log_tail_buf_lock);

	for (int i = 0; i < LOG_TAIL_NUM_BUFS; ++i) {
		if (log_desc->tail[i]->free)
			continue;

		if (dev_offt >= log_desc->tail[i]->start && dev_offt <= log_desc->tail[i]->end) {
			__sync_fetch_and_add(&log_desc->tail[i]->pending_readers, 1);
			reply.in_tail = 1;
			// log_info("KV at tail! offt %llu in the device or %llu", dev_offt,
			// dev_offt % SEGMENT_SIZE);
			reply.addr = &log_desc->tail[i]->buf[dev_offt % SEGMENT_SIZE];
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

void bt_done_with_value_log_address(struct bt_log_descriptor *log_desc, struct bt_kv_log_address *L)
{
	assert(log_desc->tail[L->tail_id]->pending_readers > 0);
	__sync_fetch_and_sub(&log_desc->tail[L->tail_id]->pending_readers, 1);
}

struct bt_kv_log_address bt_get_kv_medium_log_address(struct bt_log_descriptor *log_desc, uint64_t dev_offt)
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

static void pr_init_log(struct bt_log_descriptor *log_desc)
{
	// Just update the chunk counters according to the log size
	if (RWLOCK_INIT(&log_desc->log_tail_buf_lock, NULL) != 0) {
		log_fatal("Failed to init lock");
		exit(EXIT_FAILURE);
	}

	for (int i = 0; i < LOG_TAIL_NUM_BUFS; ++i) {
		if (posix_memalign((void **)&log_desc->tail[i], ALIGNMENT_SIZE, sizeof(struct log_tail)) != 0) {
			log_fatal("Failed to allocate log buffer for direct IO");
			exit(EXIT_FAILURE);
		}
		memset(log_desc->tail[i], 0x00, sizeof(struct log_tail));
		log_desc->tail[i]->free = 1;
		log_desc->tail[i]->fd = FD;
	}
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
	}
	if (offt_in_seg > 0 && offt_in_seg % LOG_CHUNK_SIZE != 0)
		log_desc->tail[0]->bytes_in_chunk[i] = offt_in_seg % LOG_CHUNK_SIZE;
}

#if 0
static void pr_init_medium_log_L0(struct db_handle *handle, int tree_id) {
  // The in memory part
  struct segment_header *inmem_header = NULL;
  if (posix_memalign((void **)&inmem_header, SEGMENT_SIZE, SEGMENT_SIZE) != 0) {
    log_fatal("Failed to allocate memory for L0 inmem log");
    exit(EXIT_FAILURE);
  }
  for (int i = 0; i < NUM_TREES_PER_LEVEL; ++i) {
    inmem_header->bytes_per_chunk[tree_id] = tree_id;
    inmem_header->segment_id = 0;
  }
  handle->db_desc->inmem_medium_log_L0[tree_id].head_dev_offt =
      ABSOLUTE_ADDRESS(inmem_header);
  handle->db_desc->inmem_medium_log_L0[tree_id].tail_dev_offt =
      ABSOLUTE_ADDRESS(inmem_header);
  handle->db_desc->inmem_medium_log_L0[tree_id].size =
      sizeof(struct segment_header);
  // The same for the dev part
  struct segment_header *dev_header =
      seg_get_raw_log_segment(handle->volume_desc);
  dev_header->segment_id = 0;
  for (int i = 0; i < NUM_TREES_PER_LEVEL; ++i) {
    dev_header->bytes_per_chunk[tree_id] = tree_id;
    dev_header->segment_id = 0;
  }
  handle->db_desc->dev_medium_log_L0[tree_id].head_dev_offt =
      ABSOLUTE_ADDRESS(inmem_header);
  handle->db_desc->dev_medium_log_L0[tree_id].tail_dev_offt =
      ABSOLUTE_ADDRESS(inmem_header);
  handle->db_desc->dev_medium_log_L0[tree_id].size =
      sizeof(struct segment_header);
}
#endif

static void pr_recover_logs(db_descriptor *db_desc, struct pr_db_entry *entry)
{
	log_info("Recovering KV logs (small,medium,large) for DB: %s", db_desc->db_name);

	// Small log
	db_desc->small_log.head_dev_offt = entry->small_log_head_offt;
	db_desc->small_log.tail_dev_offt = entry->small_log_tail_offt;
	db_desc->small_log.size = entry->small_log_size;
	pr_init_log(&db_desc->small_log);

	// Medium log
	db_desc->medium_log.head_dev_offt = entry->medium_log_head_offt;
	db_desc->medium_log.tail_dev_offt = entry->medium_log_tail_offt;
	db_desc->medium_log.size = entry->medium_log_size;
	pr_init_log(&db_desc->medium_log);

	// Big log
	db_desc->big_log.head_dev_offt = entry->big_log_head_offt;
	db_desc->big_log.tail_dev_offt = entry->big_log_tail_offt;
	db_desc->big_log.size = entry->big_log_size;
	pr_init_log(&db_desc->big_log);
	db_desc->lsn = entry->lsn;
}

static void pr_init_logs(db_descriptor *db_desc, volume_descriptor *volume_desc)
{
	log_info("Initializing KV logs (small,medium,large) for DB: %s", db_desc->db_name);
#if 0
	// Medium log L0
  for (int i = 0; i < NUM_TREES_PER_LEVEL; ++i) {
    db_desc->inmem_medium_log_L0[i].head_dev_offt = 0;
    db_desc->inmem_medium_log_L0[i].tail_dev_offt = 0;
    db_desc->inmem_medium_log_L0[i].size = 0;
    db_desc->dev_medium_log_L0[i].head_dev_offt = 0;
    db_desc->dev_medium_log_L0[i].tail_dev_offt = 0;
    db_desc->dev_medium_log_L0[i].size = 0;
  }
#endif

	// Large log
	struct segment_header *s = seg_get_raw_log_segment(volume_desc);
	s->segment_id = 0;
	s->next_segment = NULL;
	s->prev_segment = NULL;
	db_desc->big_log.head_dev_offt = ABSOLUTE_ADDRESS(s);
	db_desc->big_log.tail_dev_offt = db_desc->big_log.head_dev_offt;
	db_desc->big_log.size = sizeof(segment_header);
	pr_init_log(&db_desc->big_log);
	log_info("Big log head %llu", db_desc->big_log.head_dev_offt);

	// Medium log
	s = seg_get_raw_log_segment(volume_desc);
	s->segment_id = 0;
	s->next_segment = NULL;
	s->prev_segment = NULL;
	db_desc->medium_log.head_dev_offt = ABSOLUTE_ADDRESS(s);
	db_desc->medium_log.tail_dev_offt = db_desc->medium_log.head_dev_offt;
	db_desc->medium_log.size = sizeof(segment_header);
	pr_init_log(&db_desc->medium_log);

	// Small log
	s = seg_get_raw_log_segment(volume_desc);
	s->segment_id = 0;
	s->prev_segment = NULL;
	s->next_segment = NULL;
	db_desc->small_log.head_dev_offt = ABSOLUTE_ADDRESS(s);
	db_desc->small_log.tail_dev_offt = db_desc->small_log.head_dev_offt;
	db_desc->small_log.size = sizeof(segment_header);
	pr_init_log(&db_desc->small_log);
	db_desc->lsn = 0;
}
#if 0
void recover_database_logs(db_descriptor *db_desc, pr_db_entry *db_entry)
{
	db_desc->commit_log = (commit_log_info *)REAL_ADDRESS(db_entry->commit_log);

	if (db_desc->commit_log->big_log_head != NULL)
		db_desc->big_log_head = (segment_header *)REAL_ADDRESS(db_desc->commit_log->big_log_head);
	else
		db_desc->big_log_head = NULL;

	if (db_desc->commit_log->big_log_tail != NULL)
		db_desc->big_log_tail = (segment_header *)REAL_ADDRESS(db_desc->commit_log->big_log_tail);
	else
		db_desc->big_log_tail = NULL;

	db_desc->big_log_size = db_desc->commit_log->big_log_size;
	db_desc->big_log_head_offset = db_entry->big_log_head_offset;
	db_desc->big_log_tail_offset = db_entry->big_log_tail_offset;

	log_info("Big log segments first: %llu last: %llu log_size %llu", (long long unsigned)db_desc->big_log_head,
		 (long long unsigned)db_desc->big_log_tail, (long long unsigned)db_desc->big_log_size);
	log_info("L0 start log offset %llu end %llu", db_desc->big_log_head_offset, db_desc->big_log_tail_offset);

	if (db_desc->commit_log->medium_log_head != NULL)
		db_desc->medium_log_head = (segment_header *)REAL_ADDRESS(db_desc->commit_log->medium_log_head);
	else
		db_desc->medium_log_head = NULL;

	if (db_desc->commit_log->medium_log_tail != NULL)
		db_desc->medium_log_tail = (segment_header *)REAL_ADDRESS(db_desc->commit_log->medium_log_tail);
	else
		db_desc->medium_log_tail = NULL;

	db_desc->medium_log_size = db_desc->commit_log->medium_log_size;
	db_desc->medium_log_head_offset = db_entry->medium_log_head_offset;
	db_desc->medium_log_tail_offset = db_entry->medium_log_tail_offset;

	log_info("Medium log segments first: %llu last: %llu log_size %llu",
		 (long long unsigned)db_desc->medium_log_head, (long long unsigned)db_desc->medium_log_tail,
		 (long long unsigned)db_desc->medium_log_size);
	log_info("Medium L0 start log offset %llu end %llu", db_desc->medium_log_head_offset,
		 db_desc->medium_log_tail_offset);

	if (db_desc->commit_log->small_log_head != NULL)
		db_desc->small_log_head = (segment_header *)REAL_ADDRESS(db_desc->commit_log->small_log_head);
	else
		db_desc->small_log_head = NULL;

	if (db_desc->commit_log->small_log_tail != NULL)
		db_desc->small_log_tail = (segment_header *)REAL_ADDRESS(db_desc->commit_log->small_log_tail);
	else
		db_desc->small_log_tail = NULL;

	db_desc->small_log_size = db_desc->commit_log->small_log_size;
	db_desc->small_log_head_offset = db_entry->small_log_head_offset;
	db_desc->small_log_tail_offset = db_entry->small_log_tail_offset;

	log_info("Small log segments first: %llu last: %llu log_size %llu", (long long unsigned)db_desc->small_log_head,
		 (long long unsigned)db_desc->small_log_tail, (long long unsigned)db_desc->small_log_size);
	log_info("Small L0 start log offset %llu end %llu", db_desc->small_log_head_offset,
		 db_desc->small_log_tail_offset);
=======
log_info("Recovering KV logs (small,medium,large) for DB: %s", db_desc->db_name);

// Small log
db_desc->big_log_head = REAL_ADDRESS(entry->big_log_head_offt);
db_desc->big_log_tail = REAL_ADDRESS(entry->big_log_tail_offt);
db_desc->big_log_size = entry->big_log_size;

// Medium log
db_desc->medium_log_head = REAL_ADDRESS(entry->medium_log_head_offt);
db_desc->medium_log_tail = REAL_ADDRESS(entry->medium_log_tail_offt);
db_desc->medium_log_size = entry->medium_log_size;

// Large log
db_desc->big_log_head = REAL_ADDRESS(entry->big_log_head_offt);
db_desc->big_log_tail = REAL_ADDRESS(entry->big_log_tail_offt);
db_desc->big_log_size = entry->big_log_size;
db_desc->lsn = entry->lsn;
}
#endif

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
#if 0
static void bt_recover_L0(struct db_handle *hd)
{
	(void)hd;
}
#endif
struct db_handle *bt_restore_db(struct volume_descriptor *volume_desc, struct pr_db_entry *db_entry,
				struct db_coordinates db_c)
{
	struct db_handle *handle = calloc(1, sizeof(struct db_handle));
	struct db_descriptor *db_desc = calloc(1, sizeof(struct db_descriptor));

	handle->volume_desc = volume_desc;
	handle->db_desc = db_desc;
	/*initialize database descriptor, soft state first*/
	db_desc->group_id = db_c.group_id;
	db_desc->group_index = db_c.index;
	/*restore db name, in memory*/
	memset(db_desc->db_name, 0x00, MAX_DB_NAME_SIZE);
	strcpy(db_desc->db_name, db_entry->db_name);
	db_desc->dirty = 0;

	/*restore now persistent state of all levels*/
	for (uint8_t level_id = 0; level_id < MAX_LEVELS; level_id++) {
		db_desc->levels[level_id].level_size[0] = 0;
		db_desc->levels[level_id].level_size[1] = 0;

		for (uint8_t tree_id = 0; tree_id < NUM_TREES_PER_LEVEL; tree_id++) {
			db_desc->levels[level_id].level_size[tree_id] = 0;
			/*segments info per level*/
			if (db_entry->first_segment[level_id][tree_id] != 0) {
				db_desc->levels[level_id].first_segment[tree_id] =
					(segment_header *)REAL_ADDRESS(db_entry->first_segment[level_id][tree_id]);
				db_desc->levels[level_id].last_segment[tree_id] =
					(segment_header *)REAL_ADDRESS(db_entry->last_segment[level_id][tree_id]);
				db_desc->levels[level_id].offset[tree_id] = db_entry->offset[level_id][tree_id];
			} else {
				db_desc->levels[level_id].first_segment[tree_id] = NULL;
				db_desc->levels[level_id].last_segment[tree_id] = NULL;
				db_desc->levels[level_id].offset[tree_id] = 0;
			}
			/*total keys*/
			db_desc->levels[level_id].level_size[tree_id] = db_entry->level_size[level_id][tree_id];
			/*finally the roots*/
			if (db_entry->root_r[level_id][tree_id] != 0)
				db_desc->levels[level_id].root_r[tree_id] =
					(node_header *)REAL_ADDRESS(db_entry->root_r[level_id][tree_id]);
			else
				db_desc->levels[level_id].root_r[tree_id] = NULL;

			db_desc->levels[level_id].root_w[tree_id] = NULL;
		}
	}

	pr_recover_logs(db_desc, db_entry);
	return handle;
}

db_handle *db_open(char *volumeName, uint64_t start, uint64_t size, char *db_name, char CREATE_FLAG)
{
	uint32_t leaf_size_per_level[10] = { LEVEL0_LEAF_SIZE, LEVEL1_LEAF_SIZE, LEVEL2_LEAF_SIZE, LEVEL3_LEAF_SIZE,
					     LEVEL4_LEAF_SIZE, LEVEL5_LEAF_SIZE, LEVEL6_LEAF_SIZE, LEVEL7_LEAF_SIZE };
	struct db_handle *handle = NULL;
	struct volume_descriptor *volume_desc = NULL;
	struct db_descriptor *db = NULL;

	fprintf(stderr, "\n%s[%s:%s:%d](\"%s\", %" PRIu64 ", %" PRIu64 ", %s);%s\n", "\033[0;32m", __FILE__, __func__,
		__LINE__, volumeName, start, size, db_name, "\033[0m");

	MUTEX_LOCK(&init_lock);
	parse_options();
	if (!(volume_desc = get_volume_desc(volumeName, start, 0)))
		volume_desc = get_volume_desc(volumeName, start, 1);

	assert(volume_desc->open_databases);
	index_order = IN_LENGTH;
	_Static_assert(sizeof(index_node) == 4096, "Index node is not page aligned");
	db = klist_find_element_with_key(volume_desc->open_databases, db_name);

	if (db != NULL) {
		log_info("DB %s already open for volume", db_name);
		handle = calloc(1, sizeof(struct db_handle));
		memset(handle, 0x00, sizeof(db_handle));
		handle->volume_desc = volume_desc;
		handle->db_desc = db;
		++handle->db_desc->reference_count;
		MUTEX_UNLOCK(&init_lock);
		return handle;
	} else {
		uint64_t level0_size;
		uint64_t growth_factor;
		struct lib_option *option;

		HASH_FIND_STR(dboptions, "level0_size", option);
		check_option("level0_size", option);
		level0_size = MB(option->value.count);

		HASH_FIND_STR(dboptions, "growth_factor", option);
		check_option("growth_factor", option);
		growth_factor = option->value.count;

		struct db_coordinates db_c;
		if (CREATE_FLAG == CREATE_DB)
			db_c = locate_db(volume_desc, db_name, 1);
		else
			db_c = locate_db(volume_desc, db_name, 0);

		if (db_c.out_of_space) {
			log_fatal("DB catalogue out of space");
			exit(EXIT_FAILURE);
		} else if (db_c.found) {
			if (db_c.new_db) {
				log_info("Creating new DB: %s at index [%d,%d]", db_name, db_c.group_id, db_c.index);
				handle = calloc(1, sizeof(struct db_handle));
				if (!handle) {
					log_fatal("calloc failed");
					exit(EXIT_FAILURE);
				}
				handle->db_desc = calloc(1, sizeof(struct db_descriptor));

				if (!handle->db_desc) {
					log_fatal("calloc failed");
					exit(EXIT_FAILURE);
				}

				handle->volume_desc = volume_desc;
				handle->db_desc->group_id = db_c.group_id;
				handle->db_desc->group_index = db_c.index;
				strcpy(handle->db_desc->db_name, db_name);

				for (uint8_t level_id = 0; level_id < MAX_LEVELS; level_id++) {
					for (uint8_t tree_id = 0; tree_id < NUM_TREES_PER_LEVEL; tree_id++) {
						handle->db_desc->levels[level_id].root_r[tree_id] = NULL;
						handle->db_desc->levels[level_id].root_w[tree_id] = NULL;
						handle->db_desc->levels[level_id].level_size[tree_id] = 0;
						handle->db_desc->levels[level_id].first_segment[tree_id] = NULL;
						handle->db_desc->levels[level_id].last_segment[tree_id] = NULL;
						handle->db_desc->levels[level_id].offset[tree_id] = 0;
						init_leaf_sizes_perlevel(&handle->db_desc->levels[level_id]);
					}

					if (level_id != 0)
						handle->db_desc->levels[level_id].max_level_size =
							handle->db_desc->levels[level_id - 1].max_level_size *
							growth_factor;
					else
						handle->db_desc->levels[level_id].max_level_size = level0_size;

					log_info("Level %d max_total_size %llu", level_id,
						 handle->db_desc->levels[level_id].max_level_size);
				}
				handle->db_desc->levels[MAX_LEVELS - 1].max_level_size = UINT64_MAX;
				pr_init_logs(handle->db_desc, volume_desc);
				handle->db_desc->reference_count = 1;
			} else {
				log_info("DB: %s found at index [%d,%d]", db_name, db_c.group_id, db_c.index);
				handle = bt_restore_db(volume_desc,
						       &volume_desc->mem_catalogue->db_group_index[db_c.group_id]
								->db_entries[db_c.index],
						       db_c);
				handle->db_desc->reference_count = 1;
			}
		} else {
			log_warn("DB: %s not found instructed not to create a new one!", db_name);
			MUTEX_UNLOCK(&init_lock);
			return NULL;
		}
	}

	/*init soft state for all levels*/
	MUTEX_INIT(&handle->db_desc->compaction_lock, NULL);
	MUTEX_INIT(&handle->db_desc->compaction_structs_lock, NULL);
	pthread_cond_init(&handle->db_desc->compaction_cond, NULL);
	handle->db_desc->blocked_clients = 0;
	handle->db_desc->compaction_count = 0;
	handle->db_desc->is_compaction_daemon_sleeping = 0;
#if MEASURE_MEDIUM_INPLACE
	db_desc->count_medium_inplace = 0;
#endif

	if (sem_init(&handle->db_desc->compaction_sem, 0, 0) != 0) {
		log_fatal("Semaphore cannot be initialized");
		exit(EXIT_FAILURE);
	}
	if (sem_init(&handle->db_desc->compaction_daemon_sem, 0, 0) != 0) {
		log_fatal("FATAL semaphore cannot be initialized");
		exit(EXIT_FAILURE);
	}

	for (uint8_t level_id = 0; level_id < MAX_LEVELS; level_id++) {
		RWLOCK_INIT(&handle->db_desc->levels[level_id].guard_of_level.rx_lock, NULL);
		MUTEX_INIT(&handle->db_desc->levels[level_id].spill_trigger, NULL);
		MUTEX_INIT(&handle->db_desc->levels[level_id].level_allocation_lock, NULL);
		init_level_locktable(handle->db_desc, level_id);
		memset(handle->db_desc->levels[level_id].level_size, 0, sizeof(uint64_t) * NUM_TREES_PER_LEVEL);
		handle->db_desc->levels[level_id].medium_log_size = 0;
		handle->db_desc->levels[level_id].active_writers = 0;
		/*check again which tree should be active*/
		handle->db_desc->levels[level_id].active_tree = 0;
		handle->db_desc->levels[level_id].level_id = level_id;
		handle->db_desc->levels[level_id].leaf_size = leaf_size_per_level[level_id];
#if MEASURE_SST_USED_SPACE
		db_desc->levels[level_id].avg_leaf_used_space = 0;
		db_desc->levels[level_id].leaf_used_space = 0;
		db_desc->levels[level_id].count_leaves = 0;
		db_desc->levels[level_id].count_compactions = 0;
#endif
		for (uint8_t tree_id = 0; tree_id < NUM_TREES_PER_LEVEL; tree_id++) {
			handle->db_desc->levels[level_id].tree_status[tree_id] = NO_SPILLING;
#if ENABLE_BLOOM_FILTERS
			init_level_bloom_filters(db_desc, level_id, tree_id);
#endif
		}
		init_leaf_sizes_perlevel(&handle->db_desc->levels[level_id]);
	}
	sem_init(&gc_daemon_interrupts, PTHREAD_PROCESS_PRIVATE, 0);

	static int gc_thread_spawned = 0;
	if (!gc_thread_spawned) {
		++gc_thread_spawned;
		assert(handle->volume_desc->open_databases);
		if (pthread_create(&(handle->db_desc->gc_thread), NULL, (void *)gc_log_entries, (void *)handle) != 0) {
			log_fatal("Failed to start compaction_daemon for db %s", db_name);
			exit(EXIT_FAILURE);
		}
	}
	/* if(!gc_thread_spawned){ */
	/* 	++gc_thread_spawned; */
	/* handle->db_desc->gc_count_segments = 0; */
	/* handle->db_desc->gc_last_segment_id = 0; */
	/* handle->db_desc->gc_keys_transferred = 0; */
	/* if (pthread_create(&(handle->db_desc->gc_thread), NULL, (void
* *)gc_log_entries, (void *)handle) != 0) { */
	/* 	log_fatal("Failed to start compaction_daemon for db %s", db_name); */
	/* 	exit(EXIT_FAILURE); */
	/* } */
	/* } */
	_Static_assert(UNKNOWN_LOG_CATEGORY < 8, "Log categories number cannot be "
						 "stored in 3 bits, increase "
						 "key_category");
	_Static_assert(sizeof(struct bt_dynamic_leaf_slot_array) == 4,
		       "Dynamic slot array is not 4 bytes, are you sure you want to continue?");
	_Static_assert(sizeof(struct segment_header) == 4096, "Segment header not page aligned!");
	_Static_assert(sizeof(struct pr_db_group) == 4096, "pr_db_group overflow!");

	MUTEX_INIT(&handle->db_desc->lock_log, NULL);

	klist_add_first(volume_desc->open_databases, handle->db_desc, db_name, NULL);
	handle->db_desc->stat = DB_OPEN;
	MUTEX_UNLOCK(&init_lock);

	log_info("Opened DB %s starting its compaction daemon", db_name);

	sem_init(&handle->db_desc->compaction_daemon_interrupts, PTHREAD_PROCESS_PRIVATE, 0);

	if (pthread_create(&(handle->db_desc->compaction_daemon), NULL, (void *)compaction_daemon, (void *)handle) !=
	    0) {
		log_fatal("Failed to start compaction_daemon for db %s", db_name);
		exit(EXIT_FAILURE);
	}

#if 0
	/*recovery checks*/
	log_info("performing recovery checks for db: %s", handle->db_desc->db_name);

	/*where is L0 located at the log?*/
	if (handle->db_desc->big_log_tail_offset > handle->db_desc->big_log_head_offset ||
	    handle->db_desc->medium_log_tail_offset > handle->db_desc->medium_log_head_offset ||
	    handle->db_desc->small_log_tail_offset > handle->db_desc->small_log_head_offset) {
		log_info("L0 present performing recovery checks ...");

		if (handle->db_desc->big_log_tail_offset < handle->db_desc->commit_log->big_log_size ||
		    handle->db_desc->medium_log_tail_offset < handle->db_desc->commit_log->medium_log_size ||
		    handle->db_desc->small_log_tail_offset < handle->db_desc->commit_log->small_log_size) {
			log_info("Commit log: %llu is ahead of L0: %llu replaying "
				 "missing log parts",
				 handle->db_desc->commit_log->big_log_size, handle->db_desc->big_log_tail_offset);
			recovery_request rh;
			rh.volume_desc = volume_desc;
			rh.db_desc = handle->db_desc;
			rh.big_log_start_offset = handle->db_desc->big_log_tail_offset;
			rh.medium_log_start_offset = handle->db_desc->medium_log_tail_offset;
			rh.small_log_start_offset = handle->db_desc->small_log_tail_offset;
			recover_region(&rh);
			log_info("recovery completed successfully");
		} else if (handle->db_desc->big_log_tail_offset == handle->db_desc->commit_log->big_log_size &&
			   handle->db_desc->medium_log_tail_offset == handle->db_desc->commit_log->medium_log_size &&
			   handle->db_desc->small_log_tail_offset == handle->db_desc->commit_log->small_log_size) {
			log_info("no recovery needed for db: %s ready :-)\n", handle->db_desc->db_name);
		} else {
			log_fatal("Boom! Corrupted state for db: %s :-(", handle->db_desc->db_name);
			raise(SIGINT);
			exit(EXIT_FAILURE);
		}

	} else if (handle->db_desc->big_log_tail_offset == handle->db_desc->big_log_head_offset ||
		   handle->db_desc->medium_log_tail_offset == handle->db_desc->medium_log_head_offset ||
		   handle->db_desc->small_log_tail_offset == handle->db_desc->small_log_head_offset) {
		log_info("L0 is absent L1 ends at %llu replaying missing parts", handle->db_desc->big_log_tail_offset);
		log_info("L0 is absent L1 ends at %llu replaying missing parts",
			 handle->db_desc->medium_log_tail_offset);
		log_info("L0 is absent L1 ends at %llu replaying missing parts",
			 handle->db_desc->small_log_tail_offset);

		log_info("Condition part1 %d part2 %d part3 %d",
			 handle->db_desc->big_log_tail_offset < handle->db_desc->commit_log->big_log_size,
			 handle->db_desc->medium_log_tail_offset < handle->db_desc->commit_log->medium_log_size,
			 handle->db_desc->small_log_tail_offset < handle->db_desc->commit_log->small_log_size);

		if (handle->db_desc->big_log_tail_offset < handle->db_desc->commit_log->big_log_size ||
		    handle->db_desc->medium_log_tail_offset < handle->db_desc->commit_log->medium_log_size ||
		    handle->db_desc->small_log_tail_offset < handle->db_desc->commit_log->small_log_size) {
			log_info("Commit log (%llu) is ahead of L0 end (%llu) replaying missing "
				 "log parts",
				 handle->db_desc->commit_log->big_log_size, handle->db_desc->big_log_tail_offset);
			recovery_request rh;
			rh.volume_desc = volume_desc;
			rh.db_desc = handle->db_desc;
			rh.big_log_start_offset = handle->db_desc->big_log_tail_offset;
			rh.medium_log_start_offset = handle->db_desc->medium_log_tail_offset;
			rh.small_log_start_offset = handle->db_desc->small_log_tail_offset;
			recover_region(&rh);
			log_info("Recovery completed successfully");
		} else if (handle->db_desc->big_log_tail_offset == handle->db_desc->commit_log->big_log_size &&
			   handle->db_desc->medium_log_tail_offset == handle->db_desc->commit_log->medium_log_size &&
			   handle->db_desc->small_log_tail_offset == handle->db_desc->commit_log->small_log_size) {
			log_info("no recovery needed for db: %s ready :-)\n", handle->db_desc->db_name);
		} else {
			log_fatal("FATAL corrupted state for db: %s :-(", handle->db_desc->db_name);
			exit(EXIT_FAILURE);
		}

	} else {
		log_fatal("FATAL Corrupted state detected");
		exit(EXIT_FAILURE);
	}
	log_info("big start %llu big end %llu diff %llu", handle->db_desc->big_log_head, handle->db_desc->big_log_tail,
		 handle->db_desc->big_log_tail_offset - handle->db_desc->big_log_head_offset);
	log_info("medium start %llu medium end %llu", handle->db_desc->medium_log_head,
		 handle->db_desc->medium_log_tail);
	log_info("small start %llu small end %llu", handle->db_desc->small_log_head, handle->db_desc->small_log_tail);
#endif

	handle->db_desc->gc_db = db_open(volumeName, 0, size, SYSTEMDB, DONOT_CREATE_DB);

	if (!handle->db_desc->gc_db)
		handle->db_desc->gc_db = db_open(volumeName, 0, size, SYSTEMDB, CREATE_DB);

	assert(handle->db_desc->gc_db);

	return handle;
}

char db_close(db_handle *handle)
{
	/*verify that this is a valid db*/
	if (klist_find_element_with_key(handle->volume_desc->open_databases, handle->db_desc->db_name) == NULL) {
		log_fatal("received close for db: %s that is not listed as open", handle->db_desc->db_name);
		exit(EXIT_FAILURE);
	}

	log_info("closing region/db %s snapshotting volume\n", handle->db_desc->db_name);
	handle->db_desc->stat = DB_IS_CLOSING;
	snapshot(handle->volume_desc);
/*stop log appenders*/
#if LOG_WITH_MUTEX
	MUTEX_LOCK(&handle->db_desc->lock_log);
#else
	SPIN_LOCK(&handle->db_desc->lock_log);
#endif
	/*stop all writers at all levels*/
	uint8_t level_id;
	for (level_id = 0; level_id < MAX_LEVELS; level_id++) {
		RWLOCK_WRLOCK(&handle->db_desc->levels[level_id].guard_of_level.rx_lock);
		spin_loop(&(handle->db_desc->levels[level_id].active_writers), 0);
	}

	destroy_level_locktable(handle->db_desc, 0);

	if (klist_remove_element(handle->volume_desc->open_databases, handle->db_desc) != 1) {
		log_info("Could not find db: %s", handle->db_desc->db_name);
		MUTEX_UNLOCK(&init_lock);
		return COULD_NOT_FIND_DB;
	}
	return KREON_OK;
}

uint8_t insert_key_value(db_handle *handle, void *key, void *value, uint32_t key_size, uint32_t value_size)
{
	bt_insert_req ins_req;
	char __tmp[KV_MAX_SIZE];
	char *key_buf = __tmp;
	double kv_ratio;
	uint32_t kv_size;
	int active_tree = handle->db_desc->levels[0].active_tree;

	while (handle->db_desc->levels[0].level_size[active_tree] > handle->db_desc->levels[0].max_level_size) {
		pthread_mutex_lock(&handle->db_desc->client_barrier_lock);
		active_tree = handle->db_desc->levels[0].active_tree;
		if (handle->db_desc->levels[0].level_size[active_tree] > handle->db_desc->levels[0].max_level_size) {
			sem_post(&handle->db_desc->compaction_daemon_interrupts);
			if (pthread_cond_wait(&handle->db_desc->client_barrier,
					      &handle->db_desc->client_barrier_lock) != 0) {
				log_fatal("failed to throttle");
				exit(EXIT_FAILURE);
			}
		}
		active_tree = handle->db_desc->levels[0].active_tree;
		pthread_mutex_unlock(&handle->db_desc->client_barrier_lock);
	}

	if (key_size > MAX_KEY_SIZE) {
		log_info("Keys > %d bytes are not supported!", MAX_KEY_SIZE);
		return KREON_FAILED;
	}

	kv_size = sizeof(uint32_t) + key_size + sizeof(uint32_t) + value_size /* + sizeof(uint64_t) */;
	kv_ratio = ((double)key_size) / value_size;

	if (kv_size > KV_MAX_SIZE) {
		log_fatal("Key buffer overflow");
		BREAKPOINT;
		exit(EXIT_FAILURE);
	}
	/*prepare the request*/
	*(uint32_t *)key_buf = key_size;
	memcpy((void *)(uint64_t)key_buf + sizeof(uint32_t), key, key_size);
	*(uint32_t *)((uint64_t)key_buf + sizeof(uint32_t) + key_size) = value_size;
	memcpy((void *)(uint64_t)key_buf + sizeof(uint32_t) + key_size + sizeof(uint32_t), value, value_size);
	ins_req.metadata.handle = handle;
	ins_req.key_value_buf = key_buf;
	ins_req.metadata.kv_size = kv_size;
	ins_req.metadata.level_id = 0;
	ins_req.metadata.key_format = KV_FORMAT;
	ins_req.metadata.append_to_log = 1;
	ins_req.metadata.gc_request = 0;
	ins_req.metadata.special_split = 0;

	if (kv_ratio >= 0.0 && kv_ratio < 0.004) {
		ins_req.metadata.cat = BIG_INLOG;
	} else if (kv_ratio >= 0.004 && kv_ratio <= 0.3) {
#if MEDIUM_LOG_UNSORTED
		ins_req.metadata.cat = MEDIUM_INLOG;
#else
		ins_req.metadata.cat = MEDIUM_INPLACE;
#endif
	} else {
		ins_req.metadata.cat = SMALL_INPLACE;
	}

	/*
* Note for L0 inserts since active_tree changes dynamically we decide which
* is the active_tree after
* acquiring the guard lock of the region
* */

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
		data_size->key_len = *(uint32_t *)req->del_req->key_buf;
		data_size->value_len = 0;
		data_size->kv_size = data_size->key_len + (sizeof(uint32_t) * 2);
		break;
	default:
		log_fatal("Trying to append unknown operation in log! ");
		exit(EXIT_FAILURE);
	}
}

void write_keyvalue_inlog(log_operation *req, metadata_tologop *data_size, char *addr_inlog, uint64_t lsn)
{
	*(uint64_t *)addr_inlog = lsn;
	addr_inlog += sizeof(struct log_sequence_number);

	switch (req->optype_tolog) {
	case insertOp:
		if (req->metadata->key_format == KV_FORMAT) {
			memcpy(addr_inlog, req->ins_req->key_value_buf,
			       sizeof(data_size->key_len) + data_size->key_len + sizeof(data_size->value_len) +
				       data_size->value_len);
		} else {
			memcpy(addr_inlog, (void *)*(uint64_t *)(req->ins_req->key_value_buf + PREFIX_SIZE),
			       sizeof(data_size->key_len) + data_size->key_len + sizeof(data_size->value_len) +
				       data_size->value_len);
			req->metadata->key_format = KV_FORMAT;
		}
		break;
	case deleteOp:
		memcpy(addr_inlog, req->del_req->key_buf, sizeof(data_size->key_len) + data_size->key_len);
		addr_inlog += (sizeof(data_size->key_len) + data_size->key_len);
		memcpy(addr_inlog, &data_size->value_len, sizeof(data_size->value_len));
		break;
	default:
		log_fatal("Trying to append unknown operation in log! ");
		exit(EXIT_FAILURE);
	}
}

size_t SIZE_INMEMORY_LOG = ((1 * 1024 * 1024 * 1024) * 3UL);

void update_log_metadata(db_descriptor *db_desc, struct log_towrite *log_metadata)
{
	switch (log_metadata->status) {
	case BIG_INLOG:
		db_desc->big_log.tail_dev_offt = log_metadata->log_desc->tail_dev_offt;
		return;
	case MEDIUM_INLOG:
#if MEDIUM_LOG_UNSORTED
		if (log_metadata->level_id) {
			log_fatal("KV separation allowed only for L0");
			exit(EXIT_FAILURE);
			return;
		} else
			db_desc->medium_log.tail_dev_offt = log_metadata->log_desc->tail_dev_offt;
#else
		if (log_metadata->level_id != 0) {
			db_desc->medium_log.tail_dev_offt = log_metadata->log_desc->tail_dev_offt;
			return;
		} else {
			log_fatal("MEDIUM_INLOG with level_id 0 not allowed!");
			exit(EXIT_FAILURE);
		}
#endif
	case SMALL_INPLACE:
	case SMALL_INLOG:
	case MEDIUM_INPLACE:
		db_desc->small_log.tail_dev_offt = log_metadata->log_desc->tail_dev_offt;
		return;
	default:
		assert(0);
	}
}

//######################################################################################################
// Helper functions for writing to the log(s) with direct IO
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
		assert(0);
		return;
	}
	uint64_t offt_in_seg = ticket->log_offt % SEGMENT_SIZE;
	switch (ticket->req->optype_tolog) {
	case insertOp: {
		uint64_t offt = offt_in_seg;
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
		log_fatal("Delete operation not supported yet");
		exit(EXIT_FAILURE);
	}
	case paddingOp: {
		if (offt_in_seg == 0)
			ticket->op_size = 0;
		else {
			ticket->op_size = SEGMENT_SIZE - offt_in_seg;
			// log_info("Time for padding for log_offset %llu offt in seg %llu pad
			// bytes
			// %u", ticket->log_offt,
			//	 offt_in_seg, ticket->op_size);
			memset(&ticket->tail->buf[offt_in_seg], 0, ticket->op_size);
		}
		break;
	}
	default:
		log_fatal("Unknown op");
		exit(EXIT_FAILURE);
	}

	uint32_t remaining = ticket->op_size;
	uint32_t curr_offt_in_seg = offt_in_seg;
	while (remaining > 0) {
		uint32_t chunk_id = curr_offt_in_seg / LOG_CHUNK_SIZE;
		int64_t offt_in_chunk = curr_offt_in_seg - (chunk_id * LOG_CHUNK_SIZE);
		int64_t bytes = LOG_CHUNK_SIZE - offt_in_chunk;
		if (remaining < bytes)
			bytes = remaining;

		__sync_fetch_and_add(&ticket->tail->bytes_in_chunk[chunk_id], bytes);
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
	assert(chunk_id != num_chunks);
	int do_IO;

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
	ssize_t total_bytes_written;
	if (chunk_id)
		total_bytes_written = 0;
	else
		total_bytes_written = sizeof(struct segment_header);
	ssize_t bytes_written = 0;
	uint32_t size = LOG_CHUNK_SIZE;
	// log_info("IO time, start %llu size %llu segment dev_offt %llu offt in seg
	// %llu", total_bytes_written, size,
	//	 ticket->tail->dev_segment_offt, ticket->IO_start_offt);
	while (total_bytes_written < size) {
		bytes_written = pwrite(ticket->tail->fd,
				       &ticket->tail->buf[ticket->IO_start_offt + total_bytes_written],
				       size - total_bytes_written,
				       ticket->tail->dev_offt + ticket->IO_start_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to write LOG_CHUNK reason follows");
			perror("Reason");
			exit(EXIT_FAILURE);
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
	uint32_t remaining = ticket->op_size;
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

static void *bt_append_to_log_direct_IO(struct log_operation *req, struct log_towrite *log_metadata,
					struct metadata_tologop *data_size)
{
	db_handle *handle = req->metadata->handle;

	struct pr_log_ticket my_ticket = { .log_offt = 0, .IO_start_offt = 0, .IO_size = 0 };
	struct pr_log_ticket pad_ticket = { .log_offt = 0, .IO_start_offt = 0, .IO_size = 0 };
	char *addr_inlog = NULL;
	MUTEX_LOCK(&handle->db_desc->lock_log);
	uint32_t available_space_in_log;
	// append data part in the data log
	if (log_metadata->log_desc->size % SEGMENT_SIZE != 0)
		available_space_in_log = SEGMENT_SIZE - (log_metadata->log_desc->size % SEGMENT_SIZE);
	else
		available_space_in_log = 0;

	uint32_t num_chunks = SEGMENT_SIZE / LOG_CHUNK_SIZE;
	int segment_change = 0;
	//log_info("Direct IO in log kv size is %u log size %u avail space %u", data_size->kv_size,
	//	 log_metadata->log_desc->size, available_space_in_log);
	if (available_space_in_log < (data_size->kv_size + sizeof(struct log_sequence_number))) {
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

		struct segment_header *d_header = seg_get_raw_log_segment(handle->volume_desc);
		struct segment_header *last_segment = REAL_ADDRESS(log_metadata->log_desc->tail_dev_offt);
		d_header->segment_id = last_segment->segment_id + 1;
		d_header->next_segment = NULL;
		last_segment->next_segment = (void *)ABSOLUTE_ADDRESS(d_header);
		log_metadata->log_desc->tail_dev_offt = ABSOLUTE_ADDRESS(d_header);
		// position the log to the newly added block
		log_metadata->log_desc->size += sizeof(segment_header);
		// Reset tail for new use
		for (int j = 0; j < (SEGMENT_SIZE / LOG_CHUNK_SIZE); ++j)
			next_tail->bytes_in_chunk[j] = 0;
		next_tail->IOs_completed_in_tail = 0;
		next_tail->start = ABSOLUTE_ADDRESS(d_header);
		next_tail->end = next_tail->start + SEGMENT_SIZE;
		next_tail->dev_offt = ABSOLUTE_ADDRESS(d_header);
		next_tail->bytes_in_chunk[0] = sizeof(struct segment_header);
		next_tail->free = 0;
		log_metadata->log_desc->curr_tail_id = next_tail_id;
		//log_info("Curr tail %u start %llu end %llu",next_tail_id,next_tail->start,next_tail->end);
		segment_change = 1;
		RWLOCK_UNLOCK(&log_metadata->log_desc->log_tail_buf_lock);
	}
	uint32_t tail_id = log_metadata->log_desc->curr_tail_id;
	my_ticket.req = req;
	my_ticket.data_size = data_size;
	my_ticket.tail = log_metadata->log_desc->tail[tail_id % LOG_TAIL_NUM_BUFS];
	my_ticket.log_offt = log_metadata->log_desc->size;
	my_ticket.lsn.id = __sync_fetch_and_add(&handle->db_desc->lsn, 1);

	//Where we *will* store it on the device
	struct segment_header *T = REAL_ADDRESS(log_metadata->log_desc->tail_dev_offt);
	addr_inlog = (void *)((uint64_t)T + (log_metadata->log_desc->size % SEGMENT_SIZE));

	req->metadata->log_offset = log_metadata->log_desc->size;
	log_metadata->log_desc->size += (data_size->kv_size + sizeof(struct log_sequence_number));
	MUTEX_UNLOCK(&handle->db_desc->lock_log);

	if (segment_change && available_space_in_log > 0) {
		// do the padding IO as well
		pr_do_log_IO(&pad_ticket);
	}
	pr_copy_kv_to_tail(&my_ticket);
	pr_do_log_IO(&my_ticket);

	return addr_inlog + sizeof(struct log_sequence_number);
}
//######################################################################################################

#if 0
static void *bt_append_key_value_to_log_mmap(struct log_operation *req, struct log_towrite *log_metadata,
					     struct metadata_tologop *data_size)
{
	segment_header *d_header;
	void *addr_inlog;

	uint64_t lsn;
	uint32_t available_space_in_log;
	uint32_t allocated_space;
	db_handle *handle = req->metadata->handle;

	MUTEX_LOCK(&handle->db_desc->lock_log);

	/*append data part in the data log*/
	if (log_metadata->log_desc->size % SEGMENT_SIZE != 0)
		available_space_in_log = SEGMENT_SIZE - (log_metadata->log_desc->size % SEGMENT_SIZE);
	else
		available_space_in_log = 0;

	if (available_space_in_log < data_size->kv_size + sizeof(struct log_sequence_number)) {
		/*fill info for kreon master here*/
		req->metadata->log_segment_addr = log_metadata->log_desc->tail_dev_offt;
		req->metadata->log_offset_full_event = log_metadata->log_desc->size;
		struct segment_header *T = REAL_ADDRESS(log_metadata->log_desc->tail_dev_offt);
		req->metadata->segment_id = T->segment_id;
		req->metadata->log_padding = available_space_in_log;
		req->metadata->end_of_log = log_metadata->log_desc->size + available_space_in_log;
		req->metadata->segment_full_event = 1;

		/*pad with zeroes remaining bytes in segment*/
		addr_inlog = (void *)((uint64_t)T + (log_metadata->log_desc->size % SEGMENT_SIZE));
		memset(addr_inlog, 0x00, available_space_in_log);

		allocated_space = data_size->kv_size + sizeof(struct log_sequence_number) + sizeof(segment_header);
		allocated_space += SEGMENT_SIZE - (allocated_space % SEGMENT_SIZE);
		d_header = seg_get_raw_log_segment(handle->volume_desc);
		d_header->segment_id = T->segment_id + 1;
		d_header->prev_segment = (void *)log_metadata->log_desc->tail_dev_offt;
		d_header->next_segment = NULL;
		T->next_segment = (void *)ABSOLUTE_ADDRESS(d_header);
		log_metadata->log_desc->tail_dev_offt = ABSOLUTE_ADDRESS(d_header);
		/* position the log to the newly added block*/
		log_metadata->log_desc->size += (available_space_in_log + sizeof(segment_header));
		update_log_metadata(handle->db_desc, log_metadata);
	}
	struct segment_header *T = REAL_ADDRESS(log_metadata->log_desc->tail_dev_offt);
	addr_inlog = (void *)((uint64_t)T + (log_metadata->log_desc->size % SEGMENT_SIZE));
	req->metadata->log_offset = log_metadata->log_desc->size;
	log_metadata->log_desc->size += data_size->kv_size + sizeof(struct log_sequence_number);

	/* if(req->metadata->cat == BIG_INLOG){ */
	/*   log_info("kv_size = %d ",data_size.kv_size); */
	/* } */

	lsn = __sync_fetch_and_add(&handle->db_desc->lsn, 1);
	MUTEX_UNLOCK(&handle->db_desc->lock_log);

	write_keyvalue_inlog(req, data_size, addr_inlog, lsn);

	return addr_inlog + sizeof(struct log_sequence_number);
}
#endif

void *append_key_value_to_log(log_operation *req)
{
	db_handle *handle = req->metadata->handle;
	struct log_towrite log_metadata;
	log_metadata.level_id = req->metadata->level_id;
	log_metadata.status = req->metadata->cat;
	struct metadata_tologop data_size;
	extract_keyvalue_size(req, &data_size);

	switch (log_metadata.status) {
	case SMALL_INPLACE:
		log_metadata.log_desc = &handle->db_desc->small_log;
		return bt_append_to_log_direct_IO(req, &log_metadata, &data_size);
	case MEDIUM_INPLACE: {
		uint8_t level_id = req->metadata->level_id;
		if (level_id) {
			log_fatal("Append for MEDIUM_INPLACE for level_id > 0 ? Not allowed");
			exit(EXIT_FAILURE);
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
			exit(EXIT_FAILURE);
		} else {
			log_metadata.log_desc = &handle->db_desc->medium_log;
			return bt_append_to_log_direct_IO(req, &log_metadata, &data_size);
		}
#else
		if (level_id == 0) {
			log_fatal("MEDIUM_INLOG not allowed for level_id 0!");
			exit(EXIT_FAILURE);
		} else {
			log_metadata.log_desc = &handle->db_desc->medium_log;
			//return bt_append_key_value_to_log_mmap(req, &log_metadata, &data_size);
			char *c = bt_append_to_log_direct_IO(req, &log_metadata, &data_size);
			return c;
		}
#endif
	}
	case BIG_INLOG:
		log_metadata.log_desc = &handle->db_desc->big_log;
		//return bt_append_key_value_to_log_mmap(req, &log_metadata, &data_size);
		return bt_append_to_log_direct_IO(req, &log_metadata, &data_size);
	default:
		log_fatal("Unknown category %u", log_metadata.status);
		exit(EXIT_FAILURE);
	}
}

uint8_t _insert_key_value(bt_insert_req *ins_req)
{
	db_handle *handle = ins_req->metadata.handle;
	db_descriptor *db_desc = ins_req->metadata.handle->db_desc;
	uint8_t rc = SUCCESS;
	int active_tree = handle->db_desc->levels[0].active_tree;

	while (handle->db_desc->levels[0].level_size[active_tree] > handle->db_desc->levels[0].max_level_size &&
	       ins_req->metadata.gc_request) {
		pthread_mutex_lock(&handle->db_desc->client_barrier_lock);
		active_tree = handle->db_desc->levels[0].active_tree;
		if (handle->db_desc->levels[0].level_size[active_tree] > handle->db_desc->levels[0].max_level_size) {
			sem_post(&handle->db_desc->compaction_daemon_interrupts);
			if (pthread_cond_wait(&handle->db_desc->client_barrier,
					      &handle->db_desc->client_barrier_lock) != 0) {
				log_fatal("failed to throttle");
				exit(EXIT_FAILURE);
			}
		}
		active_tree = handle->db_desc->levels[0].active_tree;
		pthread_mutex_unlock(&handle->db_desc->client_barrier_lock);
	}

	assert(ins_req->metadata.kv_size < 4096);
	db_desc->dirty = 0x01;

	if (writers_join_as_readers(ins_req) == SUCCESS) {
		rc = SUCCESS;
	} else if (concurrent_insert(ins_req) != SUCCESS) {
		log_warn("insert failed!");
		rc = FAILED;
	}

	return rc;
}

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

static inline struct lookup_reply lookup_in_tree(db_descriptor *db_desc, void *key, node_header *root, int level_id,
						 int tree_id)
{
	struct lookup_reply rep = { .addr = NULL, .lc_failed = 0 };
	struct find_result ret_result = { .kv = NULL };
	node_header *curr_node, *son_node = NULL;
	void *key_addr_in_leaf = NULL;
	void *next_addr;
	uint32_t index_key_len;
	lock_table *prev = NULL, *curr = NULL;

	if (db_desc->levels[level_id].root_w[tree_id] != NULL) {
		/* log_info("Level %d with tree_id %d has root_w",level_id,tree_id); */
		root = db_desc->levels[level_id].root_w[tree_id];
	} else if (db_desc->levels[level_id].root_r[tree_id] != NULL) {
		/* log_info("Level %d with tree_id %d has root_w",level_id,tree_id); */
		root = db_desc->levels[level_id].root_r[tree_id];
	} else {
		/* log_info("Level %d is empty with tree_id %d",level_id,tree_id); */
		/* if (RWLOCK_UNLOCK(&curr->rx_lock) != 0) */
		/* 	exit(EXIT_FAILURE); */
		return rep;
	}

#if ENABLE_BLOOM_FILTERS
	if (level_id > 0) {
		int check = find_key_in_bloom_filter(db_desc, level_id, key);

		if (0 == check)
			return rep;
		else if (-1 != check) {
			assert(0);
			exit(EXIT_FAILURE);
		}
	}
#endif

	curr_node = root;
	if (curr_node->type == leafRootNode) {
		curr = _find_position(db_desc->levels[level_id].level_lock_table, curr_node);

		if (RWLOCK_RDLOCK(&curr->rx_lock) != 0)
			exit(EXIT_FAILURE);

		ret_result = find_key_in_dynamic_leaf((struct bt_dynamic_leaf_node *)curr_node, db_desc, key + 4,
						      *(uint32_t *)key, level_id);
		goto deser;
	} else {
		while (curr_node->type != leafNode) {
			curr = _find_position(db_desc->levels[level_id].level_lock_table, curr_node);

			if (RWLOCK_RDLOCK(&curr->rx_lock) != 0)
				exit(EXIT_FAILURE);

			if (prev)
				if (RWLOCK_UNLOCK(&prev->rx_lock) != 0)
					exit(EXIT_FAILURE);

			next_addr = _index_node_binary_search((index_node *)curr_node, key, KV_FORMAT);
			son_node = (void *)REAL_ADDRESS(*(uint64_t *)next_addr);
			prev = curr;
			curr_node = son_node;
		}

		prev = curr;
		curr = _find_position(db_desc->levels[level_id].level_lock_table, curr_node);
		if (RWLOCK_RDLOCK(&curr->rx_lock) != 0) {
			exit(EXIT_FAILURE);
		}

		if (RWLOCK_UNLOCK(&prev->rx_lock) != 0)
			exit(EXIT_FAILURE);
	}

	ret_result = find_key_in_dynamic_leaf((struct bt_dynamic_leaf_node *)curr_node, db_desc, key + 4,
					      *(uint32_t *)key, level_id);

deser:
	if (ret_result.kv) {
		if (ret_result.key_type == KV_INPLACE) {
			key_addr_in_leaf = ret_result.kv;
			key_addr_in_leaf = (void *)REAL_ADDRESS(key_addr_in_leaf);
			index_key_len = KEY_SIZE(key_addr_in_leaf);
			rep.addr = (void *)(uint64_t)key_addr_in_leaf + 4 + index_key_len;
			rep.lc_failed = 0;
		} else if (ret_result.key_type == KV_INLOG) {
			key_addr_in_leaf = ret_result.kv;
			key_addr_in_leaf = (void *)REAL_ADDRESS(*(uint64_t *)key_addr_in_leaf);
			index_key_len = KEY_SIZE(key_addr_in_leaf);
			rep.addr = (void *)(uint64_t)key_addr_in_leaf + 4 + index_key_len;
			rep.lc_failed = 0;
		} else
			assert(0);
	} else {
		rep.addr = NULL;
		rep.lc_failed = 0;
	}

	if (RWLOCK_UNLOCK(&curr->rx_lock) != 0)
		exit(EXIT_FAILURE);

	__sync_fetch_and_sub(&db_desc->levels[level_id].active_writers, 1);
	return rep;
}

/*this function will be reused in various places such as deletes*/
void *__find_key(db_handle *handle, void *key)
{
	struct lookup_reply rep = { .addr = NULL, .lc_failed = 0 };
	/*again special care for L0*/
	// Acquiring guard lock for level 0
	if (RWLOCK_RDLOCK(&handle->db_desc->levels[0].guard_of_level.rx_lock) != 0)
		exit(EXIT_FAILURE);
	__sync_fetch_and_add(&handle->db_desc->levels[0].active_writers, 1);
	uint8_t tree_id = handle->db_desc->levels[0].active_tree;
	uint8_t base = tree_id;

	while (1) {
		/*first look the current active tree of the level*/

		rep = lookup_in_tree(handle->db_desc, key, NULL, 0, tree_id);
		if (rep.addr != NULL) {
			if (RWLOCK_UNLOCK(&handle->db_desc->levels[0].guard_of_level.rx_lock) != 0)
				exit(EXIT_FAILURE);
			__sync_fetch_and_sub(&handle->db_desc->levels[0].active_writers, 1);

			goto finish;
		}
		++tree_id;
		if (tree_id >= NUM_TREES_PER_LEVEL)
			tree_id = 0;
		if (tree_id == base)
			break;
	}
	if (RWLOCK_UNLOCK(&handle->db_desc->levels[0].guard_of_level.rx_lock) != 0)
		exit(EXIT_FAILURE);
	__sync_fetch_and_sub(&handle->db_desc->levels[0].active_writers, 1);
	/*search the rest trees of the level*/
	for (uint8_t level_id = 1; level_id < MAX_LEVELS; ++level_id) {
		if (RWLOCK_RDLOCK(&handle->db_desc->levels[level_id].guard_of_level.rx_lock) != 0)
			exit(EXIT_FAILURE);
		__sync_fetch_and_add(&handle->db_desc->levels[level_id].active_writers, 1);

		rep = lookup_in_tree(handle->db_desc, key, NULL, level_id, 0);
		if (rep.addr != NULL) {
			if (RWLOCK_UNLOCK(&handle->db_desc->levels[level_id].guard_of_level.rx_lock) != 0)
				exit(EXIT_FAILURE);
			__sync_fetch_and_sub(&handle->db_desc->levels[level_id].active_writers, 1);

			goto finish;
		}
		if (RWLOCK_UNLOCK(&handle->db_desc->levels[level_id].guard_of_level.rx_lock) != 0)
			exit(EXIT_FAILURE);
		__sync_fetch_and_sub(&handle->db_desc->levels[level_id].active_writers, 1);
	}

finish:
	return rep.addr;
}

/* returns the addr where the value of the KV pair resides */
/* TODO: make this return the offset from MAPPED, not a pointer
 * to the offset */

void *find_key(db_handle *handle, void *key, uint32_t key_size)
{
	char buf[4000];
	void *key_buf = &(buf[0]);
	void *value;

	if (key_size <= (4000 - sizeof(uint32_t))) {
		key_buf = &(buf[0]);
		*(uint32_t *)key_buf = key_size;
		memcpy((void *)key_buf + sizeof(uint32_t), key, key_size);
		value = __find_key(handle, key_buf);
	} else {
		key_buf = malloc(key_size + sizeof(uint32_t));
		*(uint32_t *)key_buf = key_size;
		memcpy((void *)key_buf + sizeof(uint32_t), key, key_size);
		value = __find_key(handle, key_buf);
		free(key_buf);
	}

	return value;
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
int8_t update_index(index_node *node, node_header *left_child, node_header *right_child, void *key_buf)
{
	int64_t ret = 0;
	void *addr;
	void *dest_addr;
	uint64_t entry_val = 0;
	void *index_key_buf;
	int32_t middle = 0;
	int32_t start_idx = 0;
	int32_t end_idx = node->header.num_entries - 1;
	size_t num_of_bytes;

	addr = (void *)(uint64_t)node + sizeof(node_header);

	if (node->header.num_entries > 0) {
		while (1) {
			middle = (start_idx + end_idx) / 2;
			addr = (void *)(uint64_t)node + (uint64_t)sizeof(node_header) + sizeof(uint64_t) +
			       (uint64_t)(middle * 2 * sizeof(uint64_t));
			index_key_buf = (void *)(MAPPED + *(uint64_t *)addr);
			ret = key_cmp(index_key_buf, key_buf, KV_FORMAT, KV_FORMAT);
			if (ret > 0) {
				end_idx = middle - 1;
				if (start_idx > end_idx)
					// addr is the same
					break;
			} else if (ret == 0) {
				log_fatal("key already present index_key %s key_buf %s", index_key_buf + 4,
					  key_buf + 4);
				raise(SIGINT);
				exit(EXIT_FAILURE);
			} else {
				start_idx = middle + 1;
				if (start_idx > end_idx) {
					middle++;
					if (middle >= (int64_t)node->header.num_entries) {
						middle = node->header.num_entries;
						addr = (void *)(uint64_t)node + (uint64_t)sizeof(node_header) +
						       (uint64_t)(middle * 2 * sizeof(uint64_t)) + sizeof(uint64_t);
					} else
						addr += (2 * sizeof(uint64_t));
					break;
				}
			}
		}

		dest_addr = addr + (2 * sizeof(uint64_t));
		num_of_bytes = (node->header.num_entries - middle) * 2 * sizeof(uint64_t);
		memmove(dest_addr, addr, num_of_bytes);
		addr -= sizeof(uint64_t);
	} else
		addr = (void *)node + sizeof(node_header);

	/*update the entry*/
	if (left_child != 0)
		entry_val = (uint64_t)left_child - MAPPED;
	else
		entry_val = 0;

	memcpy(addr, &entry_val, sizeof(uint64_t));
	addr += sizeof(uint64_t);
	entry_val = (uint64_t)key_buf - MAPPED;
	memcpy(addr, &entry_val, sizeof(uint64_t));

	addr += sizeof(uint64_t);
	if (right_child != 0)
		entry_val = (uint64_t)right_child - MAPPED;
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
void insert_key_at_index(bt_insert_req *ins_req, index_node *node, node_header *left_child, node_header *right_child,
			 void *key_buf)
{
	void *key_addr = NULL;
	struct db_handle *handle = ins_req->metadata.handle;
	IN_log_header *d_header = NULL;
	IN_log_header *last_d_header = NULL;
	int32_t avail_space;
	int32_t req_space;
	int32_t allocated_space;

	uint32_t key_len = *(uint32_t *)key_buf;
	int8_t ret;

	// assert_index_node(node);
	if (node->header.key_log_size % KEY_BLOCK_SIZE == 0)
		avail_space = 0;
	else
		avail_space = (int32_t)KEY_BLOCK_SIZE - (node->header.key_log_size % (int32_t)KEY_BLOCK_SIZE);

	req_space = (key_len + sizeof(uint32_t));
	if (avail_space < req_space) {
		/*room not sufficient get new block*/
		allocated_space = (req_space + sizeof(IN_log_header)) / KEY_BLOCK_SIZE;
		if ((req_space + sizeof(IN_log_header)) % KEY_BLOCK_SIZE != 0)
			allocated_space++;
		allocated_space *= KEY_BLOCK_SIZE;

		if (allocated_space > KEY_BLOCK_SIZE) {
			log_info("alloc %d key block %d", allocated_space, KEY_BLOCK_SIZE);
			log_fatal("Cannot host index key larger than KEY_BLOCK_SIZE");
			raise(SIGINT);
			exit(EXIT_FAILURE);
		}

		d_header = seg_get_IN_log_block(handle->volume_desc,
						&handle->db_desc->levels[ins_req->metadata.level_id],
						ins_req->metadata.tree_id);

		d_header->next = NULL;
		last_d_header = (IN_log_header *)(MAPPED + (uint64_t)node->header.last_IN_log_header);
		last_d_header->next = (void *)((uint64_t)d_header - MAPPED);
		node->header.last_IN_log_header = last_d_header->next;
		node->header.key_log_size +=
			(avail_space + sizeof(IN_log_header)); /* position the log to the newly added block*/
	}
	/* put the KV now */
	key_addr = (void *)MAPPED + (uint64_t)node->header.last_IN_log_header +
		   (uint64_t)(node->header.key_log_size % KEY_BLOCK_SIZE);
	memcpy(key_addr, key_buf, sizeof(uint32_t) + key_len); /*key length */
	node->header.key_log_size += (sizeof(uint32_t) + key_len);

	ret = update_index(node, left_child, right_child, key_addr);
	if (ret)
		node->header.num_entries++;
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
	node_header *left_child;
	node_header *right_child;
	node_header *tmp_index;
	void *full_addr;
	void *key_buf;
	uint32_t i = 0;
	// assert_index_node(node);
	result.left_child = (node_header *)seg_get_index_node(
		ins_req->metadata.handle->volume_desc,
		&ins_req->metadata.handle->db_desc->levels[ins_req->metadata.level_id], ins_req->metadata.tree_id,
		INDEX_SPLIT);

	result.right_child = (node_header *)seg_get_index_node(
		ins_req->metadata.handle->volume_desc,
		&ins_req->metadata.handle->db_desc->levels[ins_req->metadata.level_id], ins_req->metadata.tree_id,
		INDEX_SPLIT);
	// result.left_child->v1++; /*lamport counter*/
	// result.right_child->v1++; /*lamport counter*/

	/*initialize*/
	full_addr = (void *)((uint64_t)node + (uint64_t)sizeof(node_header));
	/*set node heights*/
	result.left_child->height = node->height;
	result.right_child->height = node->height;

	for (i = 0; i < node->num_entries; i++) {
		if (i < node->num_entries / 2)
			tmp_index = result.left_child;
		else
			tmp_index = result.right_child;

		left_child = (node_header *)REAL_ADDRESS(*(uint64_t *)full_addr);
		full_addr += sizeof(uint64_t);
		key_buf = (void *)REAL_ADDRESS(*(uint64_t *)full_addr);
		full_addr += sizeof(uint64_t);
		right_child = (node_header *)REAL_ADDRESS(*(uint64_t *)full_addr);

		if (i == node->num_entries / 2) {
			result.middle_key_buf = key_buf;
			continue; /*middle key not needed, is going to the upper level*/
		}

		insert_key_at_index(ins_req, (index_node *)tmp_index, left_child, right_child, key_buf);
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
	enum log_category cat = ins_req->metadata.cat;
	int append_tolog = ins_req->metadata.append_to_log; //&&
		//(cat == SMALL_INLOG || cat == SMALL_INPLACE || // Needed for consistency purposes
		//cat == MEDIUM_INLOG ||  cat == BIG_INLOG));
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

	if (ret == INSERT /* || ret == FOUND */) {
		int measure_level_used_space = cat == BIG_INLOG || cat == SMALL_INLOG;
		int medium_inlog = cat == MEDIUM_INLOG && level_id != LEVEL_MEDIUM_INPLACE;

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
	return split_functions[req->metadata.special_split]((struct bt_dynamic_leaf_node *)node, leaf_size, req);
}

/**
 *	gesalous added at 30/05/2014 14:00, performs a binary search at an
 *index(root, internal node) and returns the index. We have
 *  a separate search function for index and leaves due to their different
 *format
 *  Updated (26/10/2016 17:05) key_buf can be in two formats
 *
 **/
void *_index_node_binary_search(index_node *node, void *key_buf, char query_key_format)
{
	void *addr = NULL;
	void *index_key_buf;
	int64_t ret;
	int32_t middle = 0;
	int32_t start_idx = 0;
	int32_t end_idx = node->header.num_entries - 1;
	int32_t numberOfEntriesInNode = node->header.num_entries;

	while (numberOfEntriesInNode > 0) {
		middle = (start_idx + end_idx) / 2;

		if (numberOfEntriesInNode > index_order || middle < 0 || middle >= numberOfEntriesInNode)
			return NULL;

		addr = &(node->p[middle].pivot);
		index_key_buf = (void *)(MAPPED + *(uint64_t *)addr);
		ret = key_cmp(index_key_buf, key_buf, KV_FORMAT, query_key_format);
		if (ret == 0) {
			// log_debug("I passed from this corner case1 %s",
			// (char*)(index_key_buf+4));
			addr = &(node->p[middle].right);
			break;
		} else if (ret > 0) {
			end_idx = middle - 1;
			if (start_idx > end_idx) {
				// log_debug("I passed from this corner case2 %s",
				// (char*)(index_key_buf+4));
				addr = &(node->p[middle].left[0]);
				middle--;
				break;
			}
		} else { /* ret < 0 */
			start_idx = middle + 1;
			if (start_idx > end_idx) {
				// log_debug("I passed from this corner case3 %s",
				// (char*)(index_key_buf+4));
				addr = &(node->p[middle].right);
				middle++;
				break;
			}
		}
	}

	if (middle < 0) {
		// log_debug("I passed from this corner case4 %s",
		// (char*)(index_key_buf+4));
		addr = &(node->p[0].left[0]);
	} else if (middle >= (int64_t)node->header.num_entries) {
		// log_debug("I passed from this corner case5 %s",
		// (char*)(index_key_buf+4));
		/* log_debug("I passed from this corner case2 %s",
* (char*)(index_key_buf+4)); */
		addr = &(node->p[node->header.num_entries - 1].right);
	}
	// log_debug("END");
	return addr;
}
/*functions used for debugging*/
void assert_index_node(node_header *node)
{
	uint32_t k;
	void *key_tmp;
	void *key_tmp_prev = NULL;
	void *addr;
	node_header *child;
	addr = (void *)(uint64_t)node + (uint64_t)sizeof(node_header);
	if (node->num_entries == 0)
		return;
	//	if(node->height > 1)
	//	log_info("Checking node of height %lu\n",node->height);
	for (k = 0; k < node->num_entries; k++) {
		/*check child type*/
		child = (node_header *)(MAPPED + *(uint64_t *)addr);
		if (child->type != rootNode && child->type != internalNode && child->type != leafNode &&
		    child->type != leafRootNode) {
			log_fatal("corrupted child at index for child %llu type is %d\n",
				  (long long unsigned)(uint64_t)child - MAPPED, child->type);
			raise(SIGINT);
			exit(EXIT_FAILURE);
		}
		addr += sizeof(uint64_t);
		key_tmp = (void *)MAPPED + *(uint64_t *)addr;
		// log_info("key %s\n", (char *)key_tmp + sizeof(int32_t));

		if (key_tmp_prev != NULL) {
			if (key_cmp(key_tmp_prev, key_tmp, KV_FORMAT, KV_FORMAT) >= 0) {
				log_fatal("corrupted index %d:%s something else %d:%s\n", *(uint32_t *)key_tmp_prev,
					  key_tmp_prev + 4, *(uint32_t *)key_tmp, key_tmp + 4);
				raise(SIGINT);
				exit(EXIT_FAILURE);
			}
		}
		if (key_tmp_prev)
			log_fatal("corrupted index %*s something else %*s\n", *(uint32_t *)key_tmp_prev,
				  key_tmp_prev + 4, *(uint32_t *)key_tmp, key_tmp + 4);

		key_tmp_prev = key_tmp;
		addr += sizeof(uint64_t);
	}
	child = (node_header *)(MAPPED + *(uint64_t *)addr);
	if (child->type != rootNode && child->type != internalNode && child->type != leafNode &&
	    child->type != leafRootNode) {
		log_fatal("Corrupted last child at index");
		exit(EXIT_FAILURE);
	}
	// printf("\t\tpointer to last child %llu\n", (LLU)(uint64_t)child-MAPPED);
}

uint64_t hash(uint64_t x)
{
	x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
	x = x ^ (x >> 31);
	return x;
}

lock_table *_find_position(lock_table **table, node_header *node)
{
	unsigned long position;
	lock_table *node_lock;

	if (node->height < 0 || node->height >= MAX_HEIGHT) {
		log_fatal("MAX_HEIGHT exceeded %d rearrange values in size_per_height array ", node->height);
		raise(SIGINT);
		exit(EXIT_FAILURE);
	}

	position = hash((uint64_t)node) % size_per_height[node->height];
	// log_info("node %llu height %d position %lu size of height %d", node,
	// node->height, position, size_per_height[node->height]);
	node_lock = table[node->height];
	return &node_lock[position];
}

void _unlock_upper_levels(lock_table *node[], unsigned size, unsigned release)
{
	unsigned i;
	for (i = release; i < size; ++i)
		if (RWLOCK_UNLOCK(&node[i]->rx_lock) != 0) {
			log_fatal("ERROR unlocking");
			exit(EXIT_FAILURE);
		}
}

int is_split_needed(void *node, bt_insert_req *req, uint32_t leaf_size)
{
	node_header *header = (node_header *)node;
	int64_t num_entries = header->num_entries;
	uint32_t height = header->height;
	enum log_category cat = req->metadata.cat;
	uint8_t level_id = req->metadata.level_id;

	if (height != 0) {
		uint8_t split_index_node = num_entries >= index_order;
		return split_index_node;
	}

	int status;

	if (cat == BIG_INLOG || (cat == MEDIUM_INLOG && level_id != LEVEL_MEDIUM_INPLACE) || cat == SMALL_INLOG)
		status = KV_INLOG;
	else
		status = KV_INPLACE;

	return check_dynamic_leaf_split(node, leaf_size, req->metadata.kv_size, req->metadata.level_id, status, cat);
}

static uint8_t concurrent_insert(bt_insert_req *ins_req)
{
	/*The array with the locks that belong to this thread from upper levels*/
	lock_table *upper_level_nodes[MAX_HEIGHT];
	struct bt_rebalance_result split_res;
	lock_table *lock;
	void *next_addr;
	pr_system_catalogue *mem_catalogue;
	volume_descriptor *volume_desc;
	db_descriptor *db_desc;

	index_node *new_index_node;
	node_header *node_copy;
	node_header *father;
	node_header *son;
	unsigned size; /*Size of upper_level_nodes*/
	unsigned release; /*Counter to know the position that releasing should begin*/

	lock_table *guard_of_level;
	int64_t *num_level_writers;
	uint32_t level_id;

	volume_desc = ins_req->metadata.handle->volume_desc;
	db_desc = ins_req->metadata.handle->db_desc;
	level_id = ins_req->metadata.level_id;
	guard_of_level = &(db_desc->levels[level_id].guard_of_level);
	num_level_writers = &db_desc->levels[level_id].active_writers;

	release = 0;
	size = 0;

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
		exit(EXIT_FAILURE);
	}
	/*now look which is the active_tree of L0*/
	if (ins_req->metadata.level_id == 0) {
		ins_req->metadata.tree_id = ins_req->metadata.handle->db_desc->levels[0].active_tree;
	}
	/*level's guard lock aquired*/
	upper_level_nodes[size++] = guard_of_level;
	/*mark your presence*/
	__sync_fetch_and_add(num_level_writers, 1);
	mem_catalogue = ins_req->metadata.handle->volume_desc->mem_catalogue;

	father = NULL;

	/*cow logic follows*/
	if (db_desc->levels[level_id].root_w[ins_req->metadata.tree_id] == NULL) {
		if (db_desc->levels[level_id].root_r[ins_req->metadata.tree_id] != NULL) {
			if (db_desc->levels[level_id].root_r[ins_req->metadata.tree_id]->type == rootNode) {
				index_node *t = seg_get_index_node_header(ins_req->metadata.handle->volume_desc,
									  &db_desc->levels[level_id],
									  ins_req->metadata.tree_id);
				memcpy(t, db_desc->levels[level_id].root_r[ins_req->metadata.tree_id], INDEX_NODE_SIZE);
				t->header.epoch = mem_catalogue->epoch;
				db_desc->levels[level_id].root_w[ins_req->metadata.tree_id] = (node_header *)t;
			} else {
				/*Tree too small consists only of 1 leafRootNode*/
				leaf_node *t = seg_get_leaf_node_header(ins_req->metadata.handle->volume_desc,
									&db_desc->levels[level_id],
									ins_req->metadata.tree_id);

				memcpy(t, db_desc->levels[level_id].root_r[ins_req->metadata.tree_id],
				       db_desc->levels[level_id].leaf_size);

				t->header.epoch = mem_catalogue->epoch;
				db_desc->levels[level_id].root_w[ins_req->metadata.tree_id] = (node_header *)t;
			}
		} else {
			/*we are allocating a new tree*/

			log_info("Allocating new active tree %d for level id %d epoch is at %llu",
				 ins_req->metadata.tree_id, level_id, (long long unsigned)mem_catalogue->epoch);

			leaf_node *t = seg_get_leaf_node(ins_req->metadata.handle->volume_desc,
							 &db_desc->levels[level_id], ins_req->metadata.tree_id);

			t->header.type = leafRootNode;
			t->header.epoch = mem_catalogue->epoch;
			db_desc->levels[level_id].root_w[ins_req->metadata.tree_id] = (node_header *)t;
		}
	}
	/*acquiring lock of the current root*/
	lock = _find_position(db_desc->levels[level_id].level_lock_table,
			      db_desc->levels[level_id].root_w[ins_req->metadata.tree_id]);
	if (RWLOCK_WRLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR locking");
		exit(EXIT_FAILURE);
	}

	upper_level_nodes[size++] = lock;
	son = db_desc->levels[level_id].root_w[ins_req->metadata.tree_id];

	while (1) {
		/*Check if father is safe it should be*/
		if (father) {
			unsigned int father_order;
			(void)father_order;
			if (father->type == leafNode || father->type == leafRootNode)
				father_order = db_desc->levels[level_id].leaf_offsets.kv_entries;
			else
				father_order = index_order;

			assert(father->epoch > volume_desc->dev_catalogue->epoch);
			assert(father->num_entries < father_order);
		}

		if (is_split_needed(son, ins_req, db_desc->levels[level_id].leaf_size)) {
			/*Overflow split*/
			if (son->height > 0) {
				split_res = split_index(son, ins_req);
				/*node has splitted, free it*/
				seg_free_index_node(ins_req->metadata.handle->volume_desc, &db_desc->levels[level_id],
						    ins_req->metadata.tree_id, (index_node *)son);
				// free_logical_node(&(req->allocator_desc), son);
			} else {
				if (reorganize_dynamic_leaf((struct bt_dynamic_leaf_node *)son,
							    db_desc->levels[level_id].leaf_size, ins_req))
					goto release_and_retry;

				split_res = split_leaf(ins_req, (leaf_node *)son);

				if ((uint64_t)son != (uint64_t)split_res.left_child) {
					/*cow happened*/
					seg_free_leaf_node(ins_req->metadata.handle->volume_desc,
							   &ins_req->metadata.handle->db_desc->levels[level_id],
							   ins_req->metadata.tree_id, (leaf_node *)son);
					/*fix the dangling lamport*/
				}
			}

			/*Insert pivot at father*/
			if (father != NULL) {
				/*lamport counter*/
				assert(father->epoch > ins_req->metadata.handle->volume_desc->dev_catalogue->epoch);

				insert_key_at_index(ins_req, (index_node *)father, split_res.left_child,
						    split_res.right_child, split_res.middle_key_buf);

				/*lamport counter*/
			} else {
				/*Root was splitted*/
				// log_info("new root");
				new_index_node = seg_get_index_node(ins_req->metadata.handle->volume_desc,
								    &db_desc->levels[level_id],
								    ins_req->metadata.tree_id, NEW_ROOT);
				new_index_node->header.height = db_desc->levels[ins_req->metadata.level_id]
									.root_w[ins_req->metadata.tree_id]
									->height +
								1;

				new_index_node->header.type = rootNode;

				insert_key_at_index(ins_req, new_index_node, split_res.left_child,
						    split_res.right_child, split_res.middle_key_buf);
				/*new write root of the tree*/
				db_desc->levels[level_id].root_w[ins_req->metadata.tree_id] =
					(node_header *)new_index_node;
			}
			goto release_and_retry;
		} else if (son->epoch <= volume_desc->dev_catalogue->epoch) {
			/*Cow*/
			if (son->height > 0) {
				node_copy = (node_header *)seg_get_index_node_header(
					ins_req->metadata.handle->volume_desc, &db_desc->levels[level_id],
					ins_req->metadata.tree_id);

				memcpy(node_copy, son, INDEX_NODE_SIZE);
				seg_free_index_node_header(ins_req->metadata.handle->volume_desc,
							   &db_desc->levels[level_id], ins_req->metadata.tree_id, son);
			} else {
				node_copy = (node_header *)seg_get_leaf_node_header(
					ins_req->metadata.handle->volume_desc, &db_desc->levels[level_id],
					ins_req->metadata.tree_id);

				memcpy(node_copy, son, db_desc->levels[level_id].leaf_size);
				/* Add static and dynamic layout free operations*/
				seg_free_leaf_node(ins_req->metadata.handle->volume_desc, &db_desc->levels[level_id],
						   ins_req->metadata.tree_id, (leaf_node *)son);
			}
			node_copy->epoch = volume_desc->mem_catalogue->epoch;
			son = node_copy;
			/*Update father's pointer*/
			if (father != NULL)
				*(uint64_t *)next_addr = (uint64_t)node_copy - MAPPED;
			else /*We COWED the root*/
				db_desc->levels[level_id].root_w[ins_req->metadata.tree_id] = node_copy;

			goto release_and_retry;
		}

		if (son->height == 0)
			break;
		/*Finding the next node to traverse*/
		next_addr = _index_node_binary_search((index_node *)son, ins_req->key_value_buf,
						      ins_req->metadata.key_format);
		father = son;
		/*Taking the lock of the next node before its traversal*/
		lock = _find_position(ins_req->metadata.handle->db_desc->levels[level_id].level_lock_table,
				      (node_header *)(MAPPED + *(uint64_t *)next_addr));
		upper_level_nodes[size++] = lock;
		if (RWLOCK_WRLOCK(&lock->rx_lock) != 0) {
			log_fatal("ERROR unlocking reason follows rc");
			exit(EXIT_FAILURE);
		}
		/*Node acquired */
		ins_req->metadata.reorganized_leaf_pos_INnode = next_addr;
		son = (node_header *)(MAPPED + *(uint64_t *)next_addr);

		/*if the node is not safe hold its ancestor's lock else release locks from
    ancestors */

		if (!(son->epoch <= volume_desc->dev_catalogue->epoch ||
		      is_split_needed(son, ins_req, db_desc->levels[level_id].leaf_size))) {
			_unlock_upper_levels(upper_level_nodes, size - 1, release);
			release = size - 1;
		}
	}
	/*Succesfully reached a bin (bottom internal node)*/
	if (son->type != leafRootNode)
		assert((size - 1) - release == 0);

	if (son->height != 0) {
		log_fatal("FATAL son corrupted");
		exit(EXIT_FAILURE);
	}

	assert(son->epoch > ins_req->metadata.handle->volume_desc->dev_catalogue->epoch);

	insert_KV_at_leaf(ins_req, son);
	/*Unlock remaining locks*/
	_unlock_upper_levels(upper_level_nodes, size, release);
	__sync_fetch_and_sub(num_level_writers, 1);
	return SUCCESS;
}

static uint8_t writers_join_as_readers(bt_insert_req *ins_req)
{
	/*The array with the locks that belong to this thread from upper levels*/
	lock_table *upper_level_nodes[MAX_HEIGHT];
	void *next_addr;
	volume_descriptor *volume_desc;
	db_descriptor *db_desc;
	node_header *son;
	lock_table *lock;

	unsigned size; /*Size of upper_level_nodes*/
	unsigned release; /*Counter to know the position that releasing should begin*/
	// remove some warnings here
	uint32_t level_id;
	lock_table *guard_of_level;
	int64_t *num_level_writers;
	int ret = 0;
	volume_desc = ins_req->metadata.handle->volume_desc;
	db_desc = ins_req->metadata.handle->db_desc;
	level_id = ins_req->metadata.level_id;
	guard_of_level = &db_desc->levels[level_id].guard_of_level;
	num_level_writers = &db_desc->levels[level_id].active_writers;

	size = 0;
	release = 0;

	/*
* Caution no retry here, we just optimistically try to insert,
* if we donot succeed we try with concurrent_insert
*/
	/*Acquire read guard lock*/
	ret = RWLOCK_RDLOCK(&guard_of_level->rx_lock);
	if (ret) {
		log_fatal("Failed to acquire guard lock for db: %s", db_desc->db_name);
		perror("Reason: ");
		exit(EXIT_FAILURE);
	}
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
		return FAILURE;
	}

	/*acquire read lock of the current root*/
	lock = _find_position(db_desc->levels[level_id].level_lock_table,
			      db_desc->levels[level_id].root_w[ins_req->metadata.tree_id]);

	if (RWLOCK_RDLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR locking");
		exit(EXIT_FAILURE);
	}

	upper_level_nodes[size++] = lock;
	son = db_desc->levels[level_id].root_w[ins_req->metadata.tree_id];
	while (1) {
		if (is_split_needed(son, ins_req, db_desc->levels[level_id].leaf_size)) {
			/*failed needs split*/
			_unlock_upper_levels(upper_level_nodes, size, release);
			__sync_fetch_and_sub(num_level_writers, 1);
			return FAILURE;
		} else if (son->epoch <= volume_desc->dev_catalogue->epoch) {
			/*failed needs COW*/
			_unlock_upper_levels(upper_level_nodes, size, release);
			__sync_fetch_and_sub(num_level_writers, 1);
			return FAILURE;
		}
		/*Find the next node to traverse*/
		next_addr = _index_node_binary_search((index_node *)son, ins_req->key_value_buf,
						      ins_req->metadata.key_format);
		son = (node_header *)(MAPPED + *(uint64_t *)next_addr);

		if (son->height == 0)
			break;
		/*Acquire the lock of the next node before its traversal*/
		lock = _find_position(db_desc->levels[level_id].level_lock_table,
				      (node_header *)(MAPPED + *(uint64_t *)next_addr));
		upper_level_nodes[size++] = lock;

		if (RWLOCK_RDLOCK(&lock->rx_lock) != 0) {
			log_fatal("ERROR unlocking");
			exit(EXIT_FAILURE);
		}
		/*lock of node acquired */
		_unlock_upper_levels(upper_level_nodes, size - 1, release);
		release = size - 1;
	}

	lock = _find_position(db_desc->levels[level_id].level_lock_table,
			      (node_header *)(MAPPED + *(uint64_t *)next_addr));
	upper_level_nodes[size++] = lock;

	if (RWLOCK_WRLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR unlocking");
		exit(EXIT_FAILURE);
	}

	if (is_split_needed(son, ins_req, db_desc->levels[level_id].leaf_size) ||
	    son->epoch <= volume_desc->dev_catalogue->epoch) {
		_unlock_upper_levels(upper_level_nodes, size, release);
		__sync_fetch_and_sub(num_level_writers, 1);
		return FAILURE;
	}

	/*Succesfully reached a bin (bottom internal node)*/
	if (son->height != 0) {
		log_fatal("FATAL son corrupted");
		exit(EXIT_FAILURE);
	}

	insert_KV_at_leaf(ins_req, son);
	/*Unlock remaining locks*/
	_unlock_upper_levels(upper_level_nodes, size, release);
	__sync_fetch_and_sub(num_level_writers, 1);
	return SUCCESS;
}

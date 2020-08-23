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
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <assert.h>
#include <emmintrin.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <log.h>

#include "btree.h"
#include "gc.h"
#include "segment_allocator.h"
#include "static_leaf.h"
#include "dynamic_leaf.h"
#include "../../utilities/macros.h"
#include "../allocator/dmap-ioctl.h"
#include "../scanner/scanner.h"
#include "conf.h"

#define PREFIX_STATISTICS_NO
#define MIN(x, y) ((x > y) ? (y) : (x))

#define DEVICE_BLOCK_SIZE 4096
#define COULD_NOT_FIND_DB 0x02

int32_t index_order;
extern char *pointer_to_kv_in_log;

uint64_t countgoto = 0;
pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_spinlock_t log_buffer_lock;
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
void _sent_flush_command_to_replica(db_descriptor *db_desc, int padded_space, int SYNC);

struct bt_rebalance_result split_leaf(bt_insert_req *req, leaf_node *node);

/*Buffering aware functions*/
void spill_buffer(void *_spill_req);

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

int64_t _tucana_key_cmp(void *index_key_buf, void *query_key_buf, char index_key_format, char query_key_format)
{
	int64_t ret;
	uint32_t size;
	/*we need the left most entry*/
	if (query_key_buf == NULL)
		return 1;

	if (index_key_format == KV_FORMAT && query_key_format == KV_FORMAT) {
		size = *(uint32_t *)index_key_buf;
		if (size > *(uint32_t *)query_key_buf)
			size = *(uint32_t *)query_key_buf;

		ret = memcmp((void *)index_key_buf + sizeof(uint32_t), (void *)query_key_buf + sizeof(uint32_t), size);
		if (ret != 0)
			return ret;
		else if (ret == 0 && *(uint32_t *)index_key_buf == *(uint32_t *)query_key_buf)
			return 0;

		else { /*larger key wins*/

			if (*(uint32_t *)index_key_buf > *(uint32_t *)query_key_buf)
				return 1;
			else
				return -1;
		}
	} else if (index_key_format == KV_FORMAT && query_key_format == KV_PREFIX) {
		if (*(uint32_t *)index_key_buf >= PREFIX_SIZE)
			ret = prefix_compare(index_key_buf + sizeof(uint32_t), query_key_buf, PREFIX_SIZE);
		else // check here TODO
			ret = prefix_compare(index_key_buf + sizeof(uint32_t), query_key_buf,
					     *(int32_t *)index_key_buf);
		if (ret == 0) { /* we have a tie, prefix didn't help, fetch query_key form KV log*/

			query_key_buf = (void *)(*(uint64_t *)(query_key_buf + PREFIX_SIZE));

			size = *(uint32_t *)index_key_buf;
			if (size > *(uint32_t *)query_key_buf)
				size = *(uint32_t *)query_key_buf;

			ret = memcmp((void *)index_key_buf + sizeof(uint32_t), (void *)query_key_buf + sizeof(uint32_t),
				     size);

			if (ret != 0)
				return ret;
			else if (ret == 0 && *(uint32_t *)index_key_buf == *(uint32_t *)query_key_buf)
				return 0;

			else { /*larger key wins*/
				if (*(uint32_t *)index_key_buf > *(uint32_t *)query_key_buf)
					return 1;
				else
					return -1;
			}
		} else
			return ret;
	} else if (index_key_format == KV_PREFIX && query_key_format == KV_FORMAT) {
		if (*(uint32_t *)query_key_buf >= PREFIX_SIZE)
			ret = prefix_compare(index_key_buf, query_key_buf + sizeof(uint32_t), PREFIX_SIZE);
		else // check here TODO
			ret = prefix_compare(index_key_buf, query_key_buf + sizeof(uint32_t),
					     *(int32_t *)query_key_buf);
		if (ret == 0) { /* we have a tie, prefix didn't help, fetch query_key form KV log*/
			index_key_buf = (void *)(*(uint64_t *)(index_key_buf + PREFIX_SIZE));

			size = *(uint32_t *)query_key_buf;
			if (size > *(uint32_t *)index_key_buf)
				size = *(uint32_t *)index_key_buf;

			ret = memcmp((void *)index_key_buf + sizeof(uint32_t), (void *)query_key_buf + sizeof(uint32_t),
				     size);
			if (ret != 0)
				return ret;
			else if (ret == 0 && *(uint32_t *)index_key_buf == *(uint32_t *)query_key_buf)
				return 0;
			else { /*larger key wins*/

				if (*(uint32_t *)index_key_buf > *(uint32_t *)query_key_buf)
					return 1;
				else
					return -1;
			}
		} else
			return ret;
	} else {
		/*KV_PREFIX and KV_PREFIX*/
		ret = prefix_compare(index_key_buf, query_key_buf, PREFIX_SIZE);
		if (ret != 0)
			return ret;
		/*full comparison*/
		void *index_full_key = (void *)*(uint64_t *)(index_key_buf + PREFIX_SIZE);
		void *query_full_key = (void *)*(uint64_t *)(query_key_buf + PREFIX_SIZE);
		uint32_t size = *(uint32_t *)index_full_key;
		char index_smaller = 0;
		size = *(uint32_t *)query_full_key;
		if (size > *(uint32_t *)index_full_key) {
			size = *(uint32_t *)index_full_key;
			index_smaller = 1;
		}
		ret = memcmp(index_full_key, query_full_key, size);
		if (ret != 0)
			return ret;
		if (index_smaller)
			return -1;
		else
			return 1;
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

static void init_leaf_sizes_perlevel(level_descriptor *level, int level_id)
{
	enum bt_layout leaf_layout_per_level[MAX_LEVELS] = { LEVEL0_LEAF_LAYOUT, LEVEL1_LEAF_LAYOUT, LEVEL2_LEAF_LAYOUT,
							     LEVEL3_LEAF_LAYOUT, LEVEL4_LEAF_LAYOUT, LEVEL5_LEAF_LAYOUT,
							     LEVEL6_LEAF_LAYOUT, LEVEL7_LEAF_LAYOUT };

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
	level->node_layout = leaf_layout_per_level[level_id];
}

static void destroy_level_locktable(db_descriptor *database, uint8_t level_id)
{
	for (int i = 0; i < MAX_HEIGHT; ++i)
		free(&database->levels[level_id].level_lock_table[i]);
}

static void pr_init_logs(db_descriptor *db_desc, pr_db_entry *db_entry, volume_descriptor *volume_desc)
{
	log_info("Primary db initializing KV log");

	db_desc->big_log_head = seg_get_raw_log_segment(volume_desc);
	db_desc->big_log_tail = db_desc->big_log_head;
	db_desc->big_log_tail->segment_id = 0;
	db_desc->big_log_tail->next_segment = NULL;
	db_desc->big_log_tail->prev_segment = NULL;
	db_desc->big_log_size = sizeof(segment_header);
	db_desc->big_log_head_offset = sizeof(segment_header);
	db_desc->big_log_tail_offset = sizeof(segment_header);
	/*get a page for commit_log info*/
	db_desc->commit_log->big_log_head = (segment_header *)ABSOLUTE_ADDRESS(db_desc->big_log_head);
	db_desc->commit_log->big_log_tail = (segment_header *)ABSOLUTE_ADDRESS(db_desc->big_log_tail);
	db_desc->commit_log->big_log_size = db_desc->big_log_size;

	/* Medium log */
	db_desc->medium_log_head = seg_get_raw_log_segment(volume_desc);
	db_desc->medium_log_tail = db_desc->medium_log_head;
	db_desc->medium_log_tail->segment_id = 0;
	db_desc->medium_log_tail->next_segment = NULL;
	db_desc->medium_log_tail->prev_segment = NULL;
	db_desc->medium_log_size = sizeof(segment_header);
	db_desc->medium_log_head_offset = sizeof(segment_header);
	db_desc->medium_log_tail_offset = sizeof(segment_header);
	db_desc->commit_log->medium_log_head = (segment_header *)ABSOLUTE_ADDRESS(db_desc->medium_log_head);
	db_desc->commit_log->medium_log_tail = (segment_header *)ABSOLUTE_ADDRESS(db_desc->medium_log_tail);
	db_desc->commit_log->medium_log_size = db_desc->medium_log_size;

	/* Small log */
	db_desc->small_log_head = seg_get_raw_log_segment(volume_desc);
	db_desc->small_log_tail = db_desc->small_log_head;
	db_desc->small_log_tail->segment_id = 0;
	db_desc->small_log_tail->next_segment = NULL;
	db_desc->small_log_tail->prev_segment = NULL;
	db_desc->small_log_size = sizeof(segment_header);
	db_desc->small_log_head_offset = sizeof(segment_header);
	db_desc->small_log_tail_offset = sizeof(segment_header);
	db_desc->commit_log->small_log_head = (segment_header *)ABSOLUTE_ADDRESS(db_desc->small_log_head);
	db_desc->commit_log->small_log_tail = (segment_header *)ABSOLUTE_ADDRESS(db_desc->small_log_tail);
	db_desc->commit_log->small_log_size = db_desc->small_log_size;
	db_desc->lsn = db_desc->commit_log->lsn;

	/*persist commit log information, this location stays permanent, there is no
		 * need to rewrite it during snapshot()*/
	db_entry->commit_log = ABSOLUTE_ADDRESS(db_desc->commit_log);
}

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

	log_info("Big log segments first: %llu last: %llu log_size %llu", (LLU)db_desc->big_log_head,
		 (LLU)db_desc->big_log_tail, (LLU)db_desc->big_log_size);
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

	log_info("Medium log segments first: %llu last: %llu log_size %llu", (LLU)db_desc->medium_log_head,
		 (LLU)db_desc->medium_log_tail, (LLU)db_desc->medium_log_size);
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

	log_info("Small log segments first: %llu last: %llu log_size %llu", (LLU)db_desc->small_log_head,
		 (LLU)db_desc->small_log_tail, (LLU)db_desc->small_log_size);
	log_info("Small L0 start log offset %llu end %llu", db_desc->small_log_head_offset,
		 db_desc->small_log_tail_offset);
}

void fill_spill_req(db_handle *handle, bt_spill_request *spill_req, uint64_t curr_level_size, int level_id,
		    int to_spill_tree_id)
{
	spill_req->db_desc = handle->db_desc;
	spill_req->volume_desc = handle->volume_desc;
	spill_req->aggregate_level_size = curr_level_size;
	spill_req->src_level = level_id;
	spill_req->dst_level = level_id + 1;
	spill_req->src_tree = to_spill_tree_id;
	spill_req->dst_tree = 0;
	spill_req->start_key = NULL;
	spill_req->end_key = NULL;
}

void enqueue_level_forcompaction(struct compaction_pairs *pending_compactions, int curr_level_id)
{
	int dst_level = curr_level_id + 1;
	int level_already_pending, enqueue_index = -1;

	for (int i = 0; i < MAX_LEVELS; ++i) {
		level_already_pending = pending_compactions[i].src_level == curr_level_id ||
					pending_compactions[i].dst_level == curr_level_id ||
					pending_compactions[i].src_level == dst_level ||
					pending_compactions[i].dst_level == dst_level;

		if (enqueue_index == -1 && pending_compactions[i].src_level == -1)
			enqueue_index = i;

		if (level_already_pending)
			return;
	}

	if (!level_already_pending) {
		pending_compactions[enqueue_index].src_level = curr_level_id;
		pending_compactions[enqueue_index].dst_level = dst_level;
	}
}

void dequeue_level_forcompaction(struct compaction_pairs *pending_compactions, int curr_level_id)
{
	for (int i = 0; i < MAX_LEVELS; ++i) {
		if (pending_compactions[i].src_level == curr_level_id) {
			pending_compactions[i].src_level = pending_compactions[i].dst_level = -1;
			return;
		}
	}
}

void enqueue_ongoing_compaction(struct compaction_pairs *ongoing_compactions, int curr_level_id)
{
	for (int i = 0; i < MAX_LEVELS; ++i) {
		if (ongoing_compactions[i].src_level == -1) {
			ongoing_compactions[i].src_level = curr_level_id;
			ongoing_compactions[i].dst_level = curr_level_id + 1;
			return;
		}
	}
}

void dequeue_ongoing_compaction(struct compaction_pairs *ongoing_compactions, int curr_level_id)
{
	for (int i = 0; i < MAX_LEVELS; ++i) {
		if (ongoing_compactions[i].src_level == curr_level_id) {
			ongoing_compactions[i].src_level = -1;
			ongoing_compactions[i].dst_level = -1;
			return;
		}
	}
	assert(0);
}

bt_spill_request *prepare_compaction_metadata(db_handle *handle, int curr_level_id)
{
	db_descriptor *db_desc = handle->db_desc;
	bt_spill_request *spill_req = malloc(sizeof(bt_spill_request));
	uint64_t curr_level_size;
	int new_active_tree = db_desc->levels[0].active_tree == 0 ? 1 : 0;
	int to_spill_tree_id = 0;
	uint8_t dst_level = curr_level_id + 1;

	/* Level 0 is a special case because we need to employ double buffering to serve clients without blocking when possible.
	 * For levels > 0 we don't want to employ double buffering atm because if we do then that's tiering. */
	if (curr_level_id == 0) {
		to_spill_tree_id = db_desc->levels[curr_level_id].active_tree;
		curr_level_size = db_desc->levels[curr_level_id].actual_level_size;
		assert(curr_level_size >= db_desc->levels[curr_level_id].max_level_size);

		assert(spill_req);
		fill_spill_req(handle, spill_req, curr_level_size, curr_level_id, to_spill_tree_id);

		/*set source*/
		if (db_desc->levels[curr_level_id].root_w[to_spill_tree_id] != NULL)
			spill_req->src_root = db_desc->levels[curr_level_id].root_w[to_spill_tree_id];
		else
			spill_req->src_root = db_desc->levels[curr_level_id].root_r[to_spill_tree_id];


		if (db_desc->levels[curr_level_id].tree_status[spill_req->src_tree] == NO_SPILLING &&
		    db_desc->levels[dst_level].tree_status[spill_req->dst_tree] == NO_SPILLING) {
			db_desc->levels[dst_level].tree_status[spill_req->dst_tree] = SPILLING_IN_PROGRESS;
			db_desc->levels[curr_level_id].tree_status[spill_req->src_tree] = SPILLING_IN_PROGRESS;
			db_desc->levels[curr_level_id].active_tree = new_active_tree;
			db_desc->levels[curr_level_id].actual_level_size = 0;
			return spill_req;
		} else {
			MUTEX_LOCK(&db_desc->compaction_structs_lock);
			enqueue_level_forcompaction(db_desc->pending_compactions, curr_level_id);
			MUTEX_UNLOCK(&db_desc->compaction_structs_lock);
		}
	} else {
		to_spill_tree_id = db_desc->levels[curr_level_id].active_tree;
		curr_level_size = db_desc->levels[curr_level_id].actual_level_size;
		/*  Since we don't double buffer levels > 0 to_spill_tree_id must always be 0. */
		assert(!to_spill_tree_id);
		assert(curr_level_size >= db_desc->levels[curr_level_id].max_level_size);
		assert(spill_req);
		fill_spill_req(handle, spill_req, curr_level_size, curr_level_id, to_spill_tree_id);

		/*set source*/
		if (db_desc->levels[curr_level_id].root_w[to_spill_tree_id] != NULL)
			spill_req->src_root = db_desc->levels[curr_level_id].root_w[to_spill_tree_id];
		else
			spill_req->src_root = db_desc->levels[curr_level_id].root_r[to_spill_tree_id];

		if (db_desc->levels[curr_level_id].tree_status[spill_req->src_tree] == NO_SPILLING &&
		    db_desc->levels[dst_level].tree_status[spill_req->dst_tree] == NO_SPILLING) {
			db_desc->levels[dst_level].tree_status[spill_req->dst_tree] = SPILLING_IN_PROGRESS;
			db_desc->levels[curr_level_id].tree_status[spill_req->src_tree] = SPILLING_IN_PROGRESS;
			db_desc->levels[curr_level_id].actual_level_size = 0;
			return spill_req;
		} else {
			MUTEX_LOCK(&db_desc->compaction_structs_lock);
			enqueue_level_forcompaction(db_desc->pending_compactions, curr_level_id);
			MUTEX_UNLOCK(&db_desc->compaction_structs_lock);
		}
	}

	free(spill_req);
	return NULL;
}
#if 0
/* Checks for pending compactions. It is responsible to check for dependencies between two levels before triggering a compaction. */
void *compaction_daemon(void *args)
{
	db_handle handle = *(db_handle *)args;
	db_descriptor *db_desc = handle.db_desc;
	int i, level_is_free, level_is_full, level_compaction_ready, ongoing_compaction, prev_level_compaction;

	while (1) {
		for (int level_id = 0; level_id < MAX_LEVELS; ++level_id) {
			for (i = 0; i < MAX_LEVELS; ++i) {
				if (db_desc->pending_compactions[i].src_level != -1) {
					level_id = db_desc->pending_compactions[i].src_level;
					break;
				}
			}

			assert(level_id >= 0 && level_id < MAX_LEVELS);

			level_compaction_ready = db_desc->levels[level_id].actual_level_size >=
							 db_desc->levels[level_id].max_level_size /* && */
						 /* !db_desc->levels[level_id].outstanding_spill_ops */;

			if (!level_compaction_ready)
				continue;

			for (i = 0; i < MAX_LEVELS; ++i) {
				level_is_free = !(level_id == db_desc->inprogress_compactions[i].src_level ||
						  level_id == db_desc->inprogress_compactions[i].dst_level);

				if (!level_is_free)
					break;
			}

			if (level_is_free) {
				/* Check level's capacity, if full trigger compaction but first
				 * prepare the appropriate structures for level i and i + 1.*/
				prev_level_compaction = level_id > 0 /* && */
							/* db_desc->levels[level_id - 1].outstanding_spill_ops != 0 */;

				ongoing_compaction = 0/* db_desc->levels[level_id].outstanding_spill_ops != 0 || */
						     /* db_desc->levels[level_id + 1].outstanding_spill_ops != 0 */;

				level_is_full = db_desc->levels[level_id].actual_level_size >=
						db_desc->levels[level_id].max_level_size;
				/* if(level_is_full && level_id == 1) */
				/* 	BREAKPOINT; */

				if (!prev_level_compaction && !ongoing_compaction && level_is_full) {
					bt_spill_request *spill_req = prepare_compaction_metadata(&handle, level_id);

					if (spill_req) {
						MUTEX_LOCK(&db_desc->compaction_structs_lock);
						enqueue_ongoing_compaction(db_desc->inprogress_compactions,
									   spill_req->src_level);
						MUTEX_UNLOCK(&db_desc->compaction_structs_lock);
					}

					spill_trigger(spill_req);
				}
			}
		}
		int sleep_or_spin = 0; /* Sleep = 0 Spin = 1 */

		for (int level_id = 0; level_id < MAX_LEVELS && !sleep_or_spin; ++level_id)
			sleep_or_spin = db_desc->pending_compactions[level_id].src_level != -1 ||
					db_desc->pending_compactions[level_id].dst_level != -1 ||
					db_desc->inprogress_compactions[level_id].src_level != -1 ||
					db_desc->inprogress_compactions[level_id].dst_level != -1;

		if (!sleep_or_spin) {
			struct timespec ts;
			if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
				perror("FATAL: clock_gettime failed)\n");
				exit(-1);
			}
			ts.tv_sec += (COMPACTION_INTERVAL / 1000000L);
			ts.tv_nsec += (COMPACTION_INTERVAL % 1000000L) * 1000L;

			MUTEX_LOCK(&db_desc->compaction_lock);
			switch (pthread_cond_timedwait(&db_desc->compaction_cond, &db_desc->compaction_lock, &ts)) {
			case EINVAL:
				assert(0);
			case EPERM:
				assert(0);
			default:
				break;
			}
			MUTEX_UNLOCK(&db_desc->compaction_lock);
		}
	}
}
#endif
/**
 * @param   blockSize
 * @param   db_name
 * @return  db_handle
 **/
db_handle *db_open(char *volumeName, uint64_t start, uint64_t size, char *db_name, char CREATE_FLAG)
{
	uint32_t leaf_size_per_level[MAX_LEVELS] = { LEVEL0_LEAF_SIZE, LEVEL1_LEAF_SIZE, LEVEL2_LEAF_SIZE,
						     LEVEL3_LEAF_SIZE, LEVEL4_LEAF_SIZE, LEVEL5_LEAF_SIZE,
						     LEVEL6_LEAF_SIZE, LEVEL7_LEAF_SIZE };
	db_handle *handle;
	volume_descriptor *volume_desc;
	db_descriptor *db_desc;
	char *key;
	uint64_t val;
	int i = 0;
	int digits;
	uint8_t level_id, tree_id;

	fprintf(stderr, "\n%s[%s:%s:%d](\"%s\", %" PRIu64 ", %" PRIu64 ", %s);%s\n", "\033[0;32m", __FILE__, __func__,
		__LINE__, volumeName, start, size, db_name, "\033[0m");

	MUTEX_LOCK(&init_lock);

	if (mappedVolumes == NULL) {
		mappedVolumes = init_list(&destroy_volume_node);
		/*calculate max leaf,index order*/
		index_order = (INDEX_NODE_SIZE - sizeof(node_header)) / (2 * sizeof(uint64_t));
		index_order -= 2; /*more space for extra pointer, and for rebalacing (merge)*/
		while (index_order % 2 != 1)
			--index_order;

		log_info("index order set to: %d sizeof node_header = %lu", index_order, sizeof(node_header));
	}

	/*Is requested volume already mapped?, construct key which will be
* volumeName|start*/
	val = start;
	digits = 0;

	while (val > 0) {
		val = val / 10;
		digits++;
	}

	if (digits == 0)
		digits = 1;

	key = malloc(strlen(volumeName) + digits + 1);
	strcpy(key, volumeName);
	sprintf(key + strlen(volumeName), "%llu", (LLU)start);
	key[strlen(volumeName) + digits] = '\0';
	log_info("Searching volume %s", key);
	volume_desc = (volume_descriptor *)find_element(mappedVolumes, key);

	if (volume_desc == NULL) {
		volume_desc = malloc(sizeof(volume_descriptor));
		volume_desc->state = VOLUME_IS_OPEN;
		volume_desc->snap_preemption = SNAP_INTERRUPT_DISABLE;
		volume_desc->last_snapshot = get_timestamp();
		volume_desc->last_commit = get_timestamp();
		volume_desc->last_sync = get_timestamp();

		volume_desc->volume_name = malloc(strlen(volumeName) + 1);
		strcpy(volume_desc->volume_name, volumeName);
		volume_desc->volume_id = malloc(strlen(key) + 1);
		strcpy(volume_desc->volume_id, key);
		volume_desc->open_databases = init_list(&destoy_db_list_node);
		volume_desc->offset = start;
		volume_desc->size = size;
		/*allocator lock*/
		MUTEX_INIT(&(volume_desc->allocator_lock), NULL);
		/*free operations log*/
		MUTEX_INIT(&(volume_desc->FREE_LOG_LOCK), NULL);
		allocator_init(volume_desc);
		add_first(mappedVolumes, volume_desc, key);
		volume_desc->reference_count++;
		/*soft state about the in use pages of level-0 for each BUFFER_SEGMENT_SIZE
* segment inside the volume*/
		volume_desc->segment_utilization_vector_size =
			((volume_desc->volume_superblock->dev_size_in_blocks -
			  (1 + FREE_LOG_SIZE + volume_desc->volume_superblock->bitmap_size_in_blocks)) /
			 (SEGMENT_SIZE / DEVICE_BLOCK_SIZE)) *
			2;
		volume_desc->segment_utilization_vector =
			(uint16_t *)malloc(volume_desc->segment_utilization_vector_size);

		if (volume_desc->segment_utilization_vector == NULL) {
			log_fatal("failed to allocate memory for segment utilization vector of "
				  "size %lu",
				  volume_desc->segment_utilization_vector_size);
			exit(EXIT_FAILURE);
		}

		memset(volume_desc->segment_utilization_vector, 0x00, volume_desc->segment_utilization_vector_size);

		log_info("volume %s state created max_tries %d", volume_desc->volume_name, MAX_ALLOCATION_TRIES);
	} else {
		log_info("Volume already mapped");
		volume_desc->reference_count++;
	}
	/*Before searching the actual volume's catalogue take a look at the current open databases*/
	db_desc = find_element(volume_desc->open_databases, db_name);

	if (db_desc != NULL) {
		log_info("DB %s already open for volume %s", db_name, key);
		handle = malloc(sizeof(db_handle));
		memset(handle, 0x00, sizeof(db_handle));
		handle->volume_desc = volume_desc;
		handle->db_desc = db_desc;
		db_desc->reference_count++;
		MUTEX_UNLOCK(&init_lock);
		free(key);
		return handle;
	} else {
		pr_db_group *db_group;
		pr_db_entry *db_entry;
		int32_t empty_group;
		int32_t empty_index;
		int32_t j;

		log_info("Searching volume's %s catalogue for db %s...", volume_desc->volume_name, db_name);
		empty_group = -1;
		empty_index = -1;
		/*we are going to search system's catalogue to find the root_r of the
* corresponding database*/
		for (i = 0; i < NUM_OF_DB_GROUPS; i++) {
			/*is group empty?*/
			if (volume_desc->mem_catalogue->db_group_index[i] != 0) {
				db_group = (pr_db_group *)REAL_ADDRESS(volume_desc->mem_catalogue->db_group_index[i]);
				for (j = 0; j < GROUP_SIZE; j++) {
					/*empty slot keep in mind*/
					if (db_group->db_entries[j].valid == 0 && empty_index == -1) {
						/*Remember the location of the first empty slot within the group*/
						// log_info("empty slot %d in group %d\n", i, j);
						empty_group = i;
						empty_index = j;
					}

					if (db_group->db_entries[j].valid) {
						/*hosts a database*/
						db_entry = &db_group->db_entries[j];
						// log_info("entry at %s looking for %s offset %llu",
						// (uint64_t)db_entry->db_name,
						//	 db_name, db_entry->offset[0]);
						if (!strcmp((const char *)db_entry->db_name, (const char *)db_name)) {
							/*found database, recover state and create the appropriate handle and store it in the open_db's list*/
							log_info("database: %s found at index [%d,%d]",
								 db_entry->db_name, i, j);
							handle = malloc(sizeof(db_handle));
							memset(handle, 0x00, sizeof(db_handle));
							db_desc = malloc(sizeof(db_descriptor));

							handle->volume_desc = volume_desc;
							handle->db_desc = db_desc;
							/*initialize database descriptor, soft state first*/
							db_desc->reference_count = 0;
							db_desc->group_id = i;
							db_desc->group_index = j;
							/*restore db name, in memory*/
							memset(db_desc->db_name, 0x00, MAX_DB_NAME_SIZE);
							strcpy(db_desc->db_name, db_entry->db_name);
							db_desc->dirty = 0;

							/*restore now persistent state of all levels*/
							for (level_id = 0; level_id < MAX_LEVELS; level_id++) {
								db_desc->levels[level_id].level_size[0] = 0;
								db_desc->levels[level_id].level_size[1] = 0;
								db_desc->levels[level_id].actual_level_size = 0;
								for (tree_id = 0; tree_id < NUM_TREES_PER_LEVEL;
								     tree_id++) {
									db_desc->levels[level_id].level_size[tree_id] =
										0;
									/*segments info per level*/
									if (db_entry->first_segment
										    [(level_id * NUM_TREES_PER_LEVEL) +
										     tree_id] != 0) {
										db_desc->levels[level_id]
											.first_segment[tree_id] =
											(segment_header *)REAL_ADDRESS(
												db_entry->first_segment
													[(level_id *
													  NUM_TREES_PER_LEVEL) +
													 tree_id]);
										db_desc->levels[level_id]
											.last_segment[tree_id] =
											(segment_header *)REAL_ADDRESS(
												db_entry->last_segment
													[(level_id *
													  NUM_TREES_PER_LEVEL) +
													 tree_id]);
										db_desc->levels[level_id]
											.offset[tree_id] =
											db_entry->offset
												[(level_id *
												  NUM_TREES_PER_LEVEL) +
												 tree_id];
									} else {
										db_desc->levels[level_id]
											.first_segment[tree_id] = NULL;

										db_desc->levels[level_id]
											.last_segment[tree_id] = NULL;
										db_desc->levels[level_id]
											.offset[tree_id] = 0;
									}
									/*total keys*/
									db_desc->levels[level_id].level_size[tree_id] =
										db_entry->level_size
											[(level_id *
											  NUM_TREES_PER_LEVEL) +
											 tree_id];
									/*finally the roots*/
									if (db_entry->root_r[(level_id *
											      NUM_TREES_PER_LEVEL) +
											     tree_id] != 0) {
										db_desc->levels[level_id].root_r
											[tree_id] = (node_header *)REAL_ADDRESS(
											db_entry->root_r
												[(level_id *
												  NUM_TREES_PER_LEVEL) +
												 tree_id]);
										log_warn(
											"Recovered root r of [%lu][%lu] = %llu ",
											level_id, tree_id,
											db_desc->levels[level_id]
												.root_r[tree_id]);
									} else
										db_desc->levels[level_id]
											.root_r[tree_id] = NULL;

									db_desc->levels[level_id].root_w[tree_id] =
										NULL;
								}
							}

#if 0
							/*recover replica L1 forest if needed*/
							if (db_entry->replica_forest != NULL) {
								memcpy((void *)&db_desc->replica_forest,
								       (void *)MAPPED +
									       (uint64_t)db_entry->replica_forest,
								       sizeof(forest));
								for (i = 0; i < MAX_FOREST_SIZE; i++) {
									if (db_desc->replica_forest.tree_status[i] ==
									    PERSISTED) {
										db_desc->replica_forest
											.tree_segment_list[i] =
											(segment_header *)MAPPED +
											*(uint64_t *)db_entry
												 ->replica_forest
												 ->tree_segment_list[i];
										db_desc->replica_forest.dev / nvme0n1 =
											(node_header *)MAPPED +
											*(uint64_t *)db_entry
												 ->replica_forest
												 ->tree_roots[i];
									} else if (db_desc->replica_forest
												   .tree_status[i] !=
											   NOT_USED ||
										   db_desc->replica_forest
												   .tree_status[i] !=
											   PERSISTED) {
										DPRINT("XXX TODO XXX needs recovery of space !\n");
										exit(EXIT_FAILURE);
									} else if (db_desc->replica_forest
											   .tree_status[i] ==
										   NOT_USED) {
										db_desc->replica_forest
											.tree_segment_list[i] = NULL;
										db_desc->replica_forest.tree_roots[i] =
											NULL;
									} else {
										DPRINT("FATAL DBs forest flags in inconsistent state\n");
										exit(EXIT_FAILURE);
									}
								}
								DPRINT("-*-*-*- Recovered db's level 1 forest used in replica "
								       "mode * - * - *\n");
							} else {
								DPRINT(" - * - forest not present? skipping - * - *\n");
								memset(&db_desc->replica_forest, 0x00, sizeof(forest));
							}
/*done with replica forest*/
#endif
							/*recover KV log for this database*/
							recover_database_logs(db_desc, db_entry);

							goto finish_init;
						}
					}
				}
			} else if (empty_group == -1)
				empty_group = i;
		}

		if (CREATE_FLAG != CREATE_DB && CREATE_FLAG != O_CREATE_REPLICA_DB) {
			DPRINT("DB not found instructed not to create one returning NULL\n");
			return NULL;
		}

		/*db not found allocate a new slot for it*/
		if (empty_group == -1 && empty_index == -1) {
			log_info("FATAL MAX DBS %d reached", NUM_OF_DB_GROUPS * GROUP_SIZE);
			exit(EXIT_FAILURE);
		}

		if (empty_index == -1) {
			/*space found in empty group*/
			pr_db_group *new_group = get_space_for_system(volume_desc, sizeof(pr_db_group));
			memset(new_group, 0x00, sizeof(pr_db_group));
			new_group->epoch = volume_desc->mem_catalogue->epoch;
			volume_desc->mem_catalogue->db_group_index[empty_group] =
				(pr_db_group *)ABSOLUTE_ADDRESS(new_group);
			empty_index = 0;
			log_info("allocated new pr_db_group epoch at %llu volume epoch %llu", new_group->epoch,
				 volume_desc->mem_catalogue->epoch);
		}

		log_info("database %s not found, allocating slot [%d,%d] for it", (const char *)db_name, empty_group,
			 empty_index);
		pr_db_group *cur_group =
			(pr_db_group *)REAL_ADDRESS(volume_desc->mem_catalogue->db_group_index[empty_group]);

		db_entry = &cur_group->db_entries[empty_index];
		db_entry->valid = 1;
		handle = malloc(sizeof(db_handle));
		memset(handle, 0x00, sizeof(db_handle));
		db_desc = (db_descriptor *)malloc(sizeof(db_descriptor));

		/*this nullifies replica also*/
		memset(db_desc, 0x00, sizeof(db_descriptor));
		handle->volume_desc = volume_desc;
		handle->db_desc = db_desc;
		/*initialize database descriptor, soft state first*/
		db_desc->reference_count = 0;
		db_desc->group_id = empty_group;
		db_desc->group_index = empty_index;

		// log_info("mem epoch %llu", volume_desc->mem_catalogue->epoch);
		/*stored db name, in memory*/
		memset(db_entry->db_name, 0x00, MAX_DB_NAME_SIZE);
		strcpy(db_entry->db_name, db_name);
		memset(db_desc->db_name, 0x00, MAX_DB_NAME_SIZE);
		strcpy(db_desc->db_name, db_name);
		db_desc->dirty = 0x01;

		/*init all persistent fields levels*/
		for (level_id = 0; level_id < MAX_LEVELS; level_id++) {
			for (tree_id = 0; tree_id < NUM_TREES_PER_LEVEL; tree_id++) {
				db_desc->levels[level_id].root_r[tree_id] = NULL;
				db_desc->levels[level_id].root_w[tree_id] = NULL;
				db_desc->levels[level_id].level_size[tree_id] = 0;
				db_desc->levels[level_id].first_segment[tree_id] = NULL;
				db_desc->levels[level_id].last_segment[tree_id] = NULL;
				db_desc->levels[level_id].offset[tree_id] = 0;
				init_leaf_sizes_perlevel(&db_desc->levels[level_id], level_id);
			}

			if (level_id != 0)
				db_desc->levels[level_id].max_level_size =
					db_desc->levels[level_id - 1].max_level_size * GF;
			else
				db_desc->levels[level_id].max_level_size = MAX_LEVEL0_TOTAL_SIZE;

			log_info("Level %d max_total_size %llu", level_id, db_desc->levels[level_id].max_level_size);
		}

		/*initialize KV log for this db*/
		db_desc->commit_log = (commit_log_info *)get_space_for_system(volume_desc, sizeof(commit_log_info));
		/*get a page for commit_log info*/
		pr_init_logs(db_desc, db_entry, volume_desc);
	}

finish_init:
	/*init soft state for all levels*/
	MUTEX_INIT(&db_desc->compaction_lock, NULL);
	MUTEX_INIT(&db_desc->compaction_structs_lock, NULL);
	pthread_cond_init(&db_desc->compaction_cond, NULL);

	if (pthread_create(&db_desc->compaction_thread, NULL, compaction_daemon, handle) != 0) {
		log_fatal("Cannot create compaction daemon");
		exit(EXIT_FAILURE);
	}

	for (level_id = 0; level_id < MAX_LEVELS; level_id++) {
		if (level_id == 0)
			db_desc->levels[level_id].max_level_size = L0_SIZE;
		else
			db_desc->levels[level_id].max_level_size =
				db_desc->levels[level_id - 1].max_level_size * GROWTH_FACTOR;

		RWLOCK_INIT(&db_desc->levels[level_id].guard_of_level.rx_lock, NULL);
		MUTEX_INIT(&db_desc->levels[level_id].spill_trigger, NULL);
		MUTEX_INIT(&db_desc->levels[level_id].level_allocation_lock, NULL);
		init_level_locktable(db_desc, level_id);
		db_desc->levels[level_id].actual_level_size = 0;
		db_desc->levels[level_id].active_writers = 0;
		/*check again which tree should be active*/
		db_desc->levels[level_id].active_tree = 0;
		db_desc->levels[level_id].level_id = level_id;
		db_desc->levels[level_id].leaf_size = leaf_size_per_level[level_id];
		for (tree_id = 0; tree_id < NUM_TREES_PER_LEVEL; tree_id++) {
			db_desc->levels[level_id].tree_status[tree_id] = NO_SPILLING;
		}
		init_leaf_sizes_perlevel(&db_desc->levels[level_id], level_id);
		db_desc->levels[level_id].split_buffer = malloc(sizeof(char) * db_desc->levels[level_id].leaf_size);
		if (!db_desc->levels[level_id].split_buffer) {
			log_fatal("Cannot allocate memory exiting...");
			exit(EXIT_FAILURE);
		}
		db_desc->inprogress_compactions[level_id].src_level = -1;
		db_desc->inprogress_compactions[level_id].dst_level = -1;
		db_desc->pending_compactions[level_id].src_level = -1;
		db_desc->pending_compactions[level_id].dst_level = -1;
	}

#if LOG_WITH_MUTEX
	MUTEX_INIT(&db_desc->lock_log, NULL);
#else
	SPINLOCK_INIT(&db_desc->lock_log, PTHREAD_PROCESS_PRIVATE);
#endif

	add_first(volume_desc->open_databases, db_desc, db_name);
	MUTEX_UNLOCK(&init_lock);
	free(key);
	db_desc->stat = DB_OPEN;
	log_info("opened DB %s starting its compaction daemon", db_name);

	sem_init(&db_desc->compaction_daemon_interrupts, PTHREAD_PROCESS_PRIVATE, 0);
	if (pthread_create(&(handle->db_desc->compaction_daemon), NULL, (void *)compaction_daemon, (void *)handle) !=
	    0) {
		log_fatal("Failed to start compaction_daemon for db %s", db_name);
		exit(EXIT_FAILURE);
	}

#if 0
	else{
		log_info("opened replica db");
		db_desc->db_mode = BACKUP_DB_NO_PENDING_SPILL;
		log_info("Initializing  segment table");
		init_backup_db_segment_table(handle);
	}
	db_desc->log_buffer = NULL;
	db_desc->latest_proposal_start_segment_offset = 0;
#endif

	/*recovery checks*/
	log_info("performing recovery checks for db: %s", db_desc->db_name);

	/*where is L0 located at the log?*/
	if (db_desc->big_log_tail_offset > db_desc->big_log_head_offset ||
	    db_desc->medium_log_tail_offset > db_desc->medium_log_head_offset ||
	    db_desc->small_log_tail_offset > db_desc->small_log_head_offset) {
		log_info("L0 present performing recovery checks ...");

		if (db_desc->big_log_tail_offset < db_desc->commit_log->big_log_size ||
		    db_desc->medium_log_tail_offset < db_desc->commit_log->medium_log_size ||
		    db_desc->small_log_tail_offset < db_desc->commit_log->small_log_size) {
			log_info("Commit log: %llu is ahead of L0: %llu replaying "
				 "missing log parts",
				 (LLU)db_desc->commit_log->big_log_size, (LLU)db_desc->big_log_tail_offset);
			recovery_request rh;
			rh.volume_desc = volume_desc;
			rh.db_desc = db_desc;
			rh.big_log_start_offset = db_desc->big_log_tail_offset;
			rh.medium_log_start_offset = db_desc->medium_log_tail_offset;
			rh.small_log_start_offset = db_desc->small_log_tail_offset;
			recovery_worker(&rh);
			log_info("recovery completed successfully");
		} else if (db_desc->big_log_tail_offset == db_desc->commit_log->big_log_size &&
			   db_desc->medium_log_tail_offset == db_desc->commit_log->medium_log_size &&
			   db_desc->small_log_tail_offset == db_desc->commit_log->small_log_size) {
			log_info("no recovery needed for db: %s ready :-)\n", db_desc->db_name);
		} else {
			log_fatal("Boom! Corrupted state for db: %s :-(", db_desc->db_name);
			raise(SIGINT);
			exit(EXIT_FAILURE);
		}

	} else if (db_desc->big_log_tail_offset == db_desc->big_log_head_offset ||
		   db_desc->medium_log_tail_offset == db_desc->medium_log_head_offset ||
		   db_desc->small_log_tail_offset == db_desc->small_log_head_offset) {
		log_info("L0 is absent L1 ends at %llu replaying missing parts", (LLU)db_desc->big_log_tail_offset);
		log_info("L0 is absent L1 ends at %llu replaying missing parts", (LLU)db_desc->medium_log_tail_offset);
		log_info("L0 is absent L1 ends at %llu replaying missing parts", (LLU)db_desc->small_log_tail_offset);

		log_info("Condition part1 %d part2 %d part3 %d",
			 db_desc->big_log_tail_offset < db_desc->commit_log->big_log_size,
			 db_desc->medium_log_tail_offset < db_desc->commit_log->medium_log_size,
			 db_desc->small_log_tail_offset < db_desc->commit_log->small_log_size);

		if (db_desc->big_log_tail_offset < db_desc->commit_log->big_log_size ||
		    db_desc->medium_log_tail_offset < db_desc->commit_log->medium_log_size ||
		    db_desc->small_log_tail_offset < db_desc->commit_log->small_log_size) {
			log_info("Commit log (%llu) is ahead of L0 end (%llu) replaying missing "
				 "log parts",
				 (LLU)db_desc->commit_log->big_log_size, (LLU)db_desc->big_log_tail_offset);
			recovery_request rh;
			rh.volume_desc = volume_desc;
			rh.db_desc = db_desc;
			rh.big_log_start_offset = db_desc->big_log_tail_offset;
			rh.medium_log_start_offset = db_desc->medium_log_tail_offset;
			rh.small_log_start_offset = db_desc->small_log_tail_offset;
			recovery_worker(&rh);
			log_info("recovery completed successfully");
		} else if (db_desc->big_log_tail_offset == db_desc->commit_log->big_log_size &&
			   db_desc->medium_log_tail_offset == db_desc->commit_log->medium_log_size &&
			   db_desc->small_log_tail_offset == db_desc->commit_log->small_log_size) {
			log_info("no recovery needed for db: %s ready :-)\n", db_desc->db_name);
		} else {
			log_fatal("FATAL corrupted state for db: %s :-(", db_desc->db_name);
			exit(EXIT_FAILURE);
		}

	} else {
		log_fatal("FATAL Corrupted state detected");
		exit(EXIT_FAILURE);
	}
	log_info("MAPPED = %llu", MAPPED);
	log_info("big start %llu big end %llu diff %llu", handle->db_desc->big_log_head, handle->db_desc->big_log_tail,
		 handle->db_desc->big_log_tail_offset - handle->db_desc->big_log_head_offset);
	log_info("medium start %llu medium end %llu", handle->db_desc->medium_log_head,
		 handle->db_desc->medium_log_tail);
	log_info("small start %llu small end %llu", handle->db_desc->small_log_head, handle->db_desc->small_log_tail);

	return handle;
}

char db_close(db_handle *handle)
{
	/*verify that this is a valid db*/
	if (find_element(handle->volume_desc->open_databases, handle->db_desc->db_name) == NULL) {
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

	if (remove_element(handle->volume_desc->open_databases, handle->db_desc) != 1) {
		log_info("Could not find db: %s", handle->db_desc->db_name);
		MUTEX_UNLOCK(&init_lock);
		return COULD_NOT_FIND_DB;
	}
	return KREON_OK;
}

void spill_database(db_handle *handle)
{
	if (handle)
		log_warn("Spill database deprecated");
#if 0
	int32_t i;

	if (handle->db_desc->db_mode != PRIMARY_DB) {
		log_info("ommiting spill for back up db");
		return;
	}
	if (memcmp(handle->db_desc->tree_status, DB_NO_SPILLING, NUM_OF_TREES_PER_LEVEL) != 0) {
		log_info("Nothing to do spill operation already active");
		return;
	}
	RWLOCK_WRLOCK(&handle->db_desc->guard_level_0.rx_lock);
	spin_loop(&handle->db_desc->count_writers_level_0, 0);

	/*switch to another tree, but which?*/
	for (i = 0; i < NUM_OF_TREES_PER_LEVEL; i++) {
		if (i != handle->db_desc->active_tree && handle->db_desc->tree_status[i] != SPILLING_IN_PROGRESS) {
			int32_t level_id = handle->db_desc->active_tree;
			handle->db_desc->tree_status[level_id] = SPILLING_IN_PROGRESS;
			handle->db_desc->active_tree = i;

			/*spawn a spiller thread*/
			spill_request *spill_req =
				(spill_request *)malloc(sizeof(spill_request)); /*XXX TODO XXX MEMORY LEAK*/
			spill_req->db_desc = handle->db_desc;
			spill_req->volume_desc = handle->volume_desc;

			if (handle->db_desc->root_w[level_id] != NULL)
				spill_req->src_root = handle->db_desc->root_w[level_id];
			else if (handle->db_desc->root_r[level_id] != NULL)
				spill_req->src_root = handle->db_desc->root_r[level_id];
			else {
				log_info("empty level-0, nothing to do");
				free(spill_req);
				handle->db_desc->tree_status[level_id] = NO_SPILLING;
				break;
			}
			if (handle->db_desc->root_w[level_id] != NULL)
				spill_req->src_root = handle->db_desc->root_w[level_id];
			else
				spill_req->src_root = handle->db_desc->root_r[level_id];

			spill_req->src_tree_id = level_id;
			spill_req->dst_tree_id = NUM_OF_TREES_PER_LEVEL;
			spill_req->start_key = NULL;
			spill_req->end_key = NULL;
			handle->db_desc->count_active_spillers = 1;

			if (pthread_create(&(handle->db_desc->spiller), NULL, (void *)spill_buffer,
					   (void *)spill_req) != 0) {
				log_info("FATAL: error creating spiller thread");
				exit(EXIT_FAILURE);
			}
			break;
		}
	}
	RWLOCK_UNLOCK(&handle->db_desc->guard_level_0.rx_lock);
#endif
}
#if 0

/*method for closing a database*/
void flush_volume(volume_descriptor *volume_desc, char force_spill)
{
	(void)volume_desc;
	(void)force_spill;
	db_descriptor *db_desc;
	db_handle *handles;
	handles = (db_handle *)malloc(sizeof(db_handle) * volume_desc->open_databases->size);

	int db_id = 0;
	NODE *node;
	int i;

	while (1) {
		log_info("Waiting for pending spills to finish");
		node = get_first(volume_desc->open_databases);
		while (node != NULL) {
			db_desc = (db_descriptor *)(node->data);
			/*wait for pending spills for this db to finish*/
			i = 0;
			while (i < TOTAL_TREES) {
				if (db_desc->tree_status[i] == SPILLING_IN_PROGRESS) {
					log_info("Waiting for db %s to finish spills", db_desc->db_name);
					sleep(4);
					i = 0;
				} else
					i++;
			}
			node = node->next;
		}
		log_info("ok... no pending spills\n");

		if (force_spill == SPILL_ALL_DBS_IMMEDIATELY) {
			node = get_first(volume_desc->open_databases);
			while (node != NULL) {
				handles[db_id].db_desc = (db_descriptor *)(node->data);
				handles[db_id].volume_desc = volume_desc;
				spill_database(&handles[db_id]);
				++db_id;
				node = node->next;
			}
			force_spill = SPILLS_ISSUED;
		} else
			break;
	}
	log_info("Finally, snapshoting volume\n");
	snapshot(volume_desc);
	free(handles);
	return;
}
#endif

uint8_t insert_key_value(db_handle *handle, void *key, void *value, uint32_t key_size, uint32_t value_size)
{
	bt_insert_req ins_req;
	char __tmp[KV_MAX_SIZE];
	char *key_buf = __tmp;
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
	kv_size = sizeof(uint32_t) + key_size + sizeof(uint32_t) + value_size + sizeof(uint64_t);

	if (kv_size > KV_MAX_SIZE) {
		log_fatal("Key buffer overflow");
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
	/*
* Note for L0 inserts since active_tree changes dynamically we decide which
* is the active_tree after
* acquiring the guard lock of the region
* */
	ins_req.metadata.key_format = KV_FORMAT;
	ins_req.metadata.append_to_log = 1;
	ins_req.metadata.gc_request = 0;
	ins_req.metadata.special_split = 0;

	return _insert_key_value(&ins_req);
}

void extract_keyvalue_size(log_operation *req, metadata_tologop *data_size)
{
	switch (req->optype_tolog) {
	case insertOp:
		data_size->key_len = *(uint32_t *)req->ins_req->key_value_buf;
		data_size->value_len =
			*(uint32_t *)(req->ins_req->key_value_buf + sizeof(uint32_t) + (data_size->key_len));
		data_size->kv_size = req->metadata->kv_size;
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
		memcpy(addr_inlog, req->ins_req->key_value_buf,
		       sizeof(data_size->key_len) + data_size->key_len + sizeof(data_size->value_len) +
			       data_size->value_len);
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

void choose_log_toappend(db_descriptor *db_desc, struct log_towrite *log_metadata, uint32_t kv_size)
{
	if (kv_size >= BIG) {
		log_metadata->log_head = db_desc->big_log_head;
		log_metadata->log_tail = db_desc->big_log_tail;
		log_metadata->log_size = &db_desc->big_log_size;
		log_metadata->status = BIG;
	} else if (kv_size >= MEDIUM) {
		log_metadata->log_head = db_desc->medium_log_head;
		log_metadata->log_tail = db_desc->medium_log_tail;
		log_metadata->log_size = &db_desc->medium_log_size;
		log_metadata->status = MEDIUM;
	} else {
		log_metadata->log_head = db_desc->small_log_head;
		log_metadata->log_tail = db_desc->small_log_tail;
		log_metadata->log_size = &db_desc->small_log_size;
		log_metadata->status = SMALL;
	}
}

void update_log_metadata(db_descriptor *db_desc, struct log_towrite *log_metadata)
{
	switch (log_metadata->status) {
	case BIG:
		db_desc->big_log_tail = log_metadata->log_tail;
		return;
	case MEDIUM:
		db_desc->medium_log_tail = log_metadata->log_tail;
		return;
	case SMALL:
		db_desc->small_log_tail = log_metadata->log_tail;
		return;
	}
}

void *append_key_value_to_log(log_operation *req)
{
	struct log_towrite log_metadata;
	segment_header *d_header;
	void *addr_inlog; /*address at the device*/
	metadata_tologop data_size;
	uint64_t lsn;
	uint32_t available_space_in_log;
	uint32_t allocated_space;
	db_handle *handle = req->metadata->handle;

	extract_keyvalue_size(req, &data_size);

#ifdef LOG_WITH_MUTEX
	MUTEX_LOCK(&handle->db_desc->lock_log);
#elif SPINLOCK
	pthread_spin_lock(&handle->db_desc->lock_log);
#endif

	choose_log_toappend(handle->db_desc, &log_metadata, data_size.kv_size);
	/*append data part in the data log*/
	if (*log_metadata.log_size % BUFFER_SEGMENT_SIZE != 0)
		available_space_in_log = BUFFER_SEGMENT_SIZE - (*log_metadata.log_size % BUFFER_SEGMENT_SIZE);
	else
		available_space_in_log = 0;

	if (available_space_in_log < data_size.kv_size + +sizeof(struct log_sequence_number)) {
		/*fill info for kreon master here*/
		req->metadata->log_segment_addr = ABSOLUTE_ADDRESS(log_metadata.log_tail);
		req->metadata->log_offset_full_event = *log_metadata.log_size;
		req->metadata->segment_id = log_metadata.log_tail->segment_id;
		req->metadata->log_padding = available_space_in_log;
		req->metadata->end_of_log = *log_metadata.log_size + available_space_in_log;
		req->metadata->segment_full_event = 1;

		/*pad with zeroes remaining bytes in segment*/
		addr_inlog = (void *)((uint64_t)log_metadata.log_tail + (*log_metadata.log_size % BUFFER_SEGMENT_SIZE));
		memset(addr_inlog, 0x00, available_space_in_log);

		allocated_space = data_size.kv_size + sizeof(struct log_sequence_number) + sizeof(segment_header);
		allocated_space += BUFFER_SEGMENT_SIZE - (allocated_space % BUFFER_SEGMENT_SIZE);
		d_header = seg_get_raw_log_segment(handle->volume_desc);
		d_header->segment_id = log_metadata.log_tail->segment_id + 1;
		d_header->prev_segment = (void *)ABSOLUTE_ADDRESS(log_metadata.log_tail);
		d_header->next_segment = NULL;
		log_metadata.log_tail->next_segment = (void *)ABSOLUTE_ADDRESS(d_header);
		log_metadata.log_tail = d_header;
		/* position the log to the newly added block*/
		*log_metadata.log_size += (available_space_in_log + sizeof(segment_header));
		update_log_metadata(handle->db_desc, &log_metadata);
	}

	addr_inlog = (void *)((uint64_t)log_metadata.log_tail + (*log_metadata.log_size % BUFFER_SEGMENT_SIZE));
	req->metadata->log_offset = *log_metadata.log_size;
	*log_metadata.log_size += data_size.kv_size + sizeof(struct log_sequence_number);
	lsn = __sync_fetch_and_add(&handle->db_desc->lsn, 1);
#ifdef LOG_WITH_MUTEX
	MUTEX_UNLOCK(&handle->db_desc->lock_log);
#elif SPINLOCK
	pthread_spin_unlock(&handle->db_desc->lock_log);
#endif

	write_keyvalue_inlog(req, &data_size, addr_inlog, lsn);

	return addr_inlog + sizeof(struct log_sequence_number);
}

uint8_t _insert_key_value(bt_insert_req *ins_req)
{
	db_descriptor *db_desc = ins_req->metadata.handle->db_desc;
	unsigned key_size;
	unsigned val_size;
	uint8_t rc;
	db_desc->dirty = 0x01;

	if (ins_req->metadata.key_format == KV_FORMAT) {
		key_size = *(uint32_t *)ins_req->key_value_buf;
		val_size = *(uint32_t *)(ins_req->key_value_buf + 4 + key_size);
		ins_req->metadata.kv_size = sizeof(uint32_t) + key_size + sizeof(uint32_t) + val_size;
		assert(ins_req->metadata.kv_size < 4096);
	} else
		ins_req->metadata.kv_size = -1;

	rc = SUCCESS;

	if (writers_join_as_readers(ins_req) == SUCCESS) {
		rc = SUCCESS;
	} else if (concurrent_insert(ins_req) != SUCCESS) {
		log_warn("insert failed!");
		rc = FAILED;
	}

	return rc;
}

static inline struct lookup_reply lookup_in_tree(db_descriptor *db_desc, void *key, node_header *root, int level_id)
{
	struct lookup_reply rep = { .addr = NULL, .lc_failed = 0 };
	struct find_result ret_result;
	node_header *curr_node, *son_node = NULL;
	void *key_addr_in_leaf = NULL;
	void *next_addr;
	uint64_t curr_v1 = 0, curr_v2 = 0;
	uint64_t son_v2 = 0;
	uint32_t index_key_len;

	curr_v2 = root->v2;
	curr_node = root;
	if (curr_node->type == leafRootNode) {
		key_addr_in_leaf = find_key_in_static_leaf((struct bt_static_leaf_node *)curr_node,
							   &db_desc->levels[curr_node->level_id], key + 4,
							   *(uint32_t *)key);

		if (key_addr_in_leaf == NULL)
			rep.addr = NULL;
		else {
			key_addr_in_leaf = (void *)MAPPED + *(uint64_t *)key_addr_in_leaf;
			index_key_len = *(uint32_t *)key_addr_in_leaf;
			rep.addr = (void *)(uint64_t)key_addr_in_leaf + 4 + index_key_len;
		}
		curr_v1 = curr_node->v1;

		if (curr_v1 != curr_v2) {
			// log_info("failed at node height %d v1 %llu v2 % llu\n",
			// curr_node->height, (LLU)curr_node->v1,
			//	 (LLU)curr_node->v2);
			rep.addr = NULL;
			rep.lc_failed = 1;
			return rep;
		}

	} else {
		while (curr_node->type != leafNode) {
			next_addr = _index_node_binary_search((index_node *)curr_node, key, KV_FORMAT);
			son_node = (void *)REAL_ADDRESS(*(uint64_t *)next_addr);
			son_v2 = son_node->v2;
			curr_v1 = curr_node->v1;
			if (curr_v1 != curr_v2) {
				rep.addr = NULL;
				rep.lc_failed = 1;
				return rep;
			}

			curr_node = son_node;
			curr_v2 = son_v2;
		}
	}

	switch (db_desc->levels[level_id].node_layout) {
	case STATIC_LEAF:
		key_addr_in_leaf = find_key_in_static_leaf((struct bt_static_leaf_node *)curr_node,
							   &db_desc->levels[curr_node->level_id], key + 4,
							   *(uint32_t *)key);
		break;
	case DYNAMIC_LEAF:
		ret_result = find_key_in_dynamic_leaf((struct bt_dynamic_leaf_node *)curr_node,
						      db_desc->levels[level_id].leaf_size, key + 4, *(uint32_t *)key);
		break;
	default:
		assert(0);
		key_addr_in_leaf = NULL;
	} /* log_debug("curr node - MAPPEd %p",MAPPED-(uint64_t)curr_node); */

	/* key_addr_in_leaf = __find_key_addr_in_leaf((leaf_node *)curr_node, (struct splice *)key); */

	switch (db_desc->levels[level_id].node_layout) {
	case DYNAMIC_LEAF:
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
		break;
	case STATIC_LEAF:
		if (key_addr_in_leaf == NULL) {
			rep.addr = NULL;
			rep.lc_failed = 0;
		} else {
			key_addr_in_leaf = (void *)REAL_ADDRESS(*(uint64_t *)key_addr_in_leaf);
			index_key_len = KEY_SIZE(key_addr_in_leaf);
			rep.addr = (void *)(uint64_t)key_addr_in_leaf + 4 + index_key_len;
			rep.lc_failed = 0;
		}
		break;
	}
	curr_v1 = curr_node->v1;

	if (curr_v1 != curr_v2) {
		// log_info("failed at node height %d v1 %llu v2 % llu\n",
		// curr_node->height, (LLU)curr_node->v1,
		//	 (LLU)curr_node->v2);
		rep.addr = NULL;
		rep.lc_failed = 1;
		return rep;
	}

	return rep;
}
/*this function will be reused in various places such as deletes*/
void *__find_key(db_handle *handle, void *key)
{
	struct lookup_reply rep = { .addr = NULL, .lc_failed = 0 };
	node_header *root_w;
	node_header *root_r;
	uint32_t tries;

	/*again special care for L0*/
	uint8_t tree_id = handle->db_desc->levels[0].active_tree;
	uint8_t base = tree_id;
	while (1) {
		/*first look the current active tree of the level*/
		tries = 0;
	retry_1:
		if (tries % 1000000 == 999999)
			log_warn("possible deadlock detected lamport counters fail after 1M tries");
		// log_warn("active tree of level %lu is %lu", level_id, active_tree);
		root_w = handle->db_desc->levels[0].root_w[tree_id];
		root_r = handle->db_desc->levels[0].root_r[tree_id];

		if (root_w != NULL) {
			/* if (level_id == 1) */
			/* 	BREAKPOINT; */
			rep = lookup_in_tree(handle->db_desc, key, root_w, 0);
			if (rep.lc_failed) {
				++tries;
				goto retry_1;
			}
		} else if (root_r != NULL) {
			rep = lookup_in_tree(handle->db_desc, key, root_r, 0);

			if (rep.lc_failed) {
				++tries;
				goto retry_1;
			}
		}

		if (rep.addr != NULL)
			goto finish;
		++tree_id;
		if (tree_id >= NUM_TREES_PER_LEVEL)
			tree_id = 0;
		if (tree_id == base)
			break;
	}

	/*search the rest trees of the level*/
	for (uint8_t level_id = 1; level_id < MAX_LEVELS; ++level_id) {
		tries = 0;
	retry_2:
		if (tries % 1000000 == 999999)
			log_warn("possible deadlock detected lamport counters fail after 1M "
				 "tries");
		root_w = handle->db_desc->levels[level_id].root_w[0];
		root_r = handle->db_desc->levels[level_id].root_r[0];
		if (root_w != NULL) {
			rep = lookup_in_tree(handle->db_desc, key, root_w, 0);
			if (rep.lc_failed) {
				++tries;
				goto retry_2;
			}
		} else if (root_r != NULL) {
			rep = lookup_in_tree(handle->db_desc, key, root_r, 0);
			if (rep.lc_failed) {
				++tries;
				goto retry_2;
			}
		}
		if (rep.addr != NULL)
			goto finish;
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
			ret = _tucana_key_cmp(index_key_buf, key_buf, KV_FORMAT, KV_FORMAT);
			if (ret > 0) {
				end_idx = middle - 1;
				if (start_idx > end_idx)
					// addr is the same
					break;
			} else if (ret == 0) {
				log_fatal("key already present*");
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
			 void *key_buf, char allocation_code)
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
			log_fatal("Cannot host index key larger than KEY_BLOCK_SIZE");
			raise(SIGINT);
			exit(EXIT_FAILURE);
		}

		d_header = seg_get_IN_log_block(handle->volume_desc,
						&handle->db_desc->levels[ins_req->metadata.level_id],
						ins_req->metadata.tree_id, allocation_code);

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
	//assert_index_node(node);
}

char *node_type(nodeType_t type)
{
	switch (type) {
	case leafNode:
		return "leafNode";
	case leafRootNode:
		return "leafRootnode";
	case rootNode:
		return "rootNode";
	case internalNode:
		return "internalNode";
	default:
		assert(0);
	}
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

		insert_key_at_index(ins_req, (index_node *)tmp_index, left_child, right_child, key_buf, KEY_LOG_SPLIT);
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
	void *key_addr = ins_req->key_value_buf;
	int ret;
	uint8_t level_id = ins_req->metadata.level_id;
	uint8_t active_tree = ins_req->metadata.tree_id;

	if (ins_req->metadata.append_to_log && ins_req->metadata.key_format == KV_FORMAT) {
		log_operation append_op = { .metadata = &ins_req->metadata,
					    .optype_tolog = insertOp,
					    .ins_req = ins_req };
		ins_req->key_value_buf = append_key_value_to_log(&append_op);
	} else if (!ins_req->metadata.append_to_log && ins_req->metadata.key_format == KV_PREFIX) {
		;
	} else if (!ins_req->metadata.append_to_log && ins_req->metadata.recovery_request) {
		;
	} /* else { */
	/* 	log_fatal("Wrong combination of key format / append_to_log option"); */
	/* 	exit(EXIT_FAILURE); */
	/* } */

	switch (db_desc->levels[level_id].node_layout) {
	case STATIC_LEAF:
		ret = insert_in_static_leaf((struct bt_static_leaf_node *)leaf, ins_req,
					    &db_desc->levels[leaf->level_id]);
		break;
	case DYNAMIC_LEAF:
		ret = insert_in_dynamic_leaf((struct bt_dynamic_leaf_node *)leaf, ins_req,
					     &db_desc->levels[leaf->level_id]);
		break;
	default:
		assert(0);
	}

	return ret;
}

struct bt_rebalance_result split_leaf(bt_insert_req *req, leaf_node *node)
{
	level_descriptor *level = &req->metadata.handle->db_desc->levels[node->header.level_id];
	switch (level->node_layout) {
	case STATIC_LEAF:
		return split_static_leaf((struct bt_static_leaf_node *)node, req);
	case DYNAMIC_LEAF:;
		uint32_t leaf_size = req->metadata.handle->db_desc->levels[node->header.level_id].leaf_size;
		struct bt_rebalance_result res =
			split_dynamic_leaf((struct bt_dynamic_leaf_node *)node, leaf_size, req);
		res.left_dlchild->header.v1++;
		return res;
	default:
		log_fatal("INDEX IS CORRUPTED!");
		exit(EXIT_FAILURE);
	}
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
		ret = _tucana_key_cmp(index_key_buf, key_buf, KV_FORMAT, query_key_format);
		if (ret == 0) {
			// log_debug("I passed from this corner case1 %s",
			// (char*)(index_key_buf+4));
			addr = &(node->p[middle].right[0]);
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
				addr = &(node->p[middle].right[0]);
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
		addr = &(node->p[node->header.num_entries - 1].right[0]);
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
			log_fatal("corrupted child at index for child %llu type is %d\n", (LLU)(uint64_t)child - MAPPED,
				  child->type);
			raise(SIGINT);
			exit(EXIT_FAILURE);
		}
		addr += sizeof(uint64_t);
		key_tmp = (void *)MAPPED + *(uint64_t *)addr;
		// log_info("key %s\n", (char *)key_tmp + sizeof(int32_t));

		if (key_tmp_prev != NULL) {
			if (_tucana_key_cmp(key_tmp_prev, key_tmp, KV_FORMAT, KV_FORMAT) >= 0) {
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
	lock_table *return_value;

	if (node->height < 0 || node->height >= MAX_HEIGHT) {
		log_fatal("MAX_HEIGHT exceeded %d rearrange values in size_per_height array ", node->height);
		raise(SIGINT);
		exit(EXIT_FAILURE);
	}

	position = hash((uint64_t)node) % size_per_height[node->height];
	// log_info("node %llu height %d position %lu size of height %d", node,
	// node->height, position, size_per_height[node->height]);
	return_value = table[node->height];
	return &return_value[position];
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

int is_split_needed(void *node, enum bt_layout node_layout, uint32_t leaf_size, uint32_t kv_size)
{
	node_header *header = (node_header *)node;
	int64_t num_entries = header->num_entries;
	uint32_t height = header->height;

	if (height != 0) {
		uint8_t split_index_node = num_entries >= index_order;
		return split_index_node;
	}

	switch (node_layout) {
	case STATIC_LEAF:
		return check_static_leaf_split(node, leaf_size);
	case DYNAMIC_LEAF:
		return check_dynamic_leaf_split(node, leaf_size, kv_size, KV_INPLACE);
	default:
		assert(0);
	}
}

uint32_t get_leaf_size(uint32_t node_capacity, enum bt_layout node_layout, uint32_t leaf_size)
{
	switch (node_layout) {
	case STATIC_LEAF:
		return node_capacity;
	case DYNAMIC_LEAF:
		return leaf_size;
	default:
		assert(0);
	}
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
									  ins_req->metadata.tree_id, NEW_ROOT);
				memcpy(t, db_desc->levels[level_id].root_r[ins_req->metadata.tree_id], INDEX_NODE_SIZE);
				t->header.epoch = mem_catalogue->epoch;
				db_desc->levels[level_id].root_w[ins_req->metadata.tree_id] = (node_header *)t;
			} else {
				/*Tree too small consists only of 1 leafRootNode*/
				leaf_node *t = seg_get_leaf_node_header(ins_req->metadata.handle->volume_desc,
									&db_desc->levels[level_id],
									ins_req->metadata.tree_id, COW_FOR_LEAF);

				memcpy(t, db_desc->levels[level_id].root_r[ins_req->metadata.tree_id],
				       db_desc->levels[level_id].leaf_size);

				t->header.epoch = mem_catalogue->epoch;
				db_desc->levels[level_id].root_w[ins_req->metadata.tree_id] = (node_header *)t;
			}
		} else {
			/*we are allocating a new tree*/

			log_info("Allocating new active tree %d for level id %d epoch is at %llu",
				 ins_req->metadata.tree_id, level_id, (LLU)mem_catalogue->epoch);

			leaf_node *t = seg_get_leaf_node(ins_req->metadata.handle->volume_desc,
							 &db_desc->levels[level_id], ins_req->metadata.tree_id,
							 NEW_ROOT);

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
			if (father->type == leafNode || father->type == leafRootNode)
				father_order = db_desc->levels[level_id].leaf_offsets.kv_entries;
			else
				father_order = index_order;
			assert(father->epoch > volume_desc->dev_catalogue->epoch);
			assert(father->num_entries < father_order);
		}

		uint32_t temp_leaf_size = get_leaf_size(db_desc->levels[level_id].leaf_offsets.kv_entries,
							db_desc->levels[level_id].node_layout,
							db_desc->levels[level_id].leaf_size);

		if (is_split_needed(son, db_desc->levels[level_id].node_layout, temp_leaf_size,
				    ins_req->metadata.kv_size)) {
			/*Overflow split*/
			if (son->height > 0) {
				son->v1++;
				split_res = split_index(son, ins_req);
				/*node has splitted, free it*/
				seg_free_index_node(ins_req->metadata.handle->volume_desc, &db_desc->levels[level_id],
						    ins_req->metadata.tree_id, (index_node *)son);
				// free_logical_node(&(req->allocator_desc), son);
				son->v2++;
			} else {
				son->v1++;

				split_res = split_leaf(ins_req, (leaf_node *)son);

				if ((uint64_t)son != (uint64_t)split_res.left_child) {
					/*cow happened*/
					seg_free_leaf_node(ins_req->metadata.handle->volume_desc,
							   &ins_req->metadata.handle->db_desc->levels[level_id],
							   ins_req->metadata.tree_id, (leaf_node *)son);
					/*fix the dangling lamport*/
					split_res.left_child->v2++;
				} else
					son->v2++;
			}

			/*Insert pivot at father*/
			if (father != NULL) {
				/*lamport counter*/
				father->v1++;

				insert_key_at_index(ins_req, (index_node *)father, split_res.left_child,
						    split_res.right_child, split_res.middle_key_buf, KEY_LOG_EXPANSION);

				/*lamport counter*/
				father->v2++;
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
				new_index_node->header.v1++; /*lamport counter*/
				son->v1++;

				insert_key_at_index(ins_req, new_index_node, split_res.left_child,
						    split_res.right_child, split_res.middle_key_buf, KEY_LOG_EXPANSION);

				new_index_node->header.v2++; /*lamport counter*/
				son->v2++;
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
					ins_req->metadata.tree_id, COW_FOR_INDEX);

				memcpy(node_copy, son, INDEX_NODE_SIZE);
				seg_free_index_node_header(ins_req->metadata.handle->volume_desc,
							   &db_desc->levels[level_id], ins_req->metadata.tree_id, son);
			} else {
				node_copy = (node_header *)seg_get_leaf_node_header(
					ins_req->metadata.handle->volume_desc, &db_desc->levels[level_id],
					ins_req->metadata.tree_id, COW_FOR_LEAF);

				memcpy(node_copy, son, db_desc->levels[level_id].leaf_size);
				/* Add static and dynamic layout free operations*/
				seg_free_leaf_node(ins_req->metadata.handle->volume_desc, &db_desc->levels[level_id],
						   ins_req->metadata.tree_id, (leaf_node *)son);
			}
			node_copy->epoch = mem_catalogue->epoch;
			son = node_copy;
			/*Update father's pointer*/
			if (father != NULL) {
				father->v1++; /*lamport counter*/
				*(uint64_t *)next_addr = (uint64_t)node_copy - MAPPED;
				father->v2++; /*lamport counter*/
			} else { /*We COWED the root*/
				db_desc->levels[level_id].root_w[ins_req->metadata.tree_id] = node_copy;
			}
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
		son = (node_header *)(MAPPED + *(uint64_t *)next_addr);

		/*if the node is not safe hold its ancestor's lock else release locks from
		 * ancestors */

		temp_leaf_size = get_leaf_size(db_desc->levels[level_id].leaf_offsets.kv_entries,
					       db_desc->levels[level_id].node_layout,
					       db_desc->levels[level_id].leaf_size);

		if (!(son->epoch <= volume_desc->dev_catalogue->epoch ||
		      is_split_needed(son, db_desc->levels[level_id].node_layout, temp_leaf_size,
				      ins_req->metadata.kv_size))) {
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

	son->v1++; /*lamport counter*/
	insert_KV_at_leaf(ins_req, son);
	son->v2++; /*lamport counter*/
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
		uint32_t temp_leaf_size = get_leaf_size(db_desc->levels[level_id].leaf_offsets.kv_entries,
							db_desc->levels[level_id].node_layout,
							db_desc->levels[level_id].leaf_size);

		if (is_split_needed(son, db_desc->levels[level_id].node_layout, temp_leaf_size,
				    ins_req->metadata.kv_size)) {
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

	uint32_t temp_leaf_size = get_leaf_size(db_desc->levels[level_id].leaf_offsets.kv_entries,
						db_desc->levels[level_id].node_layout,
						db_desc->levels[level_id].leaf_size);

	if (is_split_needed(son, db_desc->levels[level_id].node_layout, temp_leaf_size, ins_req->metadata.kv_size) ||
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

	son->v1++; /*lamport counter*/
	insert_KV_at_leaf(ins_req, son);
	son->v2++; /*lamport counter*/
	/*Unlock remaining locks*/
	_unlock_upper_levels(upper_level_nodes, size, release);
	__sync_fetch_and_sub(num_level_writers, 1);
	return SUCCESS;
}

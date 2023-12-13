#include "device_level.h"
#include "../allocator/device_structures.h"
#include "../allocator/redo_undo_log.h"
#include "../utilities/spin_loop.h"
#include "bloom_filter.h"
#include "btree.h"
#include "compaction_daemon.h"
#include "conf.h"
#include "segment_allocator.h"
#include <assert.h>
#include <bloom.h>
#include <log.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
struct segment_header;
struct pbf_desc;

extern const uint32_t *const size_per_height;

struct level_lock {
	pthread_rwlock_t rx_lock;
	char pad[8];
};

struct device_level {
	struct segment_header *first_segment[NUM_TREES_PER_LEVEL];
	struct segment_header *last_segment[NUM_TREES_PER_LEVEL];
	uint64_t offset[NUM_TREES_PER_LEVEL];
	struct node_header *root[NUM_TREES_PER_LEVEL];
	struct pbf_desc *bloom_desc[NUM_TREES_PER_LEVEL];
	uint64_t level_size[NUM_TREES_PER_LEVEL];
	int64_t num_level_keys[NUM_TREES_PER_LEVEL];
	pthread_t compaction_thread;
	struct level_lock guard_of_level;
	pthread_mutex_t level_allocation_lock;
	uint64_t max_level_size;
	volatile struct segment_header *medium_log_head;
	volatile struct segment_header *medium_log_tail;
	uint64_t medium_log_size;
	int64_t active_operations;
	/*info for trimming medium_log, used only in L_{n-1}*/
	uint64_t medium_in_place_max_segment_id;
	uint64_t medium_in_place_segment_dev_offt;
	bool compaction_in_progress;
	uint8_t level_id;
	char in_recovery_mode;
};

struct device_level *level_create_fresh(uint32_t level_id, uint32_t l0_size, uint32_t growth_factor)
{
	log_debug("L0 size = %u B and growth_factor = %u", l0_size, growth_factor);
	struct device_level *level = calloc(1UL, sizeof(struct device_level));
	level->level_id = level_id;
	level->compaction_in_progress = false;

	RWLOCK_INIT(&level->guard_of_level.rx_lock, NULL);
	MUTEX_INIT(&level->level_allocation_lock, NULL);

	level->max_level_size = l0_size;
	if (0 == level_id)
		return level;
	if (MAX_LEVELS - 1 == level_id) {
		level->max_level_size = UINT64_MAX;
		return level;
	}
	for (uint32_t i = 1; i <= level_id; i++)
		level->max_level_size = level->max_level_size * growth_factor;
	log_debug("Level_id: %u has max level size of: %lu", level_id, level->max_level_size);
	return level;
}

struct device_level *level_restore_from_device(uint32_t level_id, struct pr_db_superblock *superblock,
					       uint32_t num_trees, db_handle *database, uint64_t l0_size,
					       uint32_t growth_factor)
{
	/*restore now persistent state of all levels*/
	struct device_level *level = level_create_fresh(level_id, l0_size, growth_factor);

	for (uint32_t tree_id = 0; tree_id < num_trees; tree_id++) {
		if (0 == superblock->first_segment[level_id][tree_id])
			continue; //empty level
		//
		level->first_segment[tree_id] =
			(segment_header *)REAL_ADDRESS(superblock->first_segment[level_id][tree_id]);
		level->last_segment[tree_id] =
			(segment_header *)REAL_ADDRESS(superblock->last_segment[level_id][tree_id]);
		level->offset[tree_id] = superblock->offset[level_id][tree_id];
		/*total keys*/
		level->level_size[tree_id] = superblock->level_size[level_id][tree_id];
		/*finally the roots*/
		level->root[tree_id] = REAL_ADDRESS(superblock->root_r[level_id][tree_id]);

		if (0 == superblock->bloom_filter_valid[level_id][tree_id]) {
			level->bloom_desc[tree_id] = NULL;
			continue;
		}
		level->bloom_desc[tree_id] = pbf_recover_bloom_filter(database, (uint8_t)level_id, (uint8_t)tree_id,
								      superblock->bloom_filter_hash[level_id][tree_id]);
	}

	return level;
}

// inline uint64_t level_get_txn_id(struct device_level *level, uint32_t tree_id)
// {
// 	return level->allocation_txn_id[tree_id];
// }

// inline void level_set_txn_id(struct device_level *level, uint32_t tree_id, uint64_t txn_id)
// {
// 	log_debug("---------------> Setting txn id Level[%u][%u] = %lu", level->level_id, tree_id, txn_id);
// 	level->allocation_txn_id[tree_id] = txn_id;
// }

inline struct node_header *level_get_root(struct device_level *level, uint32_t tree_id)
{
	return level->root[tree_id];
}

inline uint64_t level_get_root_dev_offt(struct device_level *level, uint32_t tree_id)
{
	struct node_header *root = level_get_root(level, tree_id);
	return ABSOLUTE_ADDRESS(root);
}

inline struct segment_header *level_get_index_first_seg(struct device_level *level, uint32_t tree_id)
{
	return level->first_segment[tree_id];
}

inline uint64_t level_get_index_first_seg_offt(struct device_level *level, uint32_t tree_id)
{
	struct segment_header *first = level_get_index_first_seg(level, tree_id);
	return ABSOLUTE_ADDRESS(first);
}

inline struct segment_header *level_get_index_last_seg(struct device_level *level, uint32_t tree_id)
{
	return level->last_segment[tree_id];
}

inline uint64_t level_get_index_last_seg_offt(struct device_level *level, uint32_t tree_id)
{
	struct segment_header *last = level_get_index_last_seg(level, tree_id);
	return ABSOLUTE_ADDRESS(last);
}

inline uint64_t level_get_offset(struct device_level *level, uint32_t tree_id)
{
	return level->offset[tree_id];
}

inline uint64_t level_get_size(struct device_level *level, uint32_t tree_id)
{
	return level->level_size[tree_id];
}

static inline bool level_is_medium_log_trimmable(struct device_level *level, uint64_t medium_log_head_offt)
{
	return (0 == level->medium_in_place_segment_dev_offt ||
		level->medium_in_place_segment_dev_offt == medium_log_head_offt) ?
		       false :
		       true;
}

uint64_t level_trim_medium_log(struct device_level *level, uint32_t tree_id, struct db_descriptor *db_desc,
			       uint64_t txn_id)
{
	uint64_t new_medium_log_head_offt = level->medium_in_place_segment_dev_offt;
	if (false == level_is_medium_log_trimmable(level, db_desc->medium_log.head_dev_offt))
		return new_medium_log_head_offt;

	struct segment_header *trim_end_segment = REAL_ADDRESS(level->medium_in_place_segment_dev_offt);
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
	level->medium_in_place_segment_dev_offt = 0;
	level->medium_in_place_max_segment_id = 0;

	log_debug("*** Freed a total of %lu MB bytes from trimming medium log head %lu tail %lu size %lu ***",
		  bytes_freed / (1024 * 1024L), db_desc->db_superblock->small_log_head_offt,
		  db_desc->db_superblock->small_log_tail_offt, db_desc->db_superblock->small_log_size);

	return new_medium_log_head_offt;
}

uint8_t level_enter_as_writer(struct device_level *level)
{
	RWLOCK_WRLOCK(&level->guard_of_level.rx_lock);
	spin_loop(&level->active_operations, 0);
	return UINT8_MAX;
}

void level_leave_as_writer(struct device_level *level)
{
	RWLOCK_UNLOCK(&level->guard_of_level.rx_lock);
}

void level_set_comp_in_progress(struct device_level *level)
{
	level->compaction_in_progress = true;
}

inline bool level_is_compacting(struct device_level *level)
{
	return level->compaction_in_progress;
}

void level_destroy(struct device_level *level)
{
	free(level);
}

void level_save_to_superblock(struct device_level *level, struct pr_db_superblock *db_superblock, uint32_t tree_id)
{
	uint32_t dst_level_id = level->level_id;
	/*new info about my level*/
	db_superblock->root_r[dst_level_id][0] = ABSOLUTE_ADDRESS(level->root[tree_id]);

	db_superblock->first_segment[dst_level_id][0] = ABSOLUTE_ADDRESS(level->first_segment[tree_id]);

	log_debug("Persist %u first was %lu", dst_level_id, ABSOLUTE_ADDRESS(level->first_segment[tree_id]));
	assert(level->first_segment[tree_id]);

	db_superblock->last_segment[dst_level_id][0] = ABSOLUTE_ADDRESS(level->last_segment[tree_id]);

	db_superblock->offset[dst_level_id][0] = level->offset[tree_id];

	db_superblock->level_size[dst_level_id][0] = level->level_size[tree_id];
	log_debug("Writing root[%u][%u] = %p", dst_level_id, tree_id, (void *)level->root[tree_id]);

	db_superblock->root_r[dst_level_id][0] = ABSOLUTE_ADDRESS(level->root[tree_id]);
}

void level_save_bf_info_to_superblock(struct device_level *level, struct pr_db_superblock *db_superblock)
{
	uint32_t dst_level_id = level->level_id;
	for (uint8_t tree_id = 0; tree_id < NUM_TREES_PER_LEVEL; tree_id++) {
		if (NULL == level->bloom_desc[tree_id]) {
			db_superblock->bloom_filter_hash[dst_level_id][tree_id] = UINT64_MAX;
			db_superblock->bloom_filter_valid[dst_level_id][tree_id] = 0;
			continue;
		}
		db_superblock->bloom_filter_hash[dst_level_id][tree_id] =
			pbf_get_bf_file_hash(level->bloom_desc[tree_id]);
		db_superblock->bloom_filter_valid[dst_level_id][tree_id] = 1;
	}
}

inline bool level_set_compaction_done(struct device_level *level)
{
	return !(level->compaction_in_progress = false);
}

bool level_does_key_exist(struct device_level *level, struct key_splice *key_splice)
{
	return pbf_check(level->bloom_desc[0], key_splice_get_key_offset(key_splice),
			 key_splice_get_key_size(key_splice));
}

uint8_t level_enter_as_reader(struct device_level *level)
{
	assert(level);
	assert(level->level_id > 0);
	RWLOCK_RDLOCK(&level->guard_of_level.rx_lock);
	__sync_fetch_and_add(&level->active_operations, 1);
	return UINT8_MAX;
}

uint8_t level_leave_as_reader(struct device_level *level)
{
	if (!level) //empty level
		return UINT8_MAX;
	RWLOCK_UNLOCK(&level->guard_of_level.rx_lock);
	__sync_fetch_and_sub(&level->active_operations, 1);
	return UINT8_MAX;
}

bool level_has_overflow(struct device_level *level, uint32_t tree_id)
{
	// log_debug("Level: %u current size: %lu max_size: %lu", level->level_id, level->level_size[tree_id],
	// 	  level->max_level_size);
	return level->level_size[tree_id] >= level->max_level_size;
}

bool level_start_comp_thread(struct device_level *level, compaction_func func, void *args)
{
	if (!level->compaction_in_progress) {
		log_fatal("Trying to start a compaction without prior setting level status to compacting... E R R O R");
		_exit(EXIT_FAILURE);
	}
	if (pthread_create(&level->compaction_thread, NULL, func, args) != 0) {
		log_fatal("Failed to start compaction");
		BUG_ON();
	}
	return true;
}

bool level_set_medium_in_place_seg_id(struct device_level *level, uint64_t segment_id)
{
	level->medium_in_place_max_segment_id = segment_id;
	return true;
}

bool level_set_medium_in_place_seg_offt(struct device_level *level, uint64_t segment_offt)
{
	level->medium_in_place_segment_dev_offt = segment_offt;
	return true;
}

bool level_zero(struct device_level *level, uint32_t tree_id)
{
	level->level_size[tree_id] = 0;
	level->first_segment[tree_id] = NULL;
	level->last_segment[tree_id] = NULL;
	level->offset[tree_id] = 0;
	level->root[tree_id] = NULL;
	level->num_level_keys[tree_id] = 0;
	return true;
}

bool level_set_root(struct device_level *level, uint32_t tree_id, struct node_header *node)
{
	level->root[tree_id] = node;
	return true;
}

bool level_swap(struct device_level *level_dst, uint32_t tree_dst, struct device_level *level_src, uint32_t tree_src)
{
	level_dst->first_segment[tree_dst] = level_src->first_segment[tree_src];
	level_src->first_segment[tree_src] = NULL;

	level_dst->last_segment[tree_dst] = level_src->last_segment[tree_src];
	level_src->last_segment[tree_src] = NULL;

	level_dst->offset[tree_dst] = level_src->offset[tree_src];
	level_src->offset[tree_src] = 0;

	level_dst->level_size[tree_dst] = level_src->level_size[tree_src];
	level_src->level_size[tree_src] = 0;

	level_dst->num_level_keys[tree_dst] = level_src->num_level_keys[tree_src];
	level_src->num_level_keys[tree_src] = 0;

	level_dst->bloom_desc[tree_dst] = level_src->bloom_desc[tree_src];
	level_src->bloom_desc[tree_src] = NULL;

	level_dst->root[tree_dst] = level_src->root[tree_src];
	level_src->root[tree_src] = NULL;

	return true;
}

bool level_destroy_bf(struct device_level *level, uint32_t tree_id)
{
	if (!level->bloom_desc[tree_id])
		return true;
	pbf_destroy_bloom_filter(level->bloom_desc[tree_id]);
	level->bloom_desc[tree_id] = NULL;
	return true;
}

int64_t level_get_num_KV_pairs(struct device_level *level, uint32_t tree_id)
{
	assert(0 == tree_id);
	return level->num_level_keys[tree_id];
}

bool level_create_bf(struct device_level *level, uint32_t tree_id, int64_t num_kv_pairs, struct db_handle *handle)
{
	level->bloom_desc[tree_id] = pbf_create(handle, level->level_id, num_kv_pairs, tree_id);
	return true;
}

bool level_persist_bf(struct device_level *level, uint32_t tree_id)
{
	if (!pbf_persist_bloom_filter(level->bloom_desc[tree_id])) {
		log_fatal("Failed to write bloom filter");
		_exit(EXIT_FAILURE);
	}
	return true;
}

bool level_increase_size(struct device_level *level, uint32_t size, uint32_t tree_id)
{
	level->level_size[tree_id] += size;
	// log_debug("Level_size[%u][%u] = %lu", level->level_id, tree_id, level->level_size[tree_id]);
	return true;
}

struct segment_header *level_allocate_segment(struct device_level *level, uint8_t tree_id,
					      struct db_descriptor *db_desc, uint64_t txn_id)
{
	if (0 == level->level_id) {
		log_fatal("This fuction is only for device levels");
		_exit(EXIT_FAILURE);
	}

	uint64_t seg_offt = seg_allocate_segment(db_desc, txn_id);
	//log_info("Allocated level segment %llu", seg_offt);
	struct segment_header *new_segment = (struct segment_header *)REAL_ADDRESS(seg_offt);
	if (!new_segment) {
		log_fatal("Failed to allocate space for new segment level");
		BUG_ON();
	}

	if (level->offset[tree_id])
		level->offset[tree_id] += SEGMENT_SIZE;
	else {
		level->offset[tree_id] = SEGMENT_SIZE;
		log_debug("Set first segment of level_id: %u tree_id: %u to %lu", level->level_id, tree_id,
			  new_segment);
		level->first_segment[tree_id] = new_segment;
		level->last_segment[tree_id] = NULL;
	}

	return new_segment;
}

bool level_add_key_to_bf(struct device_level *level, uint32_t tree_id, char *key, uint32_t key_size)
{
	pbf_bloom_add(level->bloom_desc[tree_id], key, key_size);
	return true;
}

int64_t level_inc_num_keys(struct device_level *level, uint32_t tree_id, uint32_t num_keys)
{
	// log_debug("Num level[%u][%u] keys are %ld", level->level_id, tree_id, level->num_level_keys[tree_id]);
	return level->num_level_keys[tree_id] += num_keys;
}

bool level_set_index_last_seg(struct device_level *level, struct segment_header *segment, uint32_t tree_id)
{
	level->last_segment[tree_id] = segment;
	return true;
}

uint64_t level_free_space(struct device_level *level, uint32_t tree_id, struct db_descriptor *db_desc, uint64_t txn_id)
{
	if (0 == level->level_id) {
		log_fatal("Only for device levels");
		_exit(EXIT_FAILURE);
	}
	// struct segment_header *curr_segment = db_desc->levels[level_id].first_segment[tree_id];
	// new staff
	struct segment_header *curr_segment = level->first_segment[tree_id];
	if (!curr_segment) {
		log_debug("Level [%u][%u] is free nothing to do", level->level_id, tree_id);
		return 0;
	}

	uint64_t space_freed = 0;

	while (curr_segment) {
		seg_free_segment(db_desc, txn_id, ABSOLUTE_ADDRESS(curr_segment));
		space_freed += SEGMENT_SIZE;
		curr_segment = NULL == curr_segment->next_segment ? NULL : REAL_ADDRESS(curr_segment->next_segment);
	}

	log_debug("Freed device level %u for db %s", level->level_id, db_desc->db_superblock->db_name);
	return space_freed;
}

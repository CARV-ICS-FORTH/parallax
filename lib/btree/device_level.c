#include "device_level.h"
#include "../allocator/device_structures.h"
#include "../allocator/log_structures.h"
#include "../allocator/redo_undo_log.h"
#include "../common/common.h"
#include "../utilities/spin_loop.h"
#include "bloom_filter.h"
#include "btree.h"
#include "btree_node.h"
#include "conf.h"
#include "dev_index.h"
#include "dev_leaf.h"
#include "fractal_index.h"
#include "fractal_leaf.h"
#include "key_splice.h"
#include "kv_pairs.h"
#include "segment_allocator.h"
#include "sst.h"
#include <asm-generic/errno.h>
#include <assert.h>
#include <log.h>
#include <minos.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
struct key_splice;
struct node_header;
extern const uint32_t *const size_per_height;

struct level_counter {
	int64_t active_operations;
	char pad[64 - sizeof(uint64_t)];
};

struct level_lock {
	pthread_rwlock_t rx_lock;
	// cppcheck-suppress unusedStructMember
	char pad[8];
};

struct device_level {
	//old school
	struct segment_header *first_segment[NUM_TREES_PER_LEVEL];
	struct segment_header *last_segment[NUM_TREES_PER_LEVEL];
	uint64_t offset[NUM_TREES_PER_LEVEL];
	struct node_header *root[NUM_TREES_PER_LEVEL];
	struct pbf_desc *bloom_desc[NUM_TREES_PER_LEVEL];
	uint64_t level_size[NUM_TREES_PER_LEVEL];
	int64_t num_level_keys[NUM_TREES_PER_LEVEL];
	pthread_t compaction_thread;

	pthread_mutex_t level_allocation_lock;
	uint64_t max_level_size;
	volatile struct segment_header *medium_log_head;
	volatile struct segment_header *medium_log_tail;
	uint64_t medium_log_size;
	// struct level_lock guard_of_level;
	// int64_t active_operations;
	struct level_counter active_ops[LEVEL_ENTRY_POINTS];
	struct level_lock guards[LEVEL_ENTRY_POINTS];
	/*info for trimming medium_log, used only in L_{n-1}*/
	uint64_t medium_in_place_max_segment_id;
	uint64_t medium_in_place_segment_dev_offt;
	struct level_leaf_api level_leaf_api;
	struct level_index_api level_index_api;
	struct minos *guard_table[NUM_TREES_PER_LEVEL];
	bool compaction_in_progress;
	uint8_t level_id;
	char in_recovery_mode;
};

struct device_level *level_create_fresh(uint32_t level_id, uint32_t l0_size, uint32_t growth_factor)
{
	struct device_level *level = calloc(1UL, sizeof(struct device_level));
	level->level_id = level_id;
	level->compaction_in_progress = false;

	for (int i = 0; i < LEVEL_ENTRY_POINTS; i++)
		RWLOCK_INIT(&level->guards[i].rx_lock, NULL);
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
	// log_debug("Level_id: %u has max level size of: %lu", level_id, level->max_level_size);

	dev_leaf_register(&level->level_leaf_api);
	dev_idx_register(&level->level_index_api);
	// frac_leaf_register(&level->level_leaf_api);
	// frac_idx_register(&level->level_index_api);
	for (int i = 0; i < NUM_TREES_PER_LEVEL; i++)
		level->guard_table[i] = minos_init();

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
		/*level size in B*/
		level->level_size[tree_id] = superblock->level_size[level_id][tree_id];
		/*level keys*/
		level->num_level_keys[tree_id] = superblock->num_level_keys[level_id][tree_id];
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
	log_fatal("Should not use this method with SSTs");
	assert(0);
	_exit(EXIT_FAILURE);
	return level->root[tree_id];
}

bool level_is_empty(struct device_level *level, uint32_t tree_id)
{
	return level->guard_table[tree_id] == NULL ? true : minos_is_empty(level->guard_table[tree_id]);
}

// cppcheck-suppress unusedFunction
inline uint64_t level_get_root_dev_offt(struct device_level *level, uint32_t tree_id)
{
	struct node_header *root = level_get_root(level, tree_id);
	return ABSOLUTE_ADDRESS(root);
}

inline struct segment_header *level_get_index_first_seg(struct device_level *level, uint32_t tree_id)
{
	return level->first_segment[tree_id];
}

// cppcheck-suppress unusedFunction
inline uint64_t level_get_index_first_seg_offt(struct device_level *level, uint32_t tree_id)
{
	struct segment_header *first = level_get_index_first_seg(level, tree_id);
	return ABSOLUTE_ADDRESS(first);
}

inline struct segment_header *level_get_index_last_seg(struct device_level *level, uint32_t tree_id)
{
	return level->last_segment[tree_id];
}

// cppcheck-suppress unusedFunction
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

uint64_t level_trim_medium_log(struct device_level *level, struct db_descriptor *db_desc, uint64_t txn_id)
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

static unsigned long long level_get_tsc(void)
{
#ifdef __x86_64__
	unsigned int low;
	unsigned int high;
	__asm__ volatile("rdtsc" : "=a"(low), "=d"(high));
	return ((unsigned long long)high << 32) | low;
#else
	return pthread_self();
#endif
}

uint8_t level_enter_as_writer(struct device_level *level)
{
	for (uint8_t ticket_id = 0; ticket_id < LEVEL_ENTRY_POINTS; ticket_id++) {
		RWLOCK_WRLOCK(&level->guards[ticket_id].rx_lock);
		spin_loop(&level->active_ops[ticket_id].active_operations, 0);
	}
	// RWLOCK_WRLOCK(&level->guard_of_level.rx_lock);
	// spin_loop(&level->active_operations, 0);
	return UINT8_MAX;
}

void level_leave_as_writer(struct device_level *level)
{
	for (uint8_t ticket_id = 0; ticket_id < LEVEL_ENTRY_POINTS; ticket_id++)
		RWLOCK_UNLOCK(&level->guards[ticket_id].rx_lock);
	// RWLOCK_UNLOCK(&level->guard_of_level.rx_lock);
}

uint8_t level_enter_as_reader(struct device_level *level)
{
	if (!level) //empty level
		return UINT8_MAX;
	assert(level->level_id > 0);
	uint8_t ticket_id = level_get_tsc() % LEVEL_ENTRY_POINTS;
	RWLOCK_RDLOCK(&level->guards[ticket_id].rx_lock);
	assert(level->active_ops[ticket_id].active_operations >= 0);
	__sync_fetch_and_add(&level->active_ops[ticket_id].active_operations, 1);
	RWLOCK_UNLOCK(&level->guards[ticket_id].rx_lock);
	return ticket_id;
}

uint8_t level_leave_as_reader(struct device_level *level, uint8_t ticket_id)
{
	if (!level) //empty level
		return UINT8_MAX;
	// RWLOCK_UNLOCK(&level->guard_of_level.rx_lock);
	__sync_fetch_and_sub(&level->active_ops[ticket_id].active_operations, 1);
	assert(level->active_ops[ticket_id].active_operations >= 0);
	return UINT8_MAX;
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

	db_superblock->num_level_keys[dst_level_id][0] = level->num_level_keys[tree_id];

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
	// log_debug("Bloom for level[%u][%u] is  %p", level->level_id, tree_id, (void *)level->bloom_desc[tree_id]);
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

struct segment_header *level_add_segment(struct device_level *level, uint8_t tree_id, uint64_t seg_offt)
{
	assert(seg_offt > 0);
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
			  (uint64_t)new_segment);
		level->first_segment[tree_id] = new_segment;
		level->last_segment[tree_id] = NULL;
	}

	return new_segment;
}

struct segment_header *level_allocate_segment(struct device_level *level, uint8_t tree_id,
					      struct db_descriptor *db_desc, uint64_t txn_id)
{
	uint64_t seg_offt = seg_allocate_segment(db_desc, txn_id);
	return level_add_segment(level, tree_id, seg_offt);
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

struct args {
	db_descriptor *db_desc;
	uint64_t txn_id;
};
static bool level_free_sst(void *value, void *cnxt)
{
	struct sst_meta *meta = (struct sst_meta *)value;
	struct args *args = cnxt;
	struct rul_log_entry log_entry = { .dev_offt = sst_meta_get_dev_offt(meta),
					   .txn_id = args->txn_id,
					   .op_type = RUL_FREE_SST,
					   .size = sst_meta_get_size(meta) };
	rul_add_entry_in_txn_buf(args->db_desc, &log_entry);
	return true;
}

uint64_t level_free_space(struct device_level *level, uint32_t tree_id, struct db_descriptor *db_desc, uint64_t txn_id)
{
	struct args args = { .db_desc = db_desc, .txn_id = txn_id };
	uint32_t sst_num_freed = minos_free(level->guard_table[tree_id], level_free_sst, &args);
	level->guard_table[tree_id] = NULL;
	// struct segment_header *curr_segment = level->first_segment[tree_id];
	// if (!curr_segment) {
	// 	log_debug("Level [%u][%u] is free nothing to do", level->level_id, tree_id);
	// 	return 0;
	// }

	// uint64_t space_freed = 0;

	// while (curr_segment) {
	// 	seg_free_segment(db_desc, txn_id, ABSOLUTE_ADDRESS(curr_segment));
	// 	space_freed += SEGMENT_SIZE;
	// 	curr_segment = NULL == curr_segment->next_segment ? NULL : REAL_ADDRESS(curr_segment->next_segment);
	// }

	// log_debug("Freed device level %u for db %s", level->level_id, db_desc->db_superblock->db_name);
	return sst_num_freed * SST_SIZE;
}

struct level_leaf_api *level_get_leaf_api(struct device_level *level)
{
	return &level->level_leaf_api;
}

struct level_index_api *level_get_index_api(struct device_level *level)
{
	return &level->level_index_api;
}

/**
  * @brief Fetches the leaf which is responsible to host the key splice
  * @param level pointer to the device level object
  * @param key_splice pointer to the key splice object
*/
static struct leaf_node *level_get_leaf(struct device_level *level, struct key_splice *key_splice, uint8_t tree_id)
{
	assert(key_splice_get_key_offset(key_splice));
	// log_debug("Searching appropriate leaf for key: %.*s size: %d at tree_id: %u", key_splice_get_key_size(key_splice),
	//    key_splice_get_key_offset(key_splice), key_splice_get_key_size(key_splice),tree_id);
	struct minos_iterator iter;
	bool exact_match = false;
	bool valid = minos_iter_seek_equal_or_imm_less(&iter, level->guard_table[tree_id],
						       key_splice_get_key_size(key_splice),
						       key_splice_get_key_offset(key_splice), &exact_match);

	struct sst_meta *meta = valid ? iter.iter_node->kv->value : NULL;
	if (NULL == meta)
		return NULL;
	struct key_splice *first = sst_meta_get_first_guard(meta);
	struct key_splice *last = sst_meta_get_last_guard(meta);
	if (memcmp(key_splice_get_key_offset(key_splice), key_splice_get_key_offset(last),
		   key_splice_get_key_size(key_splice)) > 0) {
		log_fatal("Got wrong sst for splice: %.*s last splice is %.*s", key_splice_get_key_size(key_splice),
			  key_splice_get_key_offset(key_splice), key_splice_get_key_size(last),
			  key_splice_get_key_offset(last));
		log_fatal("Got wrong sst first guard splice is %.*s", key_splice_get_key_size(first),
			  key_splice_get_key_offset(first));
		_exit(EXIT_FAILURE);
	}
	//debug
	// log_debug("SST responsible has first key: %.*s and last key %.*s root offt at: %lu", key_splice_get_key_size(first),
	//    key_splice_get_key_offset(first), key_splice_get_key_size(last), key_splice_get_key_offset(last),
	//    sst_meta_get_root(meta));

	struct node_header *son_node = NULL;
	uint64_t root_offt = sst_meta_get_root(meta);
	struct node_header *curr_node = REAL_ADDRESS(root_offt);
	// log_debug("Root has height: %u and num entries: %u", curr_node->height, curr_node->num_entries);
	assert(curr_node->num_entries);

	while (curr_node->type != leafNode && curr_node->type != leafRootNode) {
		//No locking needed for the device levels >= 1
		uint64_t child_offset = (*level->level_index_api.index_search)((struct index_node *)curr_node,
									       key_splice_get_key_offset(key_splice),
									       key_splice_get_key_size(key_splice));

		son_node = (void *)REAL_ADDRESS(child_offset);

		curr_node = son_node;
	}
	return (struct leaf_node *)curr_node;
}

bool level_lookup(struct device_level *level, struct lookup_operation *get_op, int tree_id)
{
	uint8_t ticket_id = level_enter_as_reader(level);
	get_op->found = 0;
	get_op->key_device_address = NULL;
	if (!level_does_key_exist(level, get_op->key_splice)) {
		goto done;
	}
	struct leaf_node *curr_node = level_get_leaf(level, get_op->key_splice, tree_id);

	if (NULL == curr_node) {
		log_debug("Level is empty");
		goto done;
	}

	int32_t key_size = key_splice_get_key_size(get_op->key_splice);
	void *key = key_splice_get_key_offset(get_op->key_splice);
	const char *error = NULL;
	struct kv_splice_base splice =
		(*level->level_leaf_api.leaf_find)((struct leaf_node *)curr_node, key, key_size, &error);

	if (error != NULL)
		goto done;

	get_op->tombstone = splice.is_tombstone;
	if (get_op->tombstone)
		goto done;

	get_op->found = 1;

	struct bt_kv_log_address kv_pair = { .addr = NULL, .tail_id = UINT8_MAX, .in_tail = 0 };

	kv_pair.addr = (char *)splice.kv_splice;
	if (splice.kv_cat == MEDIUM_INLOG || splice.kv_cat == BIG_INLOG) {
		uint64_t value_offt = kv_sep2_get_value_offt(splice.kv_sep2);
		kv_pair.addr = REAL_ADDRESS(value_offt);
	}

	int32_t value_size = kv_splice_get_value_size((struct kv_splice *)kv_pair.addr);

	get_op->buffer_overflow = 0;

	if (get_op->buffer_to_pack_kv && value_size > get_op->size)
		get_op->buffer_overflow = 1;

	if (!get_op->buffer_to_pack_kv)
		get_op->buffer_to_pack_kv = calloc(1UL, value_size);

	memcpy(get_op->buffer_to_pack_kv,
	       kv_splice_get_value_offset_in_kv((struct kv_splice *)kv_pair.addr,
						kv_splice_get_key_size((struct kv_splice *)kv_pair.addr)),
	       value_size);
	get_op->size = value_size;

done:
	level_leave_as_reader(level, ticket_id);
	return get_op->found;
}

//functions about scanning device levels

//staff about device level scanners
struct level_scanner_dev {
	db_handle *db;
	char *IO_buffer;
	struct device_level *level;
	struct node_header *root;
	struct level_leaf_api *leaf_api;
	struct level_index_api *index_api;
	struct leaf_iterator *leaf_iter;
	struct leaf_node *leaf;
	struct sst_meta *curr_sst;
	uint8_t level_id;
	uint8_t tree_id;
};

struct level_scanner_dev *level_scanner_dev_init(db_handle *database, uint8_t level_id, uint8_t tree_id)
{
	struct level_scanner_dev *level_scanner = calloc(1UL, sizeof(*level_scanner));
	level_scanner->db = database;
	level_scanner->level_id = level_id;
	level_scanner->level = database->db_desc->dev_levels[level_id];
	level_scanner->root = NULL;

	level_scanner->leaf_api = level_get_leaf_api(database->db_desc->dev_levels[level_id]);
	level_scanner->index_api = level_get_index_api(database->db_desc->dev_levels[level_id]);
	level_scanner->leaf = NULL;
	level_scanner->tree_id = tree_id;
	level_scanner->leaf_iter = level_scanner->leaf_api->leaf_create_empty_iter();
	return level_scanner;
}

bool level_scanner_dev_seek(struct level_scanner_dev *dev_level_scanner, struct key_splice *start_key_splice)
{
	struct leaf_node *leaf = NULL;
	if (!start_key_splice) {
		struct minos_iterator iter;
		log_debug("Scanner tree_id: %u", dev_level_scanner->tree_id);
		minos_iter_seek_first(&iter, dev_level_scanner->level->guard_table[dev_level_scanner->tree_id]);
		struct sst_meta *meta = iter.iter_node->kv->value;
		start_key_splice = sst_meta_get_first_guard(meta);
		leaf = level_get_leaf(dev_level_scanner->level, start_key_splice, dev_level_scanner->tree_id);
		log_debug("Done fetching first SST with key: %.*s", key_splice_get_key_size(start_key_splice),
			  key_splice_get_key_offset(start_key_splice));
	} else {
		log_debug("Fetching next SST");
		leaf = level_get_leaf(dev_level_scanner->level, start_key_splice, dev_level_scanner->tree_id);
	}
	// cppcheck-suppress variableScope
	// char smallest_possible_pivot[SMALLEST_POSSIBLE_PIVOT_SIZE];
	// if (!start_key_splice) {
	// 	bool malloced = false;
	// 	start_key_splice =
	// 		key_splice_create_smallest(smallest_possible_pivot, SMALLEST_POSSIBLE_PIVOT_SIZE, &malloced);
	// 	if (malloced) {
	// 		log_fatal("Buffer not large enough to create smallest possible key_splice");
	// 		_exit(EXIT_FAILURE);
	// 	}
	// }
	// struct leaf_node *leaf = level_get_leaf(dev_level_scanner->level, start_key_splice, dev_level_scanner->tree_id);
	dev_level_scanner->leaf = leaf;
	return (*dev_level_scanner->leaf_api->leaf_seek_iter)(leaf, dev_level_scanner->leaf_iter,
							      key_splice_get_key_offset(start_key_splice),
							      key_splice_get_key_size(start_key_splice));
}

bool level_scanner_curr(struct level_scanner_dev *dev_level_scanner, struct kv_splice_base *splice)
{
	bool valid = (*dev_level_scanner->leaf_api->leaf_is_iter_valid)(dev_level_scanner->leaf_iter);
	if (!valid)
		return false;

	*splice = (*dev_level_scanner->leaf_api->leaf_iter_curr)(dev_level_scanner->leaf_iter);
	// log_debug("Curr kv splice is key %.*s", kv_splice_base_get_key_size(splice),
	// 	  kv_splice_base_get_key_buf(splice));
	return true;
}

static uint64_t level_scanner_find_next_leaf(struct level_scanner_dev *dev_level_scanner)
{
	struct kv_splice_base last = (*dev_level_scanner->leaf_api->leaf_get_last)(dev_level_scanner->leaf);
	struct minos_iterator iter;
	bool exact_match;
	bool valid = minos_iter_seek_equal_or_imm_less(
		&iter, dev_level_scanner->level->guard_table[dev_level_scanner->tree_id],
		kv_splice_base_get_key_size(&last), kv_splice_base_get_key_buf(&last), &exact_match);
	if (!valid)
		return 0;
	minos_iter_get_next(&iter);
	if (!minos_iter_is_valid(&iter))
		return 0;

	struct sst_meta *meta = iter.iter_node->kv->value;
	return sst_meta_get_first_leaf_offt(meta);
}

bool level_scanner_dev_next(struct level_scanner_dev *dev_level_scanner)
{
	bool ret = (*dev_level_scanner->leaf_api->leaf_iter_next)(dev_level_scanner->leaf_iter);

	if (ret)
		return ret;
	uint64_t next_leaf_offt = (*dev_level_scanner->leaf_api->leaf_get_next_offt)(dev_level_scanner->leaf);
	if (0 == next_leaf_offt) {
		// log_debug("Done with the currest SST let's go to the next");
		next_leaf_offt = level_scanner_find_next_leaf(dev_level_scanner);
		if (0 == next_leaf_offt) {
			// log_debug("Done with the level");
			return false;
		}
	}
	dev_level_scanner->leaf = REAL_ADDRESS(next_leaf_offt);
	// log_debug("Leaf num entries are: %d", (*dev_level_scanner->leaf_api->leaf_get_entries)(dev_level_scanner->leaf));
	return (*dev_level_scanner->leaf_api->leaf_seek_first)(dev_level_scanner->leaf, dev_level_scanner->leaf_iter);
}

bool level_scanner_dev_close(struct level_scanner_dev *dev_level_scanner)
{
	free(dev_level_scanner);
	return true;
}
//end of device level scanners staff
bool level_add_ssts(struct device_level *level, int num_ssts, struct sst_meta *ssts[], uint32_t tree_id)
{
	level_enter_as_writer(level);

	if (level->guard_table[tree_id] == NULL)
		level->guard_table[tree_id] = minos_init();

	for (int i = 0; i < num_ssts; i++) {
		struct key_splice *first = sst_meta_get_first_guard(ssts[i]);
		log_debug("Adding in guard table key: %.*s size: %d tree_id: %u", key_splice_get_key_size(first),
			  key_splice_get_key_offset(first), key_splice_get_key_size(first), tree_id);
		struct minos_insert_request req = { .key = key_splice_get_key_offset(first),
						    .key_size = key_splice_get_key_size(first),
						    .value = ssts[i],
						    .value_size = sst_meta_get_size(ssts[i]) };
		minos_insert(level->guard_table[tree_id], &req);
	}

	level_leave_as_writer(level);
	return true;
}

bool level_remove_sst(struct device_level *level, struct sst_meta *sst, uint32_t tree_id)
{
	level_enter_as_writer(level);
	struct key_splice *first = sst_meta_get_first_guard(sst);
	log_debug("Removing key from guard table: %.*s size: %d tree_id: %u", key_splice_get_key_size(first),
		  key_splice_get_key_offset(first), key_splice_get_key_size(first), tree_id);
	bool ret = minos_delete(level->guard_table[tree_id], key_splice_get_key_offset(first),
				key_splice_get_key_size(first));

	level_leave_as_writer(level);
	return ret;
}

//compaction scanner staff
struct level_compaction_scanner {
	struct minos_iterator iter;
	char *IO_buffer;
	struct sst_meta *meta;
	struct device_level *level;
	struct leaf_node *curr_leaf;
	struct leaf_iterator *leaf_iter;
	struct level_leaf_api *leaf_api;
	uint32_t sst_size;
	uint32_t relative_leaf_offt;
	int fd;
};

static bool level_comp_scanner_read_sst(struct level_compaction_scanner *comp_scanner)
{
	ssize_t total_bytes_read = 0;
	while (total_bytes_read < comp_scanner->sst_size) {
		ssize_t read = pread(comp_scanner->fd, &comp_scanner->IO_buffer[total_bytes_read],
				     comp_scanner->sst_size - total_bytes_read,
				     sst_meta_get_dev_offt(comp_scanner->meta) + total_bytes_read);
		if (-1 == read) {
			log_fatal("Failed to read SST");
			perror("Reason:");
			_exit(EXIT_FAILURE);
		}
		total_bytes_read += read;
	}
	return true;
}

struct level_compaction_scanner *level_comp_scanner_init(struct device_level *level, uint8_t tree_id, uint32_t sst_size,
							 int file_desc)
{
	struct level_compaction_scanner *comp_scanner = calloc(1UL, sizeof(struct level_compaction_scanner));
	posix_memalign((void **)&comp_scanner->IO_buffer, ALIGNMENT, sst_size);
	comp_scanner->sst_size = sst_size;
	comp_scanner->fd = file_desc;
	minos_iter_seek_first(&comp_scanner->iter, level->guard_table[tree_id]);
	comp_scanner->meta = comp_scanner->iter.iter_node->kv->value;
	level_comp_scanner_read_sst(comp_scanner);
	comp_scanner->relative_leaf_offt = sst_meta_get_first_leaf_relative_offt(comp_scanner->meta);
	comp_scanner->leaf_api = &level->level_leaf_api;
	comp_scanner->curr_leaf = (struct leaf_node *)&comp_scanner->IO_buffer[comp_scanner->relative_leaf_offt];
	comp_scanner->leaf_iter = (*comp_scanner->leaf_api->leaf_create_empty_iter)();
	(*comp_scanner->leaf_api->leaf_seek_first)(comp_scanner->curr_leaf, comp_scanner->leaf_iter);
	return comp_scanner;
}

bool level_comp_scanner_next(struct level_compaction_scanner *comp_scanner)
{
	bool val = (*comp_scanner->leaf_api->leaf_iter_next)(comp_scanner->leaf_iter);
	if (val)
		return true;

	if (sst_meta_get_next_relative_leaf_offt(&comp_scanner->relative_leaf_offt, comp_scanner->IO_buffer)) {
		comp_scanner->curr_leaf =
			(struct leaf_node *)&comp_scanner->IO_buffer[comp_scanner->relative_leaf_offt];
		(*comp_scanner->leaf_api->leaf_seek_first)(comp_scanner->curr_leaf, comp_scanner->leaf_iter);
		return true;
	}
	minos_iter_get_next(&comp_scanner->iter);
	if (false == minos_iter_is_valid(&comp_scanner->iter))
		return false;
	comp_scanner->meta = comp_scanner->iter.iter_node->kv->value;
	level_comp_scanner_read_sst(comp_scanner);
	comp_scanner->relative_leaf_offt = sst_meta_get_first_leaf_relative_offt(comp_scanner->meta);
	comp_scanner->curr_leaf = (struct leaf_node *)&comp_scanner->IO_buffer[comp_scanner->relative_leaf_offt];
	(*comp_scanner->leaf_api->leaf_seek_first)(comp_scanner->curr_leaf, comp_scanner->leaf_iter);
	return true;
}

bool level_comp_scanner_get_curr(struct level_compaction_scanner *comp_scanner, struct kv_splice_base *splice)
{
	*splice = (*comp_scanner->leaf_api->leaf_iter_curr)(comp_scanner->leaf_iter);
	return true;
}

bool level_comp_scanner_close(struct level_compaction_scanner *comp_scanner)
{
	free(comp_scanner->leaf_iter);
	free(comp_scanner->IO_buffer);
	free(comp_scanner);
	return true;
}

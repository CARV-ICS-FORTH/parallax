#include "device_level.h"
#include "../../include/parallax/structures.h"
#include "../../utilities/spin_loop.h"
#include "../allocator/device_structures.h"
#include "../allocator/log_structures.h"
#include "../allocator/region_log.h"
#include "../btree.h"
#include "../btree_node.h"
#include "../common/common.h"
#include "../conf.h"
#include "../key_splice.h"
#include "../kv_pairs.h"
//old school
// #include "bloom_filter.h"
#include "dev_index.h"
#include "dev_leaf.h"
#include "sst.h"
#include <assert.h>
#include <log.h>
#include <minos.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct key_splice;
#define DEVICE_LEVEL_CACHE_LINE_SIZE 64

struct level_counter {
	int64_t active_operations;
	// cppcheck-suppress unusedStructMember
	char pad[DEVICE_LEVEL_CACHE_LINE_SIZE - sizeof(int64_t)];
};

struct level_lock {
	pthread_rwlock_t rx_lock;
	// cppcheck-suppress unusedStructMember
	char pad[8];
};

struct device_level {
	uint64_t level_size[NUM_TREES_PER_LEVEL];
	int64_t num_level_keys[NUM_TREES_PER_LEVEL];
	pthread_t compaction_thread;

	pthread_mutex_t level_allocation_lock;
	uint64_t max_level_size;
	volatile struct segment_header *medium_log_head;
	volatile struct segment_header *medium_log_tail;
	uint64_t medium_log_size;

	/*info for trimming medium_log, used only in L_{n-1}*/
	uint64_t medium_in_place_max_segment_id;
	uint64_t medium_in_place_segment_dev_offt;
	struct level_leaf_api level_leaf_api;
	struct level_index_api level_index_api;
	struct minos *guard_table[NUM_TREES_PER_LEVEL];
	bool compaction_in_progress;
	uint8_t level_id;
	char in_recovery_mode;
	struct level_lock guards[LEVEL_ENTRY_POINTS];
	struct level_counter active_ops[LEVEL_ENTRY_POINTS];
};

struct device_level *level_create_fresh(uint32_t level_id, uint32_t l0_size, uint32_t growth_factor)
{
	struct device_level *level = calloc(1UL, sizeof(struct device_level));
	level->level_id = level_id;
	level->compaction_in_progress = false;

	for (int i = 0; i < LEVEL_ENTRY_POINTS; i++) {
		RWLOCK_INIT(&level->guards[i].rx_lock, NULL);
		level->active_ops[i].active_operations = 0;
	}
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
		level->guard_table[i] = minos_init(false);

	return level;
}

struct device_level *level_restore_from_device(uint32_t level_id, struct pr_db_superblock *superblock,
					       uint32_t num_trees, uint64_t l0_size, uint32_t growth_factor)
{
	/*restore now persistent state of all levels*/
	struct device_level *level = level_create_fresh(level_id, l0_size, growth_factor);

	for (uint32_t tree_id = 0; tree_id < num_trees; tree_id++) {
		/*level size in B*/
		level->level_size[tree_id] = superblock->level_size[level_id][tree_id];
		/*level keys*/
		level->num_level_keys[tree_id] = superblock->num_level_keys[level_id][tree_id];
	}

	return level;
}

bool level_is_empty(struct device_level *level, uint32_t tree_id)
{
	return level->guard_table[tree_id] == NULL ? true : minos_is_empty(level->guard_table[tree_id]);
}

inline uint64_t level_get_size(struct device_level *level, uint32_t tree_id)
{
	return level_is_empty(level, tree_id) ? 0 : level->level_size[tree_id];
}

static inline bool level_is_medium_log_trimmable(const struct device_level *level, uint64_t medium_log_head_offt)
{
	return !(0 == level->medium_in_place_segment_dev_offt ||
		 level->medium_in_place_segment_dev_offt == medium_log_head_offt);
}

uint64_t level_trim_medium_log(struct device_level *level, struct db_descriptor *db_desc, uint64_t txn_id)
{
	uint64_t new_medium_log_head_offt = level->medium_in_place_segment_dev_offt;
	if (false == level_is_medium_log_trimmable(level, db_desc->medium_log.head_dev_offt))
		return new_medium_log_head_offt;

	struct segment_header *trim_end_segment = REAL_ADDRESS(level->medium_in_place_segment_dev_offt);
	const struct segment_header *head = REAL_ADDRESS(db_desc->medium_log.head_dev_offt);
	uint64_t bytes_freed = 0;
	(void)bytes_freed;

	for (struct segment_header *curr_trim_segment = REAL_ADDRESS(trim_end_segment->prev_segment);;
	     curr_trim_segment = REAL_ADDRESS(curr_trim_segment->prev_segment)) {
		struct regl_log_entry log_entry = { .dev_offt = ABSOLUTE_ADDRESS(curr_trim_segment),
						    .txn_id = txn_id,
						    .op_type = REGL_FREE,
						    .size = SEGMENT_SIZE };
		regl_add_entry_in_txn_buf(db_desc, &log_entry);
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
	assert(level);
	if (!level) //empty level
		return UINT8_MAX;
	assert(level->level_id > 0);
	uint8_t ticket_id = level_get_tsc() % LEVEL_ENTRY_POINTS;
	RWLOCK_RDLOCK(&level->guards[ticket_id].rx_lock);
	__sync_fetch_and_add(&level->active_ops[ticket_id].active_operations, 1);
	RWLOCK_UNLOCK(&level->guards[ticket_id].rx_lock);
	return ticket_id;
}

uint8_t level_leave_as_reader(struct device_level *level, uint8_t ticket_id)
{
	assert(level);
	if (!level) //empty level
		return UINT8_MAX;
	__sync_fetch_and_sub(&level->active_ops[ticket_id].active_operations, 1);
	return UINT8_MAX;
}

void level_set_comp_in_progress(struct device_level *level)
{
	level->compaction_in_progress = true;
}

inline bool level_is_compacting(const struct device_level *level)
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
	db_superblock->level_size[dst_level_id][0] = level->level_size[tree_id];
	db_superblock->num_level_keys[dst_level_id][0] = level->num_level_keys[tree_id];
}

inline bool level_set_compaction_done(struct device_level *level)
{
	return !(level->compaction_in_progress = false);
}

bool level_has_overflow(struct device_level *level, uint32_t tree_id)
{
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
	// level->first_segment[tree_id] = NULL;
	// level->last_segment[tree_id] = NULL;
	// level->offset[tree_id] = 0;
	// level->root[tree_id] = NULL;
	level->num_level_keys[tree_id] = 0;
	level->guard_table[tree_id] = NULL;
	return true;
}

bool level_swap(struct device_level *level_dst, uint32_t tree_dst, struct device_level *level_src, uint32_t tree_src)
{
	level_dst->level_size[tree_dst] = level_src->level_size[tree_src];
	level_src->level_size[tree_src] = 0;

	level_dst->num_level_keys[tree_dst] = level_src->num_level_keys[tree_src];
	level_src->num_level_keys[tree_src] = 0;

	level_dst->guard_table[tree_dst] = level_src->guard_table[tree_src];
	level_src->guard_table[tree_src] = NULL;
	return true;
}

int64_t level_get_num_KV_pairs(struct device_level *level, uint32_t tree_id)
{
	assert(0 == tree_id);
	return level->num_level_keys[tree_id];
}

bool level_increase_size(struct device_level *level, uint32_t size, uint32_t tree_id)
{
	level->level_size[tree_id] += size;
	return true;
}

int64_t level_inc_num_keys(struct device_level *level, uint32_t tree_id, uint32_t num_keys)
{
	return level->num_level_keys[tree_id] += num_keys;
}

struct level_free_sst_cb_args {
	db_descriptor *db_desc;
	uint64_t txn_id;
};
static bool level_free_sst(void *value, void *cnxt)
{
	struct sst_meta *meta = *(struct sst_meta **)value;
	struct level_free_sst_cb_args *args = cnxt;
	struct regl_log_entry log_entry = { .dev_offt = sst_meta_get_dev_offt(meta),
					    .txn_id = args->txn_id,
					    .op_type = REGL_FREE_SST,
					    .size = sst_meta_get_size() };
	regl_add_entry_in_txn_buf(args->db_desc, &log_entry);
	//Release the memory guard
	sst_meta_destroy(meta);
	return true;
}

uint64_t level_free_space(struct device_level *level, uint32_t tree_id, struct db_descriptor *db_desc, uint64_t txn_id)
{
	struct level_free_sst_cb_args args = { .db_desc = db_desc, .txn_id = txn_id };
	uint32_t sst_num_freed = minos_free(level->guard_table[tree_id], level_free_sst, &args);
	level->guard_table[tree_id] = NULL;
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

static struct sst_meta *level_get_first_sst(struct device_level *level, struct minos_iterator *iter, uint8_t tree_id)
{
	minos_iter_seek_first(iter, level->guard_table[tree_id]);
	struct sst_meta *meta = *(struct sst_meta **)iter->iter_node->kv->value;
	return meta;
}

static struct sst_meta *level_find_sst(struct device_level *level, struct minos_iterator *iter,
				       struct key_splice *key_splice, uint8_t tree_id)
{
	// log_debug("Searching appropriate leaf for key: %.*s size: %d at tree_id: %u", key_splice_get_key_size(key_splice),
	//    key_splice_get_key_offset(key_splice), key_splice_get_key_size(key_splice),tree_id);

	struct sst_meta *meta = NULL;
	char smallest = 0; //Remove this hack TODO
	bool is_smallest = key_splice_get_key_size(key_splice) == 1 &&
			   0 == memcmp(key_splice_get_key_offset(key_splice), &smallest, 1);
	if (is_smallest)
		return level_get_first_sst(level, iter, tree_id);

	bool exact_match = false;
	bool valid = minos_iter_seek_equal_or_imm_less(iter, level->guard_table[tree_id],
						       key_splice_get_key_size(key_splice),
						       key_splice_get_key_offset(key_splice), &exact_match);

	meta = valid ? *(struct sst_meta **)iter->iter_node->kv->value : NULL;

	if (NULL == meta) {
		// struct minos_iterator iter2;
		// minos_iter_seek_first(&iter2, level->guard_table[tree_id]);
		// log_debug("Nothing search key is: %.*s first guard key: %.*s level: %u",
		// 	  key_splice_get_key_size(key_splice), key_splice_get_key_offset(key_splice),
		// 	  iter2.iter_node->kv->key_size, iter2.iter_node->kv->key, level->level_id);
		return NULL;
	}
	return meta;
}
/**
  * @brief Fetches the leaf which is responsible to host the key splice
  * @param level pointer to the device level object
  * @param meta pointer to the sst meta object
  * @param key_splice pointer to the key splice object
*/
static struct leaf_node *level_get_leaf(struct device_level *level, const struct sst_meta *meta,
					struct key_splice *key_splice)
{
	assert(key_splice_get_key_offset(key_splice));
	struct node_header *son_node = NULL;
	uint64_t root_offt = sst_meta_get_root_offt(meta);
	struct node_header *curr_node = REAL_ADDRESS(root_offt);
	assert(curr_node->type == rootNode || curr_node->type == leafRootNode);
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

	if (level_is_empty(level, tree_id))
		goto done;

	struct minos_iterator iter;
	const struct sst_meta *meta = level_find_sst(level, &iter, get_op->key_splice, tree_id);
	if (NULL == meta || false == sst_key_exists(meta, get_op->key_splice))
		goto done;

	struct leaf_node *curr_node = level_get_leaf(level, meta, get_op->key_splice);
	assert(curr_node);

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
	struct device_level *level;
	struct node_header *root;
	struct level_leaf_api *leaf_api;
	struct level_index_api *index_api;
	struct leaf_iterator *leaf_iter;
	struct leaf_node *leaf;
	struct minos_iterator sst_iter;
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

static int level_cmp_keys(const char *key1, int key1_size, const char *key2, int key2_size)
{
	int ret = memcmp(key1, key2, key1_size < key2_size ? key1_size : key2_size);
	return ret ? ret : key1_size - key2_size;
}

bool level_scanner_dev_seek(struct level_scanner_dev *dev_level_scanner, struct key_splice *start_key_splice,
			    bool is_greater)
{
	// log_debug("---->new seek for level: %u",dev_level_scanner->level_id);
	if (start_key_splice == NULL) {
		log_fatal("start key cannot be NULL");
		_exit(EXIT_FAILURE);
	}
	struct leaf_node *leaf = NULL;
	struct sst_meta *meta = level_find_sst(dev_level_scanner->level, &dev_level_scanner->sst_iter, start_key_splice,
					       dev_level_scanner->tree_id);
	if (NULL == meta) {
		// log_debug("No SST from level fetch first just in case");
		meta = level_get_first_sst(dev_level_scanner->level, &dev_level_scanner->sst_iter,
					   dev_level_scanner->tree_id);
		assert(meta);
	}

	leaf = level_get_leaf(dev_level_scanner->level, meta, start_key_splice);
	assert(leaf);
	dev_level_scanner->leaf = leaf;
	(*dev_level_scanner->leaf_api->leaf_seek_iter)(leaf, dev_level_scanner->leaf_iter,
						       key_splice_get_key_offset(start_key_splice),
						       key_splice_get_key_size(start_key_splice));
	if (false == is_greater)
		return true;

	struct kv_splice_base curr = { 0 };
	bool ret = true;
	while ((ret = level_scanner_dev_curr(dev_level_scanner, &curr)) &&
	       level_cmp_keys(kv_splice_base_get_key_buf(&curr), kv_splice_base_get_key_size(&curr),
			      key_splice_get_key_offset(start_key_splice),
			      key_splice_get_key_size(start_key_splice)) <= 0) {
		if (false == level_scanner_dev_next(dev_level_scanner))
			return false;
	}
	return ret;
}

static uint64_t level_scanner_dev_find_next_leaf(struct level_scanner_dev *dev_level_scanner)
{
	minos_iter_get_next(&dev_level_scanner->sst_iter);
	if (!minos_iter_is_valid(&dev_level_scanner->sst_iter)) {
		// log_debug("Done! with SSTs of level: %u",dev_level_scanner->level->level_id);
		return 0;
	}
	struct sst_meta *meta = *(struct sst_meta **)dev_level_scanner->sst_iter.iter_node->kv->value;
	return sst_meta_get_first_leaf_offt(meta);
}

bool level_scanner_dev_curr(struct level_scanner_dev *dev_level_scanner, struct kv_splice_base *splice)
{
	bool valid = (*dev_level_scanner->leaf_api->leaf_is_iter_valid)(dev_level_scanner->leaf_iter);
	if (valid)
		goto pack_staff;

	uint64_t leaf_offt = level_scanner_dev_find_next_leaf(dev_level_scanner);
	if (0 == leaf_offt)
		return false;
	dev_level_scanner->leaf = REAL_ADDRESS(leaf_offt);
	(*dev_level_scanner->leaf_api->leaf_seek_first)(dev_level_scanner->leaf, dev_level_scanner->leaf_iter);

pack_staff:
	*splice = (*dev_level_scanner->leaf_api->leaf_iter_curr)(dev_level_scanner->leaf_iter);
	return true;
}

bool level_scanner_dev_next(struct level_scanner_dev *dev_level_scanner)
{
	bool ret = (*dev_level_scanner->leaf_api->leaf_iter_next)(dev_level_scanner->leaf_iter);

	if (ret)
		return ret;
	uint64_t next_leaf_offt = (*dev_level_scanner->leaf_api->leaf_get_next_offt)(dev_level_scanner->leaf);
	if (0 == next_leaf_offt) {
		next_leaf_offt = level_scanner_dev_find_next_leaf(dev_level_scanner);
		if (0 == next_leaf_offt) {
			return false;
		}
	}
	dev_level_scanner->leaf = REAL_ADDRESS(next_leaf_offt);
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
		level->guard_table[tree_id] = minos_init(false);
	for (int i = 0; i < num_ssts; i++) {
		struct key_splice *first = sst_meta_get_first_guard(ssts[i]);
		log_debug("Adding in guard table key: %.*s size: %d of level: %u and tree_id: %u",
			  key_splice_get_key_size(first), key_splice_get_key_offset(first),
			  key_splice_get_key_size(first), level->level_id, tree_id);
		struct minos_insert_request req = { .key = key_splice_get_key_offset(first),
						    .key_size = key_splice_get_key_size(first),
						    .value = &ssts[i],
						    .value_size = sizeof(struct sst *) };
		minos_insert(level->guard_table[tree_id], &req);
	}

	level_leave_as_writer(level);
	return true;
}

// cppcheck-suppress unusedFunction
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
	posix_memalign((void **)&comp_scanner->IO_buffer, ALIGNMENT_SIZE, sst_size);
	comp_scanner->sst_size = sst_size;
	comp_scanner->fd = file_desc;
	minos_iter_seek_first(&comp_scanner->iter, level->guard_table[tree_id]);
	comp_scanner->meta = *(struct sst_meta **)comp_scanner->iter.iter_node->kv->value;
	log_debug("--------------> Header dev offt = %u", sst_meta_get_first_leaf_relative_offt(comp_scanner->meta));
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
	comp_scanner->meta = *(struct sst_meta **)comp_scanner->iter.iter_node->kv->value;
	log_debug("--------------> Header dev offt = %u", sst_meta_get_first_leaf_relative_offt(comp_scanner->meta));
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

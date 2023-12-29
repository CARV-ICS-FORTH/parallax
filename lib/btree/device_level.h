#ifndef DEVICE_LEVEL_H
#define DEVICE_LEVEL_H
#include "btree.h"
#include "btree_node.h"
#include <stdbool.h>
#include <stdint.h>
struct pr_db_superblock;
struct db_handle;
struct device_level;
struct db_descriptor;
struct key_splice;
struct node_header;
struct segment_header;

struct kv_splice_base;
struct index_node;
struct index_node_iterator;
struct leaf_node;
struct leaf_iterator;
struct lookup_operation;
/*level leaf functions signatures*/
typedef bool (*level_leaf_append)(struct leaf_node *leaf, struct kv_splice_base *general_splice, bool is_tombstone);

typedef struct kv_splice_base (*level_leaf_find)(struct leaf_node *leaf, char *key, int32_t key_size,
						 const char **error);

typedef void (*level_leaf_init)(struct leaf_node *leaf, uint32_t leaf_size);

typedef bool (*level_leaf_is_full)(struct leaf_node *leaf, uint32_t kv_size);

typedef void (*level_leaf_set_type)(struct leaf_node *leaf, nodeType_t node_type);

typedef nodeType_t (*level_leaf_get_type)(struct leaf_node *leaf);

typedef int32_t (*level_leaf_get_entries)(struct leaf_node *leaf);

typedef struct kv_splice_base (*level_leaf_iter_curr)(struct leaf_iterator *iter);

typedef uint32_t (*level_leaf_get_size)(struct leaf_node *leaf);

typedef struct kv_splice_base (*level_leaf_get_last)(struct leaf_node *leaf);

//<leaf iterators>
typedef struct leaf_iterator *(*level_leaf_iter_create)(void);

/*return true if there is an exact match*/
typedef bool (*level_leaf_iter_first)(struct leaf_node *leaf, struct leaf_iterator *iter);

typedef bool (*level_leaf_iter_seek)(struct leaf_node *leaf, struct leaf_iterator *iter, char *key, int32_t key_size);

typedef void (*level_leaf_iter_destroy)(struct leaf_iterator *iter);

typedef bool (*level_leaf_iter_is_valid)(struct leaf_iterator *iter);

/*returns false if after advancing the iterator is out of bounds*/
typedef bool (*level_leaf_iter_next)(struct leaf_iterator *iter);

typedef struct kv_splice_base (*level_leaf_iter_curr)(struct leaf_iterator *iter);
//</leaf iterators>

/*level index functions*/
typedef struct pivot_pointer *(*level_index_get_pivot)(struct key_splice *key_splice);

typedef void (*level_index_init_node)(enum add_guard_option option, struct index_node *node, nodeType_t type);

typedef void (*level_index_set_height)(struct index_node *node, int32_t height);

typedef bool (*level_index_set_type)(struct index_node *node, nodeType_t node_type);

typedef bool (*level_index_is_empty)(struct index_node *node);

typedef void (*level_index_add_guard)(struct index_node *node, uint64_t child_node_dev_offt);

typedef bool (*level_index_append_pivot)(struct insert_pivot_req *ins_pivot_req);

typedef struct key_splice *(*level_index_remove_last_pivot_key)(struct index_node *node);

typedef void (*level_index_init_iter)(struct index_node *node, struct index_node_iterator *iterator);

typedef void (*level_index_init_iter_key)(struct index_node *node, struct index_node_iterator *iterator,
					  struct key_splice *key_splice);

typedef struct key_splice (*level_fill_smallest_possible_pivot)(char *buffer, int size);

typedef void (*level_index_set_pivot_key)(struct key_splice *pivot_splice, void *key, int32_t key_size);

typedef struct node_header *(*level_index_get_header)(struct index_node *node);

typedef uint64_t (*level_index_get_node_size)(void);

struct level_leaf_api {
	level_leaf_append leaf_append;

	level_leaf_find leaf_find;

	level_leaf_init leaf_init;

	level_leaf_is_full leaf_is_full;

	level_leaf_set_type leaf_set_type;

	level_leaf_get_type leaf_get_type;

	level_leaf_get_entries leaf_get_entries;

	level_leaf_get_size leaf_get_size;

	level_leaf_get_last leaf_get_last;
	/*iterator staff*/
	level_leaf_iter_create leaf_create_empty_iter;

	level_leaf_iter_destroy leaf_destroy_iter;

	level_leaf_iter_first leaf_seek_first;

	level_leaf_iter_seek leaf_seek_iter;

	level_leaf_iter_is_valid leaf_is_iter_valid;

	level_leaf_iter_next leaf_iter_next;

	level_leaf_iter_curr leaf_iter_curr;
};

struct level_index_api {
	level_index_get_pivot index_get_pivot;

	level_index_init_node index_init_node;

	level_index_set_height index_set_height;

	level_index_set_type index_set_type;

	level_index_is_empty index_is_empty;

	level_index_add_guard index_add_guard;

	level_index_append_pivot index_append_pivot;

	level_index_remove_last_pivot_key index_remove_last_key;

	level_index_init_iter index_init_iter;

	level_index_init_iter_key index_init_iter_key;

	level_fill_smallest_possible_pivot index_fill_pivot;

	level_index_set_pivot_key index_set_pivot_key;

	level_index_get_header index_get_header;

	level_index_get_node_size index_get_node_size;
};

/**
 * @brief Creates a new empty level
 * @param level_id the id of the level
 * @param l0_size the size of the l0
 * @param growth_factor the growth factor of the LSM together they are used to calculate max level_size
 * @return pointer to the new device level object or NULL on failure
 */
struct device_level *level_create_fresh(uint32_t level_id, uint32_t l0_size, uint32_t growth_factor);

/**
 * @brief Restores a level from the device
 * @param level_id the id of the level
 * @param superblock pointer to the superblock object
 * @param num_trees number of trees described in the superblock
 * @param l0_size the size of the l0
 * @param growth_factor the growth factor of the LSM together they are used to calculate max level_size
 * XXXTODOXXX This function could instead be a deserialize function from a buffer
 */
struct device_level *level_restore_from_device(uint32_t level_id, struct pr_db_superblock *superblock,
					       uint32_t num_trees, struct db_handle *database, uint64_t l0_size,
					       uint32_t growth_factor);

/**
 * @brief Saves level state to superblock
 * @param level pointer to the level object
 * @param db_superblock pointer to the superblock object
 * @param tree_id XXX TODO XXX redundant param serialize always 0
 */
void level_save_to_superblock(struct device_level *level, struct pr_db_superblock *db_superblock, uint32_t tree_id);

/**
 * @brief Save bloom filter info of the level to superblock
 * XXX TODO XXX Why is it different than level_save_to_superblock?
 */
void level_save_bf_info_to_superblock(struct device_level *level, struct pr_db_superblock *db_superblock);

/**
  * @brief Returns the root of tree_id in the level.
  * Each level can have up to NUM_TREES_PER_LEVEL TREES.
  *@param device_level pointer to the level object
  *@param tree_id id of tree
  *@return the root of the tree or NULL if it is empty
*/
struct node_header *level_get_root(struct device_level *level, uint32_t tree_id);

/**
  * @brief Returns the device offset of the root of tree_id in the level.
  * Each level can have up to NUM_TREES_PER_LEVEL TREES.
  * @param device_level pointer to the level object
  * @param tree_id id of tree
  * @return the offset in the device of the root of the tree or NULL if it is empty
*/
uint64_t level_get_root_dev_offt(struct device_level *level, uint32_t tree_id);

/**
  * @brief Returns pointer to the first segment of the index.
  * @param level pointer to the level object
  * @param tree_id id of the tree
  * @return pointer to the segment or NULL if empty
  */
struct segment_header *level_get_index_first_seg(struct device_level *level, uint32_t tree_id);

/**
  * @brief Returns the offset in the device where the first segment of the index resides.
  * @param level pointer to the level object
  * @param tree_id id of the tree
  * @return pointer to the segment or NULL if empty
  */
uint64_t level_get_index_first_seg_offt(struct device_level *level, uint32_t tree_id);

/**
  * @brief Returns pointer to the last segment of the index.
  * @param level pointer to the level object
  * @param tree_id id of the tree
  * @return pointer to the segment or NULL if empty
  */
struct segment_header *level_get_index_last_seg(struct device_level *level, uint32_t tree_id);

bool level_set_index_last_seg(struct device_level *level, struct segment_header *segment, uint32_t tree_id);

/**
  * @brief Returns the offset in the device where the last segment of the index resides.
  * @param level pointer to the level object
  * @param tree_id id of the tree
  * @return pointer to the segment or NULL if empty
  */
uint64_t level_get_index_last_seg_offt(struct device_level *level, uint32_t tree_id);

/**
* @brief Return the offset? of the level.
  * @param level pointer to the level object
  * @param tree_id id of the tree
  */
uint64_t level_get_offset(struct device_level *level, uint32_t tree_id);

/**
* @brief Returns the size of the level in terms of B of key-value pairs
  * stored excluding the B-Tree metadata.
  * @param level pointer to the level object
  * @param tree_id id of the tree
  */
uint64_t level_get_size(struct device_level *level, uint32_t tree_id);

/**
 * @brief Returns the bloom filter for this level
 * @param level pointer to the level object
 * @param tree_id tree_id (out of the NUM_TREES_PER_LEVEL)
 * @return pointer to the bloom filter or NULL on failure
 */
struct pbf_desc *level_get_bloom(struct device_level *level, uint32_t tree_id);

/**
 * @brief Trims medium log
 * @param level pointer to the level object
 * @param db_desc pointer to the db object
 * @param txn_id Txn id associated with the free and allocate space operations
 * @return Number of bytes freed
 */
uint64_t level_trim_medium_log(struct device_level *level, struct db_descriptor *db_desc, uint64_t txn_id);

/**
 * @brief function to ensure exclusive access in a level
 * @param level pointer to the level object
 * @param Returns UINT8_MAX on success
 */
uint8_t level_enter_as_writer(struct device_level *level);

/**
 * @brief Function to release the lock of the device level
 * @param level pointer to the level object
 */
void level_leave_as_writer(struct device_level *level);

/**
 * @brief Ensure only readers are at the level
 * @param level pointer to the level object
 * @return ticket id
 */
uint8_t level_enter_as_reader(struct device_level *level);

/**
 * @brief Let level available for exclusive access if needed
 * @param level pointer to the level object
 * @param ticket_id ticket obtain from call to level_enter_as_reader
 * @return UINT8_MAX on success
 */
uint8_t level_leave_as_reader(struct device_level *level, uint8_t ticket_id);

/**
 * @brief Set the state of this level as compaction in progress
 * @param level pointer to the level object
 */
void level_set_comp_in_progress(struct device_level *level);

/**
 * @brief Sets the state of this level as not compacting
 * @level pointer to the level object
 * @return true on SUCCESS false on FAILURE
 */
bool level_set_compaction_done(struct device_level *level);

/**
 * @brief Returns if this level is currently compacting
 * or not.
 * @param level pointer to the level object
 * @return true if it is compacting otherwise false
 */
bool level_is_compacting(struct device_level *level);

/**
 * @brief Releases only the memory of the level object
 * (not its data)
 * @param level pointer to the level object
 */
void level_destroy(struct device_level *level);

/**
 * @brief Checks the bloom filter of the level if the key is present
 * @param level pointer to the level object
 *
 */
bool level_does_key_exist(struct device_level *level, struct key_splice *key_splice);

/**
 * @brief Check if level size has exceeded its maximu size.
 * @param level pointer to the device level object
 *  @param tree_id tree of the level to check
 * @return true if it has otherwise false
*/
bool level_has_overflow(struct device_level *level, uint32_t tree_id);

typedef void *compaction_func(void *compaction_request);

/**
 * @brief Starts a compaction for this level
  */
bool level_start_comp_thread(struct device_level *level, compaction_func func, void *args);

bool level_set_medium_in_place_seg_id(struct device_level *level, uint64_t segment_id);

bool level_set_medium_in_place_seg_offt(struct device_level *level, uint64_t segment_offt);

/**
 * @brief Zero out an entire level
 * @param pointer to the level object
 * @param tree_id id of the tree (out of the NUM_TREES_PER_LEVEL)
 * @return TRUE on success
*/
bool level_zero(struct device_level *level, uint32_t tree_id);

/**
 * @brief Sets the root of the level
 * @param level pointer to the level object
 * @tree_id id of tree out of the NUM_TREES_PER_LEVEL
 * @node pointer to the new root of the level
 */
bool level_set_root(struct device_level *level, uint32_t tree_id, struct node_header *node);

bool level_swap(struct device_level *level_dst, uint32_t tree_dst, struct device_level *level_src, uint32_t tree_src);

bool level_destroy_bf(struct device_level *level, uint32_t tree_id);
bool level_create_bf(struct device_level *level, uint32_t tree_id, int64_t num_kv_pairs, struct db_handle *handle);
bool level_persist_bf(struct device_level *level, uint32_t tree_id);
bool level_add_key_to_bf(struct device_level *level, uint32_t tree_id, char *key, uint32_t key_size);

int64_t level_get_num_KV_pairs(struct device_level *level, uint32_t tree_id);
bool level_increase_size(struct device_level *level, uint32_t size, uint32_t tree_id);

int64_t level_inc_num_keys(struct device_level *level, uint32_t tree_id, uint32_t num_keys);
struct segment_header *level_allocate_segment(struct device_level *level, uint8_t tree_id,
					      struct db_descriptor *db_desc, uint64_t txn_id);

/**
* @brief Frees all the index segments of the level
  * @param level pointer to the level object
  * @param tree_id out of the NUM_TREES_PER_LEVEL
  * @param db_desc pointer to the db the level belongs
  */
uint64_t level_free_space(struct device_level *level, uint32_t tree_id, struct db_descriptor *db_desc, uint64_t txn_id);

struct level_leaf_api *level_get_leaf_api(struct device_level *level);

struct level_index_api *level_get_index_api(struct device_level *level);

bool level_lookup(struct device_level *level, struct lookup_operation *get_op, int tree_id);
#endif

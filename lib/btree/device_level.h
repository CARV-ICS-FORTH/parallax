#ifndef DEVICE_LEVEL_H
#define DEVICE_LEVEL_H
#include <stdbool.h>
#include <stdint.h>
struct pr_db_superblock;
struct db_handle;
struct device_level;
struct db_descriptor;
struct key_splice;
struct node_header;
struct segment_header;

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

struct pbf_desc *level_get_bloom(struct device_level *level, uint32_t tree_id);

uint64_t level_trim_medium_log(struct device_level *level, struct db_descriptor *db_desc, uint64_t txn_id);

uint8_t level_enter_as_writer(struct device_level *level);
void level_leave_as_writer(struct device_level *level);
uint8_t level_enter_as_reader(struct device_level *level);
uint8_t level_leave_as_reader(struct device_level *level, uint8_t ticket_id);

void level_set_comp_in_progress(struct device_level *level);
bool level_set_compaction_done(struct device_level *level);

bool level_is_compacting(struct device_level *level);

void level_destroy(struct device_level *level);

/**
 * @brief Checks the bloom filter of the level if the key is present
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
*/
bool level_zero(struct device_level *level, uint32_t tree_id);

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
uint64_t level_free_space(struct device_level *level, uint32_t tree_id, struct db_descriptor *db_desc, uint64_t txn_id);
#endif

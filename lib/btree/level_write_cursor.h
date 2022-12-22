#ifndef LEVEL_WRITE_CURSOR_H
#define LEVEL_WRITE_CURSOR_H
#include "btree.h"
#include "conf.h"
#include <stdbool.h>
#include <stdint.h>
struct comp_parallax_key;
struct wcursor_level_write_cursor {
	char segment_buf[MAX_HEIGHT][SEGMENT_SIZE];
	uint64_t segment_offt[MAX_HEIGHT];
	uint64_t first_segment_btree_level_offt[MAX_HEIGHT];
	uint64_t last_segment_btree_level_offt[MAX_HEIGHT];
	struct index_node *last_index[MAX_HEIGHT];
	struct bt_dynamic_leaf_node *last_leaf;
	struct chunk_LRU_cache *medium_log_LRU_cache;
	struct medium_log_segment_map *medium_log_segment_map;
	uint64_t root_offt;
	uint64_t segment_id_cnt;
	db_handle *handle;
	uint32_t level_id;
	uint32_t tree_id;
	int32_t tree_height;
	int fd;
};

/**
 * @brief Creates a level cursor to write a new level which is the result of a compaction.
 * @param level_id the id of the level that we write.
 * @param handle the descriptor of the database.
 * @param tree_id the id within the level where we need to store the new index.
 * @returns a pointer to the cursor.
 */
struct wcursor_level_write_cursor *wcursor_init_write_cursor(int level_id, struct db_handle *handle, int tree_id);

/**
 * @brief Appends a new KV pair into the level.
 * @param cursor pointer to the write cursor
 * @param kv_pair the kv_pair to insert in the level.
 * @returns true if success otherwise false on failure.
 */
// bool wcursor_append_KV_pair(struct wcursor_level_write_cursor *cursor, struct comp_parallax_key *kv_pair);
bool wcursor_append_KV_pair(struct wcursor_level_write_cursor *cursor, struct kv_general_splice *splice);

/**
 * @brief Flushes any in memory state of the cursor to the device.
 */
void wcursor_flush_write_cursor(struct wcursor_level_write_cursor *w_cursor);

/**
 * @brief Flushes any pending in memory state to the device and releases any
 * resources associated with the cursor.
 */
void wcursor_close_write_cursor(struct wcursor_level_write_cursor *w_cursor);
#endif

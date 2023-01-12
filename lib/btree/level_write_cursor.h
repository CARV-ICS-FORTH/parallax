#ifndef LEVEL_WRITE_CURSOR_H
#define LEVEL_WRITE_CURSOR_H
#include <stdbool.h>
#include <stdint.h>
struct kv_splice_base;
struct db_handle;
struct medium_log_LRU_cache;
struct wcursor_level_write_cursor;

/**
 * @brief Creates a level cursor to write a new level which is the result of a compaction.
 * @param level_id the id of the level that we write.
 * @param handle the descriptor of the database.
 * @param tree_id the id within the level where we need to store the new index.
 * @returns a pointer to the cursor.
 */
struct wcursor_level_write_cursor *wcursor_init_write_cursor(uint8_t level_id, struct db_handle *handle,
							     uint8_t tree_id);

/**
 * @brief Appends a new KV pair into the level.
 * @param cursor pointer to the write cursor
 * @param kv_pair the kv_pair to insert in the level.
 * @returns true if success otherwise false on failure.
 */
bool wcursor_append_KV_pair(struct wcursor_level_write_cursor *cursor, struct kv_splice_base *splice);

/**
 * @brief Flushes any in memory state of the cursor to the device.
 */
void wcursor_flush_write_cursor(struct wcursor_level_write_cursor *w_cursor);

/**
 * @brief Returns a pointer to the medium log cache object used by this cursor
 */
struct medium_log_LRU_cache *wcursor_get_LRU_cache(struct wcursor_level_write_cursor *w_cursor);
/**
 * @brief Sets the cache of this cursor for the in place transfers of the medium log
 * @param w_cursor pointer to the w_cursor object
 * @param mcache pointer to the medium log cach object
 */
void wcursor_set_LRU_cache(struct wcursor_level_write_cursor *w_cursor, struct medium_log_LRU_cache *mcache);

/**
 * @brief Returns the id of the level this cursor belongs to
 */
uint8_t wcursor_get_level_id(struct wcursor_level_write_cursor *w_cursor);

/**
 * @brief Returns the location (offset) in the device where the root of the underlying B+tree.
 */
uint64_t wcursor_get_current_root(struct wcursor_level_write_cursor *w_cursor);

/**
 * @brief Flushes any pending in memory state to the device and releases any
 * resources associated with the cursor.
 */
void wcursor_close_write_cursor(struct wcursor_level_write_cursor *w_cursor);
#endif

#ifndef LEVEL_READ_CURSOR_H
#define LEVEL_READ_CURSOR_H
#include "../scanner/scanner.h"
#include "btree.h"
#include "conf.h"
#include "kv_pairs.h"
#include "level_cursor.h"
#include <stdbool.h>
#include <stdint.h>
struct sh_heap_node;
enum rcursor_state {
	COMP_CUR_INIT,
	COMP_CUR_FIND_LEAF,
	COMP_CUR_FETCH_NEXT_SEGMENT,
	COMP_CUR_DECODE_KV,
	COMP_CUR_CHECK_OFFT
};

struct rcursor_device_cursor {
	char segment_buf[SEGMENT_SIZE];
	uint64_t device_offt;
	uint64_t offset;
	segment_header *curr_segment;
	int32_t curr_leaf_entry;
	int fd;
	enum rcursor_state state;
};

struct rcursor_L0_cursor {
	struct level_scanner *L0_scanner;
};

struct rcursor_level_read_cursor {
	uint8_t level_id;
	uint8_t tree_id;
	bool is_end_of_level;
	struct kv_general_splice splice;
	db_handle *handle;
	union {
		struct rcursor_device_cursor *device_cursor;
		struct rcursor_L0_cursor *L0_cursor;
	};
};

/**
 * @brief rcursor_cursor_init creates a level cursor to iterate the KV pairs
 * of a level. Level cursor can either iterate L0 which is in memory or device
 * levels.
 * @param handle the hande to the db where the level belongs.
 * @param level_id the id of the level inside the db which we want to iterate
 * @param tree_id In each level we can have up to NUM_TREES_PER_LEVEL B+-tree
 * indexes. tree_id address which of the B+-tree indexes we want to iterate.
 */
struct rcursor_level_read_cursor *rcursor_init_cursor(db_handle *handle, uint32_t level_id, uint32_t tree_id,
						      int file_desc);

/**
 * @brief Fetches the next key value pair from the level in sorted order.
 * @param r_cursor pointer to the cursor.
 * @returns true if the cursor has a next KV pair otherwise false if we have
 * reached the end of the level.
 */
bool rcursor_get_next_kv(struct rcursor_level_read_cursor *r_cursor);

/**
 * @brief Fills a heap node with the current KV pair that the cursor is positioned to.
 */
void wcursor_fill_heap_node(struct rcursor_level_read_cursor *r_cursor, struct sh_heap_node *h_node);

/**
 * @brief Closes cursor and releases any associated resources.
 */
void rcursor_close_cursor(struct rcursor_level_read_cursor *r_cursor);
#endif

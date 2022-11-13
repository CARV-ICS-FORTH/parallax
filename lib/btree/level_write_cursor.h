#ifndef LEVEL_WRITE_CURSOR_H
#define LEVEL_WRITE_CURSOR_H
#include "btree.h"
#include "conf.h"
#include "level_cursor.h"
#include <stdint.h>

struct comp_level_write_cursor {
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
	int32_t tree_height;
	int fd;
};

extern void comp_init_write_cursor(struct comp_level_write_cursor *c, struct db_handle *handle, int level_id, int fd);
extern void comp_append_entry_to_leaf_node(struct comp_level_write_cursor *cursor, struct comp_parallax_key *kv);
extern void comp_close_write_cursor(struct comp_level_write_cursor *w_cursor);
#endif

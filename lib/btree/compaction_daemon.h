#ifndef COMPACTION_DAEMON_H
#define COMPACTION_DAEMON_H
#include "btree.h"
#include "btree_node.h"
#include "conf.h"
#include "dynamic_leaf.h"
#include "kv_pairs.h"
#include "parallax/structures.h"
#include <stdint.h>
#include <uthash.h>

struct medium_log_segment_map {
	uint64_t id;
	uint64_t dev_offt;
	UT_hash_handle hh;
};

/*
 * Checks for pending compactions. It is responsible to check for dependencies
 * between two levels before triggering a compaction.
*/
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

enum comp_level_read_cursor_state {
	COMP_CUR_INIT,
	COMP_CUR_FIND_LEAF,
	COMP_CUR_FETCH_NEXT_SEGMENT,
	COMP_CUR_DECODE_KV,
	COMP_CUR_CHECK_OFFT
};

struct comp_parallax_key {
	union {
		struct kv_seperation_splice *kv_inlog;
		char *kv_inplace;
	};
	struct kv_seperation_splice kv_sep;
	enum kv_category kv_category;
	enum kv_entry_location kv_type;
	uint8_t tombstone : 1;
};

struct comp_level_read_cursor {
	char segment_buf[SEGMENT_SIZE];
	struct comp_parallax_key cursor_key;
	uint64_t device_offt;
	uint64_t offset;
	db_handle *handle;
	segment_header *curr_segment;
	uint32_t level_id;
	uint32_t tree_id;
	int32_t curr_leaf_entry;
	int fd;
	enum kv_category category;
	enum comp_level_read_cursor_state state;
	char end_of_level;
};

static void comp_get_space(struct comp_level_write_cursor *c, uint32_t height, nodeType_t type);

#endif // COMPACTION_DAEMON_H_

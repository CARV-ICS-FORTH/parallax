#include "btree.h"
#include "conf.h"
#include "level_cursor.h"
#include <stdint.h>

enum comp_level_read_cursor_state {
	COMP_CUR_INIT,
	COMP_CUR_FIND_LEAF,
	COMP_CUR_FETCH_NEXT_SEGMENT,
	COMP_CUR_DECODE_KV,
	COMP_CUR_CHECK_OFFT
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

extern void comp_init_read_cursor(struct comp_level_read_cursor *c, db_handle *handle, uint32_t level_id,
				  uint32_t tree_id, int fd);

extern void comp_get_next_key(struct comp_level_read_cursor *c);

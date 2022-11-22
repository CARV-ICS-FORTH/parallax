#ifndef LEVEL_READ_CURSOR_H
#define LEVEL_READ_CURSOR_H
#include "../scanner/min_max_heap.h"
#include "../scanner/scanner.h"
#include "btree.h"
#include "conf.h"
#include "level_cursor.h"
#include <stdbool.h>
#include <stdint.h>

typedef enum RCURSOR_cursor_state {
	COMP_CUR_INIT,
	COMP_CUR_FIND_LEAF,
	COMP_CUR_FETCH_NEXT_SEGMENT,
	COMP_CUR_DECODE_KV,
	COMP_CUR_CHECK_OFFT
} RCURSOR_cursor_state_e;

struct RCURSOR_device_cursor {
	char segment_buf[SEGMENT_SIZE];
	uint64_t device_offt;
	uint64_t offset;
	segment_header *curr_segment;
	int32_t curr_leaf_entry;
	int fd;
	enum RCURSOR_cursor_state state;
};

struct RCURSOR_L0_cursor {
	level_scanner *L0_scanner;
};

struct RCURSOR_level_read_cursor {
	uint32_t level_id;
	uint32_t tree_id;
	bool is_end_of_level;
	struct comp_parallax_key cursor_key;
	db_handle *handle;
	union {
		struct RCURSOR_device_cursor *device_cursor;
		struct RCURSOR_L0_cursor *L0_cursor;
	};
};

extern struct RCURSOR_level_read_cursor *RCURSOR_init_cursor(db_handle *handle, uint32_t level_id, uint32_t tree_id,
							     int file_desc);

extern bool RCURSOR_get_next_kv(struct RCURSOR_level_read_cursor *r_cursor);
extern void WCURSOR_fill_heap_node(struct RCURSOR_level_read_cursor *r_cursor, struct sh_heap_node *h_node);
extern void RCURSOR_close_cursor(struct RCURSOR_level_read_cursor *r_cursor);
#endif

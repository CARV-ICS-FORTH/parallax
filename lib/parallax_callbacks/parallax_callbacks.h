#ifndef parallax_CALLBACKS_H
#define parallax_CALLBACKS_H
#include "../allocator/log_structures.h"
#include "parallax/structures.h"
#include <stdbool.h>
#include <stdint.h>

struct wcursor_level_write_cursor;
/**
 * Call back functions related to various parallax events
*/
struct parallax_callback_funcs {
	void (*segment_is_full_cb)(void *context, uint64_t seg_offt, char *segment_buffer_addr, uint32_t segment_size,
				   uint32_t chunk_id, enum log_type log_type);
	void (*spin_for_medium_log_flush)(void *context, uint32_t chunk_id);
	void (*compaction_started_cb)(void *context, uint64_t small_log_tail_dev, uint64_t big_log_tail_dev,
				      uint32_t src_level_id, uint8_t dst_tree_id,
				      struct wcursor_level_write_cursor *wcursor);
	void (*compaction_ended_cb)(void *context, uint32_t src_level_id, uint64_t compaction_first_segment_offt,
				    uint64_t compaction_last_segment_offt, uint64_t new_root_offt);
	void (*swap_levels_cb)(void *context, uint32_t src_level_id, uint32_t src_tree_id);
	void (*comp_write_cursor_flush_segment_cb)(void *context, uint64_t starting_segment_offt,
						   struct wcursor_level_write_cursor *wcursor, uint32_t level_id,
						   uint32_t height, uint32_t buf_size, uint32_t clock, bool is_last);
	void (*comp_write_cursor_got_flush_replies_cb)(void *context, uint32_t src_level_id, uint32_t clock_id);
};

typedef struct parallax_callbacks *parallax_callbacks_t;

/**
 * set the parallax_callback functions of parallax
 * @param dbhandle: The db handle for which we will set the callbacks
 * @param parallax_callbacks: a set of function pointers which will be seted as the callbacks
 * @param context: context related information about the send index callback functions*/
void parallax_init_callbacks(par_handle dbhandle, struct parallax_callback_funcs *parallax_callbacks, void *context);

/**
 * get all the callback functions for a send index object
 * @param parallax_cb: the send index object from which the functions will be retrieved
*/
struct parallax_callback_funcs parallax_get_callbacks(parallax_callbacks_t parallax_cb);

/**
 * get the context related to the send index callbacks
*/
void *parallax_get_context(parallax_callbacks_t parallax_cb);

/**
 * return if the send index functionality is set or not
*/
int8_t are_parallax_callbacks_set(parallax_callbacks_t parallax_cb);

#endif // parallax_CALLBACKS_H

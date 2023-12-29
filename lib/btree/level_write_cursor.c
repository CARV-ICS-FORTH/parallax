// Copyright [2023] [FORTH-ICS]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include "level_write_cursor.h"
#include "../allocator/volume_manager.h"
#include "../common/common.h"
#include "btree.h"
#include "btree_node.h"
#include "conf.h"
#include "device_level.h"
#include "dynamic_leaf.h"
#include "index_node.h"
#include "key_splice.h"
#include "kv_pairs.h"
#include "medium_log_LRU_cache.h"
#include "parallax/structures.h"
#include <assert.h>
#include <log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct device_level;
#define WCURSOR_MAGIC_SMALL_KV_SIZE (33)
// IWYU pragma: no_forward_declare pbf_desc
// IWYU pragma: no_forward_declare index_node
// IWYU pragma: no_forward_declare key_splice

struct wcursor_seg_buf {
	char buffer[SEGMENT_SIZE];
#if TEBIS_FORMAT
	volatile char status[TEBIS_MAX_BACKUPS][WCURSOR_ALIGNMNENT];
#else
	uint64_t status;
#endif
} __attribute__((aligned(4096)));

struct wcursor_level_write_cursor {
	struct wcursor_seg_buf *segment_buffer;
	uint64_t segment_offt[MAX_HEIGHT];
	uint64_t first_segment_btree_level_offt[MAX_HEIGHT];
	uint64_t last_segment_btree_level_offt[MAX_HEIGHT];
	struct node_header *last_node[MAX_HEIGHT];
	// struct index_node *last_index[MAX_HEIGHT];
	// struct leaf_node *last_leaf;
	int8_t segment_buf_is_init[MAX_HEIGHT];
	struct medium_log_LRU_cache *medium_log_LRU_cache;
	uint64_t root_offt;
	uint64_t segment_id_cnt;
	db_handle *handle;
	struct level_leaf_api *leaf_api;
	struct level_index_api *index_api;
	uint64_t txn_id;
	int32_t tree_height;
	int fd;
	uint32_t num_rows;
	uint32_t num_columns;
#if TEBIS_FORMAT
	uint32_t number_of_replicas;
	uint32_t last_flush_request_height;
	uint32_t last_flush_request_clock;
	bool have_send_flush_request;
	bool spin_for_replies;
#endif
	uint32_t clock[MAX_HEIGHT];
	uint8_t level_id;
	uint8_t tree_id;
};

struct wcursor_segment_buffers_iterator {
	int curr_i;
	struct wcursor_level_write_cursor *wcursor;
};

static struct wcursor_seg_buf *wcursor_get_buf(struct wcursor_level_write_cursor *w_cursor, uint32_t row_id)
{
	uint32_t col_id = w_cursor->clock[row_id] % w_cursor->num_columns;

	return &w_cursor->segment_buffer[row_id * w_cursor->num_columns + col_id];
}

#ifdef TEBIS_FORMAT
static struct wcursor_seg_buf *wcursor_get_buf_with_coordinates(struct wcursor_level_write_cursor *w_cursor,
								uint32_t row_id, uint32_t col_id)
{
	return &w_cursor->segment_buffer[row_id * w_cursor->num_columns + col_id];
}

static void wcursor_init_status_buffers(struct wcursor_level_write_cursor *w_cursor, uint32_t num_rows,
					uint32_t num_columns)
{
	for (uint32_t i = 0; i < num_rows; ++i) {
		for (uint32_t j = 0; j < num_columns; ++j) {
			struct wcursor_seg_buf *seg_buf = wcursor_get_buf_with_coordinates(w_cursor, i, j);
			for (uint32_t backup_id = 0; backup_id < w_cursor->number_of_replicas; ++backup_id) {
				*(volatile uint64_t *)seg_buf->status[backup_id] = WCURSOR_STATUS_OK;
			}
		}
	}
	w_cursor->have_send_flush_request = false;
}

static void wcursor_invalidate_status_buffer(struct wcursor_level_write_cursor *w_cursor, uint32_t height,
					     uint32_t clock)
{
	struct wcursor_seg_buf *seg_buf = &w_cursor->segment_buffer[height * w_cursor->num_columns + clock];
	for (uint32_t i = 0; i < w_cursor->number_of_replicas; ++i) {
		*(volatile uint64_t *)seg_buf->status[i] = 0;
	}
}

void wcursor_spin_for_buffer_status(struct wcursor_level_write_cursor *wcursor)
{
	if (!wcursor->have_send_flush_request)
		return;

	struct wcursor_seg_buf *active_seg_buf = wcursor_get_buf_with_coordinates(
		wcursor, wcursor->last_flush_request_height, wcursor->last_flush_request_clock);
	for (uint32_t i = 0; i < wcursor->number_of_replicas; ++i) {
		volatile const uint64_t *backup_status = (volatile uint64_t *)active_seg_buf->status[i];
		while (*backup_status != WCURSOR_STATUS_OK) { /*spin*/
			;
		}
	}

	//TODO: geostyl callback
	parallax_callbacks_t par_callbacks = wcursor->handle->db_desc->parallax_callbacks;
	if (are_parallax_callbacks_set(par_callbacks)) {
		struct parallax_callback_funcs par_cb = parallax_get_callbacks(par_callbacks);
		void *context = parallax_get_context(par_callbacks);
		uint32_t src_level = wcursor->level_id - 1;
		uint32_t clock_id = wcursor->last_flush_request_clock % wcursor->num_columns;
		if (par_cb.comp_write_cursor_got_flush_replies_cb)
			par_cb.comp_write_cursor_got_flush_replies_cb(context, src_level, clock_id);
	}
}
#endif

static void wcursor_seg_buf_array_init(uint32_t num_rows, struct wcursor_level_write_cursor *w_cursor,
				       uint32_t num_columns)
{
	w_cursor->num_rows = num_rows;
	w_cursor->num_columns = num_columns;
	if (posix_memalign((void **)&w_cursor->segment_buffer, WCURSOR_ALIGNMNENT,
			   w_cursor->num_rows * w_cursor->num_columns * sizeof(struct wcursor_seg_buf))) {
		log_fatal("Failed to allocate a segment buffer for the level_write_cursor");
		_exit(EXIT_FAILURE);
	}
	memset(w_cursor->segment_buffer, 0x00,
	       w_cursor->num_rows * w_cursor->num_columns * sizeof(struct wcursor_seg_buf));
#if TEBIS_FORMAT
	if (w_cursor->spin_for_replies) {
		/*init statuses to STATUS OK for the first time*/
		wcursor_init_status_buffers(w_cursor, num_rows, num_columns);
	}
#endif
}

static void wcursor_increase_clock(struct wcursor_level_write_cursor *w_cursor, uint32_t height)
{
	++w_cursor->clock[height];
}

static void wcursor_seg_buf_destroy(struct wcursor_level_write_cursor *w_cursor)
{
	free(w_cursor->segment_buffer);
}

static char *wcursor_get_current_node(struct wcursor_level_write_cursor *w_cursor, int32_t height, uint32_t offt)
{
	struct wcursor_seg_buf *seg_buf = wcursor_get_buf(w_cursor, height);
	return &seg_buf->buffer[offt];
}

static void wcursor_seg_buf_zero(struct wcursor_level_write_cursor *w_cursor, uint32_t height, uint32_t offt,
				 uint32_t num_bytes)
{
	struct wcursor_seg_buf *buf = wcursor_get_buf(w_cursor, height);
	memset(&buf->buffer[offt], 0x00, num_bytes);
}

#if 0
static void wcursor_assert_node(void)
{
	struct node_header *n = (struct node_header *)&buffer[sizeof(struct segment_header)];
	switch (n->type) {
	case rootNode:
	case internalNode: {
		uint32_t decoded = sizeof(struct segment_header);
		while (decoded < SEGMENT_SIZE) {
			if (n->type == paddedSpace)
				break;
			assert(n->type == rootNode || n->type == internalNode);
			n = (struct node_header *)((char *)n + index_node_get_size());
			decoded += index_node_get_size();
		}
		break;
	}
	case leafNode:
	case leafRootNode: {
		int num_leaves = 0;
		int padded = 0;
		uint32_t decoded = sizeof(struct segment_header);
		while (decoded < SEGMENT_SIZE) {
			if (n->type == paddedSpace) {
				log_warn("Found padded space in leaf segment ok");
				padded = 1;
				break;
			}
			if (n->type != leafNode && n->type != leafRootNode) {
				log_fatal("Corruption expected leaf got %u decoded was %u", n->type, decoded);
				BUG_ON();
			}
			++num_leaves;
			n = (struct node_header *)((uint64_t)n + LEAF_NODE_SIZE);
			decoded += LEAF_NODE_SIZE;
		}
		if (padded)
			break;
		break;
	}
	case paddedSpace:
		break;
	default:
			BUG_ON();
	}

}
#endif

static void wcursor_write_segment(struct wcursor_level_write_cursor *w_cursor, uint32_t height, uint64_t dev_offt,
				  uint32_t buf_offt, uint32_t size)
{
	assert(height < MAX_HEIGHT);
	struct wcursor_seg_buf *seg_buf = wcursor_get_buf(w_cursor, height);
	ssize_t total_bytes_written = buf_offt;
	while (total_bytes_written < size) {
		ssize_t bytes_written = pwrite(wcursor_get_fd(w_cursor), &seg_buf->buffer[total_bytes_written],
					       size - total_bytes_written, dev_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to writed segment for leaf nodes reason follows");
			perror("Reason");
			BUG_ON();
		}
		total_bytes_written += bytes_written;
	}
}

static void wcursor_write_index_segment(struct wcursor_level_write_cursor *w_cursor, uint32_t height)
{
#if TEBIS_FORMAT
	if (w_cursor->spin_for_replies)
		wcursor_spin_for_buffer_status(w_cursor);
#endif
	struct segment_header *new_device_segment =
		level_allocate_segment(w_cursor->handle->db_desc->dev_levels[w_cursor->level_id], 1,
				       w_cursor->handle->db_desc, w_cursor->txn_id);
	assert(new_device_segment);

	struct segment_header *segment = (struct segment_header *)wcursor_get_buf(w_cursor, height);

	segment->next_segment = (void *)ABSOLUTE_ADDRESS(new_device_segment);
	segment->segment_id = w_cursor->segment_id_cnt++;

	wcursor_write_segment(w_cursor, height, w_cursor->last_segment_btree_level_offt[height], 0, SEGMENT_SIZE);
#if TEBIS_FORMAT

	if (w_cursor->spin_for_replies) {
		w_cursor->last_flush_request_height = height;
		w_cursor->last_flush_request_clock = w_cursor->clock[height] % w_cursor->num_columns;
		w_cursor->have_send_flush_request = true;
		wcursor_invalidate_status_buffer(w_cursor, height, w_cursor->clock[height] % w_cursor->num_columns);
		log_debug("Set last flush height and clock %u %u", w_cursor->last_flush_request_height,
			  w_cursor->last_flush_request_clock);

		//TODO: geostyl callback
		parallax_callbacks_t par_callbacks = w_cursor->handle->db_desc->parallax_callbacks;
		if (are_parallax_callbacks_set(par_callbacks)) {
			struct parallax_callback_funcs par_cb = parallax_get_callbacks(par_callbacks);
			void *context = parallax_get_context(par_callbacks);
			uint32_t src_level = w_cursor->level_id - 1;
			if (par_cb.comp_write_cursor_flush_segment_cb)
				par_cb.comp_write_cursor_flush_segment_cb(
					context, w_cursor->last_segment_btree_level_offt[height], w_cursor, src_level,
					w_cursor->last_flush_request_height, SEGMENT_SIZE,
					w_cursor->last_flush_request_clock, false);
		}
	}
#endif
	wcursor_increase_clock(w_cursor, height);
	wcursor_seg_buf_zero(w_cursor, height, 0, sizeof(struct segment_header));

	w_cursor->last_segment_btree_level_offt[height] = ABSOLUTE_ADDRESS(new_device_segment);
	w_cursor->segment_offt[height] += sizeof(struct segment_header);
}

static char *wcursor_get_space(struct wcursor_level_write_cursor *w_cursor, uint32_t height, size_t size)
{
retry:
	assert(height < MAX_HEIGHT);
	assert(0 == SEGMENT_SIZE % size);

	assert(w_cursor->segment_offt[height] != 0);

	uint32_t remaining_space = w_cursor->segment_offt[height] % SEGMENT_SIZE ?
					   (SEGMENT_SIZE - (w_cursor->segment_offt[height] % SEGMENT_SIZE)) :
					   0;
	if (remaining_space >= size) {
		char *item = wcursor_get_current_node(w_cursor, height, w_cursor->segment_offt[height] % SEGMENT_SIZE);
		w_cursor->segment_offt[height] += size;
		return item;
	}

	if (remaining_space > 0) {
		struct node_header *padded_node = (struct node_header *)wcursor_get_current_node(
			w_cursor, height, w_cursor->segment_offt[height] % SEGMENT_SIZE);
		padded_node->height = height;
		padded_node->type = paddedSpace;
		w_cursor->segment_offt[height] += remaining_space;
	}
	wcursor_write_index_segment(w_cursor, height);
	goto retry;
}

static int64_t wcursor_calculate_level_keys(struct db_descriptor *db_desc, uint8_t level_id)
{
	assert(level_id > 0);
	uint8_t tree_id = 0; /*Always caclulate the immutable aka 0 tree of the level*/
	int64_t total_keys = level_get_num_KV_pairs(db_desc->dev_levels[level_id], tree_id);

	if (0 == total_keys && 1 == level_id) {
		total_keys = db_desc->L0.max_level_size / WCURSOR_MAGIC_SMALL_KV_SIZE;
	}

	if (level_id > 1) {
		total_keys += level_get_num_KV_pairs(db_desc->dev_levels[level_id - 1], tree_id);
	}
	assert(total_keys);
	// log_debug("Total keys of level %u are %d", level_id, total_keys);
	return total_keys;
}

struct wcursor_level_write_cursor *wcursor_init_write_cursor(uint8_t level_id, struct db_handle *handle,
							     uint8_t tree_id, bool enable_double_buffering,
							     uint64_t txn_id)
{
	struct wcursor_level_write_cursor *w_cursor = NULL;
	if (posix_memalign((void **)&w_cursor, ALIGNMENT, sizeof(struct wcursor_level_write_cursor)) != 0) {
		log_fatal("Posix memalign failed");
		perror("Reason: ");
		BUG_ON();
	}
	memset(w_cursor, 0x00, sizeof(struct wcursor_level_write_cursor));
	w_cursor->txn_id = txn_id;
	w_cursor->level_id = level_id;
	w_cursor->tree_id = tree_id;
	w_cursor->tree_height = 0;
	w_cursor->fd = handle->db_desc->db_volume->vol_fd;
	w_cursor->handle = handle;

	w_cursor->leaf_api = level_get_leaf_api(handle->db_desc->dev_levels[level_id]);
	w_cursor->index_api = level_get_index_api(handle->db_desc->dev_levels[level_id]);

	assert(0 == level_get_offset(handle->db_desc->dev_levels[w_cursor->level_id], w_cursor->tree_id));
#if TEBIS_FORMAT
	w_cursor->number_of_replicas = w_cursor->handle->db_options.options[NUMBER_OF_REPLICAS].value;
	w_cursor->spin_for_replies = false;
	if (w_cursor->handle->db_options.options[WCURSOR_SPIN_FOR_FLUSH_REPLIES].value) {
		// when spinning for replies double buffering in write cursor should be enabled and there should
		// be some replicas available
		assert(w_cursor->handle->db_options.options[ENABLE_COMPACTION_DOUBLE_BUFFERING].value);
		assert(w_cursor->handle->db_options.options[NUMBER_OF_REPLICAS].value > 0);
		w_cursor->spin_for_replies = true;
	}
#endif
	wcursor_seg_buf_array_init(MAX_HEIGHT, w_cursor, enable_double_buffering ? 2 : 1);

	for (uint32_t height = 0; height < MAX_HEIGHT; ++height) {
		w_cursor->segment_offt[height] = sizeof(struct segment_header);
		// struct segment_header *segment = get_segment_for_lsm_level_IO(handle->db_desc, level_id, tree_id);
		// new segment
		struct segment_header *segment = level_allocate_segment(handle->db_desc->dev_levels[level_id], tree_id,
									handle->db_desc, w_cursor->txn_id);
		w_cursor->last_segment_btree_level_offt[height] = ABSOLUTE_ADDRESS(segment);
		w_cursor->first_segment_btree_level_offt[height] = w_cursor->last_segment_btree_level_offt[height] =
			ABSOLUTE_ADDRESS(segment);
		assert(w_cursor->last_segment_btree_level_offt[height]);
		w_cursor->last_node[height] = (struct node_header *)wcursor_get_space(
			w_cursor, height, height == 0 ? LEAF_NODE_SIZE : w_cursor->index_api->index_get_node_size());

		if (0 == height) {
			(*w_cursor->leaf_api->leaf_init)((struct leaf_node *)w_cursor->last_node[height],
							 LEAF_NODE_SIZE);
			continue;
		}
		w_cursor->index_api->index_set_height((struct index_node *)w_cursor->last_node[height], height);
		w_cursor->index_api->index_init_node(DO_NOT_ADD_GUARD, (struct index_node *)w_cursor->last_node[height],
						     internalNode);
	}

	level_create_bf(handle->db_desc->dev_levels[w_cursor->level_id], tree_id,
			wcursor_calculate_level_keys(handle->db_desc, w_cursor->level_id), handle);

	w_cursor->medium_log_LRU_cache = level_id == w_cursor->handle->db_desc->level_medium_inplace ?
						 mlog_cache_init_LRU(w_cursor->handle) :
						 NULL;

	return w_cursor;
}

#if 0
char *nodetype_tostring(nodeType_t type)
{
	switch (type) {
	case leafNode:
		return "leafnode";
	case leafRootNode:
		return "leafRootNode";
	case rootNode:
		return "rootNode";
	case internalNode:
		return "internalnode";
	case paddedSpace:
		return "paddedspace";
	default:
		return "UnknownNode";
	}
}

static void assert_level_segments(db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	uint64_t measure_level_bytes = 0;
	segment_header *segment = db_desc->levels[level_id].first_segment[tree_id];
	assert(segment);

	log_info("First segment in get_assert_level %u %p segment id %lu %s next segment %p", level_id, segment,
		 segment->segment_id, nodetype_tostring(segment->nodetype), segment->next_segment);
	measure_level_bytes += SEGMENT_SIZE;

	for (segment = REAL_ADDRESS(segment->next_segment); segment->next_segment;
	     segment = REAL_ADDRESS(segment->next_segment)) {
		log_info("segment in get_assert_level %u %p segment id %lu %s next %p ", level_id, segment,
			 segment->segment_id, nodetype_tostring(segment->nodetype), segment->next_segment);

		measure_level_bytes += SEGMENT_SIZE;
	}
	log_info("segment in get_assert_level %u %p segment id %lu %s next %p ", level_id, segment, segment->segment_id,
		 nodetype_tostring(segment->nodetype), segment->next_segment);

	measure_level_bytes += SEGMENT_SIZE;

	assert(segment == db_desc->levels[level_id].last_segment[tree_id]);
	assert(measure_level_bytes == db_desc->levels[level_id].offset[tree_id]);
}
#endif

static uint32_t wcursor_calc_offt_in_seg(struct wcursor_level_write_cursor *w_cursor, int32_t height, char *addr)
{
	struct wcursor_seg_buf *seg_buf = wcursor_get_buf(w_cursor, height);
	uint64_t start = (uint64_t)seg_buf->buffer;
	uint64_t end = (uint64_t)addr;
	// log_debug("start is %lu end is %lu", start, end);

	if (end < start) {
		log_fatal("End should be greater than start!");
		assert(0);
		BUG_ON();
	}
	assert(end - start < SEGMENT_SIZE);

	return (end - start) % SEGMENT_SIZE;
}

static void wcursor_stich_level(struct wcursor_level_write_cursor *w_cursor, int32_t height,
				struct segment_header *segment)
{
	if (MAX_HEIGHT - 1 == height) {
		level_set_index_last_seg(w_cursor->handle->db_desc->dev_levels[w_cursor->level_id],
					 REAL_ADDRESS(w_cursor->last_segment_btree_level_offt[height]), 1);
		assert(w_cursor->last_segment_btree_level_offt[height]);
		segment->next_segment = NULL;
		return;
	}
	assert(w_cursor->last_segment_btree_level_offt[height + 1]);
	segment->next_segment = (void *)w_cursor->first_segment_btree_level_offt[height + 1];
}

void wcursor_flush_write_cursor(struct wcursor_level_write_cursor *w_cursor)
{
#if TEBIS_FORMAT
	wcursor_spin_for_buffer_status(w_cursor);
#endif
	// uint32_t level_leaf_size = w_cursor->handle->db_desc->levels[w_cursor->level_id].leaf_size;
	uint32_t level_leaf_size = LEAF_NODE_SIZE;
	for (int32_t height = 0; height < MAX_HEIGHT; ++height) {
		// if (height <= w_cursor->tree_height) {
		assert(w_cursor->segment_offt[height] > 4096);

		struct node_header *padded_node =
			(struct node_header *)wcursor_get_current_node(w_cursor, height, sizeof(struct segment_header));
		if (height <= w_cursor->tree_height && w_cursor->segment_offt[height] % SEGMENT_SIZE != 0)
			padded_node = (struct node_header *)((uint64_t)w_cursor->last_node[height] +
							     (height ? w_cursor->index_api->index_get_node_size() :
								       level_leaf_size));
		padded_node->type = paddedSpace;
		padded_node->height = height;
		/* set the root of the new index */
		if (height == w_cursor->tree_height) {
			log_debug("Merged level has a height off %u", w_cursor->tree_height);

			if (!w_cursor->index_api->index_set_type((struct index_node *)w_cursor->last_node[height],
								 rootNode)) {
				log_fatal("Error setting node type");
				assert(0);
				BUG_ON();
			}

			uint32_t offt = wcursor_calc_offt_in_seg(w_cursor, height, (char *)w_cursor->last_node[height]);
			assert(offt < SEGMENT_SIZE);
			w_cursor->root_offt = w_cursor->last_segment_btree_level_offt[height] + offt;
		}

		struct wcursor_seg_buf *segment_buf = wcursor_get_buf(w_cursor, height);
		struct segment_header *segment_in_mem_buffer = (struct segment_header *)segment_buf->buffer;

		wcursor_stich_level(w_cursor, height, segment_in_mem_buffer);
		wcursor_write_segment(w_cursor, height, w_cursor->last_segment_btree_level_offt[height], 0,
				      SEGMENT_SIZE);
#if TEBIS_FORMAT
		w_cursor->last_flush_request_height = height;
		w_cursor->last_flush_request_clock = w_cursor->clock[height] % w_cursor->num_columns;
		w_cursor->have_send_flush_request = true;
		wcursor_invalidate_status_buffer(w_cursor, w_cursor->last_flush_request_height,
						 w_cursor->last_flush_request_clock);

		//TODO: geostyl callback
		parallax_callbacks_t par_callbacks = w_cursor->handle->db_desc->parallax_callbacks;
		if (are_parallax_callbacks_set(par_callbacks)) {
			struct parallax_callback_funcs par_cb = parallax_get_callbacks(par_callbacks);
			void *context = parallax_get_context(par_callbacks);
			uint32_t src_level = w_cursor->level_id - 1;
			if (par_cb.comp_write_cursor_flush_segment_cb)
				par_cb.comp_write_cursor_flush_segment_cb(
					context, w_cursor->last_segment_btree_level_offt[height], w_cursor, src_level,
					w_cursor->last_flush_request_height, SEGMENT_SIZE,
					w_cursor->last_flush_request_clock, true);
		}

#endif
	}

	level_persist_bf(w_cursor->handle->db_desc->dev_levels[w_cursor->level_id], w_cursor->tree_id);

#if 0
	assert_level_segments(c->handle->db_desc, c->level_id, 1);
#endif
}

void wcursor_close_write_cursor(struct wcursor_level_write_cursor *w_cursor)
{
	wcursor_seg_buf_destroy(w_cursor);
	memset(w_cursor, 0x00, sizeof(struct wcursor_level_write_cursor));
	free(w_cursor);
}

static void wcursor_append_pivot_to_index(int32_t height, struct wcursor_level_write_cursor *w_cursor,
					  uint64_t left_node_offt, struct key_splice *pivot, uint64_t right_node_offt)
{
	//log_debug("Append pivot %.*s left child offt %lu right child offt %lu", pivot->size, pivot->data,
	//	  left_node_offt, right_node_offt);

	if (w_cursor->tree_height < height)
		w_cursor->tree_height = height;

	struct index_node *node = (struct index_node *)w_cursor->last_node[height];

	if (w_cursor->index_api->index_is_empty(node)) {
		w_cursor->index_api->index_add_guard(node, left_node_offt);
		w_cursor->index_api->index_set_height(node, height);
	}

	struct pivot_pointer right = { .child_offt = right_node_offt };

	struct insert_pivot_req ins_pivot_req = { .node = node, .key_splice = pivot, .right_child = &right };
	while (!w_cursor->index_api->index_append_pivot(&ins_pivot_req)) {
		uint32_t offt_l = wcursor_calc_offt_in_seg(w_cursor, height, (char *)w_cursor->last_node[height]);
		uint64_t left_index_offt = w_cursor->last_segment_btree_level_offt[height] + offt_l;

		struct key_splice *pivot_copy_splice = w_cursor->index_api->index_remove_last_key(node);
		struct pivot_pointer *piv_pointer = w_cursor->index_api->index_get_pivot(pivot_copy_splice);
		w_cursor->last_node[height] = (struct node_header *)wcursor_get_space(
			w_cursor, height, w_cursor->index_api->index_get_node_size());

		index_init_node(DO_NOT_ADD_GUARD, (struct index_node *)w_cursor->last_node[height], internalNode);
		ins_pivot_req.node = (struct index_node *)w_cursor->last_node[height];
		index_add_guard(ins_pivot_req.node, piv_pointer->child_offt);
		index_set_height(ins_pivot_req.node, height);

		/*last leaf updated*/
		uint32_t offt_r = wcursor_calc_offt_in_seg(w_cursor, height, (char *)w_cursor->last_node[height]);
		uint64_t right_index_offt = w_cursor->last_segment_btree_level_offt[height] + offt_r;
		wcursor_append_pivot_to_index(height + 1, w_cursor, left_index_offt, pivot_copy_splice,
					      right_index_offt);
		free(pivot_copy_splice);
	}
}

static struct kv_splice_base wcursor_append_medium_L1(struct wcursor_level_write_cursor *w_cursor,
						      struct kv_splice_base *splice_base, char *kv_sep_buf,
						      int32_t kv_sep_buf_size)

{
	if (w_cursor->level_id != 1 || splice_base->kv_cat != MEDIUM_INPLACE)
		return *splice_base;

	struct bt_insert_req ins_req;
	ins_req.metadata.handle = w_cursor->handle;
	ins_req.metadata.log_offset = 0;

	ins_req.metadata.cat = MEDIUM_INLOG;
	ins_req.metadata.level_id = w_cursor->level_id;
	ins_req.metadata.tree_id = 1;
	ins_req.metadata.append_to_log = 1;
	ins_req.metadata.gc_request = 0;
	ins_req.metadata.key_format = KV_FORMAT;
	ins_req.metadata.tombstone = 0;
	ins_req.splice_base = splice_base;
	/*For Tebis-parallax currently*/
	// ins_req.metadata.segment_full_event = 0;
	ins_req.metadata.log_segment_addr = 0;
	ins_req.metadata.log_offset_full_event = 0;
	ins_req.metadata.segment_id = 0;
	ins_req.metadata.end_of_log = 0;
	ins_req.metadata.log_padding = 0;

	struct log_operation log_op = { .metadata = &ins_req.metadata,
					.optype_tolog = insertOp,
					.ins_req = &ins_req,
					.is_medium_log_append = true,
					.txn_id = w_cursor->txn_id };

	char *log_location = append_key_value_to_log(&log_op);

	struct kv_splice_base kv_sep = { .kv_cat = MEDIUM_INLOG,
					 .kv_type = KV_PREFIX,
					 .kv_sep2 = kv_sep2_create(kv_splice_base_get_key_size(splice_base),
								   kv_splice_base_get_key_buf(splice_base),
								   ABSOLUTE_ADDRESS(log_location), kv_sep_buf,
								   kv_sep_buf_size) };
	return kv_sep;
}

static struct key_splice *wcursor_create_pivot(struct kv_splice_base *last_splice, struct kv_splice_base *new_splice)
{
	int32_t key_left_len = kv_splice_base_get_key_size(last_splice);
	const char *key_left = kv_splice_base_get_key_buf(last_splice);
	int32_t key_right_len = kv_splice_base_get_key_size(new_splice);
	const char *key_right = kv_splice_base_get_key_buf(new_splice);
	int32_t min_len = key_left_len < key_right_len ? key_left_len : key_right_len;

	// Find the common prefix length
	int32_t idx = 0;
	for (; idx < min_len && key_left[idx] == key_right[idx]; ++idx)
		;

	if (idx == key_left_len || idx == key_right_len) {
		//just use the new_splice as pivot do not bother
		bool malloced = false;
		struct key_splice *pivot = key_splice_create(kv_splice_base_get_key_buf(new_splice),
							     kv_splice_base_get_key_size(new_splice), NULL, 0,
							     &malloced);
		// log_debug("Just returning the last splice: %.*s no room for optimization ok!",
		// 	  key_splice_get_key_size(pivot), key_splice_get_key_offset(pivot));
		return pivot;
	}

	char pivot_buf[MAX_KEY_SIZE] = { 0 };
	memcpy(pivot_buf, key_left, idx);
	// Add an extra character

	pivot_buf[idx] = (key_left[idx] + 1 < key_right[idx]) ? key_left[idx] + 1 : key_right[idx];
	bool malloced = false;
	struct key_splice *pivot = key_splice_create(pivot_buf, idx + 1, NULL, 0, &malloced);
	// log_debug("Created optimized pivot %.*s optimization ok! last_splice is: %.*s and new_splice: %.*s",
	// 	  key_splice_get_key_size(pivot), key_splice_get_key_offset(pivot),
	// 	  kv_splice_base_get_key_size(last_splice), kv_splice_base_get_key_buf(last_splice),
	// 	  kv_splice_base_get_key_size(new_splice), kv_splice_base_get_key_buf(new_splice));

	return pivot;
}

bool wcursor_append_KV_pair(struct wcursor_level_write_cursor *w_cursor, struct kv_splice_base *splice)
{
	uint64_t left_leaf_offt = 0;
	uint64_t right_leaf_offt = 0;

	struct kv_splice_base new_splice = *splice;

	char kv_sep_buf[KV_SEP2_MAX_SIZE];

	if (w_cursor->level_id == 1 && splice->kv_cat == MEDIUM_INPLACE)
		new_splice = wcursor_append_medium_L1(w_cursor, splice, kv_sep_buf, KV_SEP2_MAX_SIZE);

	if (new_splice.kv_cat == MEDIUM_INLOG &&
	    w_cursor->level_id == w_cursor->handle->db_desc->level_medium_inplace) {
		new_splice.kv_cat = MEDIUM_INPLACE;
		new_splice.kv_type = KV_FORMAT;
		new_splice.kv_splice = (struct kv_splice *)mlog_cache_fetch_kv_from_LRU(
			w_cursor->medium_log_LRU_cache, kv_sep2_get_value_offt(new_splice.kv_sep2));
		assert(kv_splice_base_get_key_size(&new_splice) <= MAX_KEY_SIZE);
		assert(kv_splice_base_get_key_size(&new_splice) > 0);

#if MEASURE_MEDIUM_INPLACE
		__sync_fetch_and_add(&cursor->handle->db_desc->count_medium_inplace, 1);
#endif
	}
	bool new_leaf = false;
	struct key_splice *pivot = NULL;
	if ((*w_cursor->leaf_api->leaf_is_full)((struct leaf_node *)w_cursor->last_node[0],
						kv_splice_base_get_size(&new_splice))) {
		struct kv_splice_base last =
			(*w_cursor->leaf_api->leaf_get_last)((struct leaf_node *)w_cursor->last_node[0]);

		pivot = wcursor_create_pivot(&last, &new_splice);

		uint32_t offt_l = wcursor_calc_offt_in_seg(w_cursor, 0, (char *)w_cursor->last_node[0]);
		left_leaf_offt = w_cursor->last_segment_btree_level_offt[0] + offt_l;
		w_cursor->last_node[0] = (struct node_header *)wcursor_get_space(w_cursor, 0, LEAF_NODE_SIZE);
		(*w_cursor->leaf_api->leaf_init)((struct leaf_node *)w_cursor->last_node[0],
						 // w_cursor->handle->db_desc->levels[w_cursor->level_id].leaf_size);
						 //new leaf
						 LEAF_NODE_SIZE);
		/*last leaf updated*/
		uint32_t offt_r = wcursor_calc_offt_in_seg(w_cursor, 0, (char *)w_cursor->last_node[0]);
		right_leaf_offt = w_cursor->last_segment_btree_level_offt[0] + offt_r;

		new_leaf = true;
	}

	if (!(*w_cursor->leaf_api->leaf_append)((struct leaf_node *)w_cursor->last_node[0], &new_splice,
						new_splice.is_tombstone)) {
		log_fatal("Append in leaf failed (It shouldn't at this point)");
		_exit(EXIT_FAILURE);
	}

	level_increase_size(w_cursor->handle->db_desc->dev_levels[w_cursor->level_id],
			    kv_splice_base_get_size(&new_splice), 1);
	level_add_key_to_bf(w_cursor->handle->db_desc->dev_levels[w_cursor->level_id], w_cursor->tree_id,
			    kv_splice_base_get_key_buf(&new_splice), kv_splice_base_get_key_size(&new_splice));

	level_inc_num_keys(w_cursor->handle->db_desc->dev_levels[w_cursor->level_id], w_cursor->tree_id, 1);

	if (!new_leaf)
		return true;

	// bool malloced = false;
	// struct key_splice *new_pivot = key_splice_create(kv_splice_base_get_key_buf(&pivot),
	// 						 kv_splice_base_get_key_size(&new_splice), NULL, 0, &malloced);

	// assert(malloced);
	wcursor_append_pivot_to_index(1, w_cursor, left_leaf_offt, pivot, right_leaf_offt);
	free(pivot);
	return true;
}

uint8_t wcursor_get_level_id(struct wcursor_level_write_cursor *w_cursor)
{
	return w_cursor->level_id;
}

uint64_t wcursor_get_current_root(struct wcursor_level_write_cursor *w_cursor)
{
	return w_cursor->root_offt;
}

void wcursor_set_LRU_cache(struct wcursor_level_write_cursor *w_cursor, struct medium_log_LRU_cache *mcache)
{
	w_cursor->medium_log_LRU_cache = mcache;
}

struct medium_log_LRU_cache *wcursor_get_LRU_cache(struct wcursor_level_write_cursor *w_cursor)
{
	return w_cursor->medium_log_LRU_cache;
}

wcursor_segment_buffers_iterator_t wcursor_segment_buffers_cursor_init(struct wcursor_level_write_cursor *wcursor)
{
	assert(wcursor);
	struct wcursor_segment_buffers_iterator *new_cursor =
		(struct wcursor_segment_buffers_iterator *)calloc(1, sizeof(struct wcursor_segment_buffers_iterator));
	new_cursor->curr_i = 0;
	new_cursor->wcursor = wcursor;
	return new_cursor;
}

// cppcheck-suppress unusedFunction
char *wcursor_segment_buffers_cursor_get_offt(wcursor_segment_buffers_iterator_t segment_buffers_cursor)
{
	struct wcursor_segment_buffers_iterator *cursor =
		(struct wcursor_segment_buffers_iterator *)segment_buffers_cursor;

	struct wcursor_seg_buf *seg_buf = wcursor_get_buf(cursor->wcursor, cursor->curr_i);
	return seg_buf->buffer;
}

bool wcursor_segment_buffers_cursor_is_valid(wcursor_segment_buffers_iterator_t segment_buffers_cursor)
{
	struct wcursor_segment_buffers_iterator *cursor =
		(struct wcursor_segment_buffers_iterator *)segment_buffers_cursor;
	if (cursor->curr_i >= MAX_HEIGHT)
		return false;
	return true;
}

void wcursor_segment_buffers_cursor_close(wcursor_segment_buffers_iterator_t segment_buffers_cursor)
{
	struct wcursor_segment_buffers_iterator *cursor =
		(struct wcursor_segment_buffers_iterator *)segment_buffers_cursor;
	free(cursor);
}

void wcursor_segment_buffers_cursor_next(wcursor_segment_buffers_iterator_t segment_buffers_cursor)
{
	struct wcursor_segment_buffers_iterator *cursor =
		(struct wcursor_segment_buffers_iterator *)segment_buffers_cursor;
	++cursor->curr_i;
}

int wcursor_get_fd(struct wcursor_level_write_cursor *w_cursor)
{
	return w_cursor->fd;
}

// cppcheck-suppress unusedFunction
char *wcursor_get_cursor_buffer(struct wcursor_level_write_cursor *w_cursor, uint32_t row_id, uint32_t col_id)
{
	assert(w_cursor);
	return (char *)&w_cursor->segment_buffer[row_id * w_cursor->num_columns + col_id];
}

// cppcheck-suppress unusedFunction
uint32_t wcursor_get_segment_buffer_size(struct wcursor_level_write_cursor *w_cursor)
{
	assert(w_cursor);
	return sizeof(struct wcursor_seg_buf) * w_cursor->num_rows * w_cursor->num_columns;
}

uint32_t wcursor_get_number_of_rows(struct wcursor_level_write_cursor *w_cursor)
{
	assert(w_cursor);
	return w_cursor->num_rows;
}

uint32_t wcursor_get_number_of_cols(struct wcursor_level_write_cursor *w_cursor)
{
	assert(w_cursor);
	return w_cursor->num_columns;
}

uint32_t wcursor_get_compaction_index_entry_size(struct wcursor_level_write_cursor *w_cursor)
{
	assert(w_cursor);
	return sizeof(w_cursor->segment_buffer->buffer);
}

// cppcheck-suppress unusedFunction
uint32_t wcursor_segment_buffer_status_size(struct wcursor_level_write_cursor *w_cursor)
{
	assert(w_cursor);
	(void)w_cursor;
#if TEBIS_FORMAT
	return sizeof(w_cursor->segment_buffer->status[0]);
#else
	return UINT32_MAX;
#endif
}

// cppcheck-suppress unusedFunction
volatile char *wcursor_segment_buffer_get_status_addr(struct wcursor_level_write_cursor *w_cursor, uint32_t height,
						      uint32_t clock_id, uint32_t replica_id)
{
	assert(w_cursor);
	(void)w_cursor;
#if TEBIS_FORMAT
	struct wcursor_seg_buf *segment_buffer = wcursor_get_buf_with_coordinates(w_cursor, height, clock_id);
	return segment_buffer->status[replica_id];
#else
	(void)height;
	(void)clock_id;
	(void)replica_id;
	return NULL;
#endif
}

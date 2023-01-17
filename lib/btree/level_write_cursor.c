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
#include "../allocator/device_structures.h"
#include "../allocator/log_structures.h"
#include "../allocator/volume_manager.h"
#include "../common/common.h"
#include "../parallax_callbacks/parallax_callbacks.h"
#include "bloom_filter.h"
#include "btree.h"
#include "btree_node.h"
#include "conf.h"
#include "dynamic_leaf.h"
#include "index_node.h"
#include "key_splice.h"
#include "kv_pairs.h"
#include "medium_log_LRU_cache.h"
#include "parallax/structures.h"
#include "segment_allocator.h"
#include <assert.h>
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define WCURSOR_MAGIC_SMALL_KV_SIZE (33)
#define WCURSOR_ALIGNMNENT (4096UL)
// IWYU pragma: no_forward_declare pbf_desc
// IWYU pragma: no_forward_declare index_node
// IWYU pragma: no_forward_declare key_splice

struct wcursor_seg_buf {
	char buffer[SEGMENT_SIZE];
	uint64_t status;
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
	int32_t tree_height;
	int fd;
	uint32_t num_rows;
	uint32_t num_columns;
	uint32_t clock[MAX_HEIGHT];
	uint8_t level_id;
	uint8_t tree_id;
};

struct wcursor_segment_buffers_iterator {
	int curr_i;
	struct wcursor_level_write_cursor *wcursor;
};

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
}

static struct wcursor_seg_buf *wcursor_get_buf(struct wcursor_level_write_cursor *w_cursor, uint32_t row_id)
{
	uint32_t col_id = w_cursor->clock[row_id] % w_cursor->num_columns;

	return &w_cursor->segment_buffer[row_id * w_cursor->num_columns + col_id];
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
	//Caution this is the device offset where we will write the next segment in the next iteration of the process
	struct segment_header *new_device_segment =
		get_segment_for_lsm_level_IO(w_cursor->handle->db_desc, w_cursor->level_id, 1);
	assert(new_device_segment);

	struct segment_header *segment = (struct segment_header *)wcursor_get_buf(w_cursor, height);

	segment->next_segment = (void *)ABSOLUTE_ADDRESS(new_device_segment);
	segment->segment_id = w_cursor->segment_id_cnt++;

	wcursor_write_segment(w_cursor, height, w_cursor->last_segment_btree_level_offt[height], 0, SEGMENT_SIZE);

	//TODO: geostyl callback
	parallax_callbacks_t par_callbacks = w_cursor->handle->db_desc->parallax_callbacks;
	if (are_parallax_callbacks_set(par_callbacks)) {
		struct parallax_callback_funcs par_cb = parallax_get_callbacks(par_callbacks);
		void *context = parallax_get_context(par_callbacks);
		uint32_t src_level = w_cursor->level_id - 1;
		par_cb.comp_write_cursor_flush_segment_cb(context, src_level, 0, SEGMENT_SIZE, 0);
	}
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
					   SEGMENT_SIZE - (w_cursor->segment_offt[height] % SEGMENT_SIZE) :
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

static int32_t wcursor_calculate_level_keys(struct db_descriptor *db_desc, uint8_t level_id)
{
	assert(level_id > 0);
	uint8_t tree_id = 0; /*Always caclulate the immutable aka 0 tree of the level*/
	int32_t total_keys = db_desc->levels[level_id].num_level_keys[tree_id];

	if (0 == total_keys && 1 == level_id)
		total_keys = db_desc->levels[0].max_level_size / WCURSOR_MAGIC_SMALL_KV_SIZE;

	if (level_id > 1) {
		total_keys += db_desc->levels[level_id - 1].num_level_keys[tree_id];
	}
	// log_debug("Total keys of level %u are %d", level_id, total_keys);
	return total_keys;
}

struct wcursor_level_write_cursor *wcursor_init_write_cursor(uint8_t level_id, struct db_handle *handle,
							     uint8_t tree_id, bool enable_double_buffering)
{
	struct wcursor_level_write_cursor *w_cursor = NULL;
	if (posix_memalign((void **)&w_cursor, ALIGNMENT, sizeof(struct wcursor_level_write_cursor)) != 0) {
		log_fatal("Posix memalign failed");
		perror("Reason: ");
		BUG_ON();
	}
	memset(w_cursor, 0x00, sizeof(struct wcursor_level_write_cursor));
	w_cursor->level_id = level_id;
	w_cursor->tree_id = tree_id;
	w_cursor->tree_height = 0;
	w_cursor->fd = handle->db_desc->db_volume->vol_fd;
	w_cursor->handle = handle;

	wcursor_seg_buf_array_init(MAX_HEIGHT, w_cursor, enable_double_buffering ? 2 : 1);

	assert(0 == handle->db_desc->levels[w_cursor->level_id].offset[w_cursor->tree_id]);

	for (uint32_t height = 0; height < MAX_HEIGHT; ++height) {
		w_cursor->segment_offt[height] = sizeof(struct segment_header);
		struct segment_header *segment = get_segment_for_lsm_level_IO(handle->db_desc, level_id, tree_id);
		w_cursor->last_segment_btree_level_offt[height] = ABSOLUTE_ADDRESS(segment);
		w_cursor->first_segment_btree_level_offt[height] = w_cursor->last_segment_btree_level_offt[height] =
			ABSOLUTE_ADDRESS(segment);
		assert(w_cursor->last_segment_btree_level_offt[height]);
		w_cursor->last_node[height] = (struct node_header *)wcursor_get_space(
			w_cursor, height,
			height == 0 ? w_cursor->handle->db_desc->levels[w_cursor->level_id].leaf_size :
				      index_node_get_size());

		if (0 == height) {
			dl_init_leaf_node((struct leaf_node *)w_cursor->last_node[height],
					  handle->db_desc->levels[level_id].leaf_size);
			continue;
		}
		index_set_height((struct index_node *)w_cursor->last_node[height], height);
		index_init_node(DO_NOT_ADD_GUARD, (struct index_node *)w_cursor->last_node[height], internalNode);
	}

	handle->db_desc->levels[w_cursor->level_id].bloom_desc[w_cursor->tree_id] =
		pbf_create(handle, w_cursor->level_id,
			   wcursor_calculate_level_keys(handle->db_desc, w_cursor->level_id), w_cursor->tree_id);

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

void wcursor_flush_write_cursor(struct wcursor_level_write_cursor *w_cursor)
{
	uint32_t level_leaf_size = w_cursor->handle->db_desc->levels[w_cursor->level_id].leaf_size;

	for (int32_t height = 0; height < MAX_HEIGHT; ++height) {
		// if (height <= w_cursor->tree_height) {
		assert(w_cursor->segment_offt[height] > 4096);

		struct node_header *padded_node =
			(struct node_header *)wcursor_get_current_node(w_cursor, height, sizeof(struct segment_header));
		if (w_cursor->segment_offt[height] % SEGMENT_SIZE != 0)
			padded_node = (struct node_header *)((uint64_t)w_cursor->last_node[height] +
							     (height ? index_node_get_size() : level_leaf_size));
		padded_node->type = paddedSpace;
		padded_node->height = height;
		/* set the root of the new index */
		if (height == w_cursor->tree_height) {
			log_debug("Merged level has a height off %u", w_cursor->tree_height);

			if (!index_set_type((struct index_node *)w_cursor->last_node[height], rootNode)) {
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

		if (MAX_HEIGHT - 1 == height) {
			w_cursor->handle->db_desc->levels[w_cursor->level_id].last_segment[1] =
				REAL_ADDRESS(w_cursor->last_segment_btree_level_offt[height]);
			assert(w_cursor->last_segment_btree_level_offt[height]);
			segment_in_mem_buffer->next_segment = NULL;
		} else {
			assert(w_cursor->last_segment_btree_level_offt[height + 1]);
			segment_in_mem_buffer->next_segment =
				(void *)w_cursor->first_segment_btree_level_offt[height + 1];
		}

		wcursor_write_segment(w_cursor, height, w_cursor->last_segment_btree_level_offt[height], 0,
				      SEGMENT_SIZE);

		//TODO: geostyl callback
		parallax_callbacks_t par_callbacks = w_cursor->handle->db_desc->parallax_callbacks;
		if (are_parallax_callbacks_set(par_callbacks)) {
			struct parallax_callback_funcs par_cb = parallax_get_callbacks(par_callbacks);
			void *context = parallax_get_context(par_callbacks);
			uint32_t src_level = w_cursor->level_id - 1;
			par_cb.comp_write_cursor_flush_segment_cb(context, src_level, height, SEGMENT_SIZE, 1);
		}
	}

	if (!pbf_persist_bloom_filter(
		    w_cursor->handle->db_desc->levels[w_cursor->level_id].bloom_desc[w_cursor->tree_id])) {
		log_fatal("Failed to write bloom filter");
		_exit(EXIT_FAILURE);
	}

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

	if (index_is_empty(node)) {
		index_add_guard(node, left_node_offt);
		index_set_height(node, height);
	}

	struct pivot_pointer right = { .child_offt = right_node_offt };

	struct insert_pivot_req ins_pivot_req = { .node = node, .key_splice = pivot, .right_child = &right };
	while (!index_append_pivot(&ins_pivot_req)) {
		uint32_t offt_l = wcursor_calc_offt_in_seg(w_cursor, height, (char *)w_cursor->last_node[height]);
		uint64_t left_index_offt = w_cursor->last_segment_btree_level_offt[height] + offt_l;

		struct key_splice *pivot_copy_splice = index_remove_last_pivot_key(node);
		struct pivot_pointer *piv_pointer = index_get_pivot_pointer(pivot_copy_splice);
		w_cursor->last_node[height] =
			(struct node_header *)wcursor_get_space(w_cursor, height, index_node_get_size());

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

static void wcursor_init_medium_log(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	log_debug("Initializing medium log for db: %s", db_desc->db_superblock->db_name);
	struct segment_header *segment = seg_get_raw_log_segment(db_desc, MEDIUM_LOG, level_id, tree_id);
	db_desc->medium_log.head_dev_offt = ABSOLUTE_ADDRESS(segment);
	db_desc->medium_log.tail_dev_offt = db_desc->medium_log.head_dev_offt;
	db_desc->medium_log.size = sizeof(segment_header);
	init_log_buffer(&db_desc->medium_log, MEDIUM_LOG);
	struct segment_header *seg_in_mem = (struct segment_header *)db_desc->medium_log.tail[0]->buf;
	seg_in_mem->segment_id = 0;
	seg_in_mem->prev_segment = NULL;
	seg_in_mem->next_segment = NULL;
	log_debug("Done initializing medium log");
}

static struct kv_splice_base wcursor_append_medium_L1(struct wcursor_level_write_cursor *w_cursor,
						      struct kv_splice_base *splice, char *kv_sep_buf,
						      int32_t kv_sep_buf_size)

{
	if (w_cursor->level_id != 1 || splice->cat != MEDIUM_INPLACE)
		return *splice;

	struct db_descriptor *db_desc = w_cursor->handle->db_desc;
	if (db_desc->medium_log.head_dev_offt == 0 && db_desc->medium_log.tail_dev_offt == 0 &&
	    db_desc->medium_log.size == 0) {
		wcursor_init_medium_log(w_cursor->handle->db_desc, w_cursor->level_id, 1);
	}
	struct bt_insert_req ins_req;
	ins_req.metadata.handle = w_cursor->handle;
	ins_req.metadata.log_offset = 0;

	ins_req.metadata.cat = MEDIUM_INLOG;
	ins_req.metadata.level_id = w_cursor->level_id;
	ins_req.metadata.tree_id = 1;
	ins_req.metadata.append_to_log = 1;
	ins_req.metadata.gc_request = 0;
	ins_req.metadata.recovery_request = 0;
	ins_req.metadata.key_format = KV_FORMAT;
	ins_req.metadata.tombstone = 0;
	ins_req.key_value_buf = (char *)kv_splice_base_get_reference(splice);
	ins_req.metadata.reorganized_leaf_pos_INnode = NULL;
	/*For Tebis-parallax currently*/
	ins_req.metadata.segment_full_event = 0;
	ins_req.metadata.log_segment_addr = 0;
	ins_req.metadata.log_offset_full_event = 0;
	ins_req.metadata.segment_id = 0;
	ins_req.metadata.end_of_log = 0;
	ins_req.metadata.log_padding = 0;

	struct log_operation log_op = { log_op.metadata = &ins_req.metadata, log_op.optype_tolog = insertOp,
					log_op.ins_req = &ins_req, log_op.is_medium_log_append = true };

	char *log_location = append_key_value_to_log(&log_op);

	struct kv_splice_base kv_sep = {
		.cat = MEDIUM_INLOG,
		.kv_sep2 = kv_sep2_create(kv_splice_base_get_key_size(splice), kv_splice_base_get_key_buf(splice),
					  ABSOLUTE_ADDRESS(log_location), kv_sep_buf, kv_sep_buf_size)
	};
	return kv_sep;
}

bool wcursor_append_KV_pair(struct wcursor_level_write_cursor *w_cursor, struct kv_splice_base *splice)
{
	uint64_t left_leaf_offt = 0;
	uint64_t right_leaf_offt = 0;

	struct kv_splice_base new_splice = *splice;

	char kv_sep_buf[KV_SEP2_MAX_SIZE];

	if (w_cursor->level_id == 1 && splice->cat == MEDIUM_INPLACE)
		new_splice = wcursor_append_medium_L1(w_cursor, splice, kv_sep_buf, KV_SEP2_MAX_SIZE);

	if (new_splice.cat == MEDIUM_INLOG && w_cursor->level_id == w_cursor->handle->db_desc->level_medium_inplace) {
		new_splice.cat = MEDIUM_INPLACE;
		new_splice.kv_splice = (struct kv_splice *)mlog_cache_fetch_kv_from_LRU(
			w_cursor->medium_log_LRU_cache, kv_sep2_get_value_offt(new_splice.kv_sep2));
		assert(kv_splice_base_get_key_size(&new_splice) <= MAX_KEY_SIZE);
		assert(kv_splice_base_get_key_size(&new_splice) > 0);

#if MEASURE_MEDIUM_INPLACE
		__sync_fetch_and_add(&cursor->handle->db_desc->count_medium_inplace, 1);
#endif
	}
	bool new_leaf = false;
	if (dl_is_leaf_full((struct leaf_node *)w_cursor->last_node[0], kv_splice_base_get_size(&new_splice))) {
		uint32_t offt_l = wcursor_calc_offt_in_seg(w_cursor, 0, (char *)w_cursor->last_node[0]);
		left_leaf_offt = w_cursor->last_segment_btree_level_offt[0] + offt_l;
		w_cursor->last_node[0] = (struct node_header *)wcursor_get_space(
			w_cursor, 0, w_cursor->handle->db_desc->levels[w_cursor->level_id].leaf_size);
		dl_init_leaf_node((struct leaf_node *)w_cursor->last_node[0],
				  w_cursor->handle->db_desc->levels[w_cursor->level_id].leaf_size);
		/*last leaf updated*/
		uint32_t offt_r = wcursor_calc_offt_in_seg(w_cursor, 0, (char *)w_cursor->last_node[0]);
		right_leaf_offt = w_cursor->last_segment_btree_level_offt[0] + offt_r;

		new_leaf = true;
	}
	if (!dl_append_splice_in_dynamic_leaf((struct leaf_node *)w_cursor->last_node[0], &new_splice,
					      new_splice.is_tombstone)) {
		log_fatal("Append in leaf failed (It shouldn't at this point)");
		_exit(EXIT_FAILURE);
	}

	w_cursor->handle->db_desc->levels[w_cursor->level_id].level_size[1] += kv_splice_base_get_size(&new_splice);
	int bloom_stat =
		pbf_bloom_add(w_cursor->handle->db_desc->levels[w_cursor->level_id].bloom_desc[w_cursor->tree_id],
			      kv_splice_base_get_key_buf(&new_splice), kv_splice_base_get_key_size(&new_splice));

	if (0 == bloom_stat) {
		log_fatal(
			"Either collision in bloom filter (should not happen all keys in a compaction are unique) or general failure");
		_exit(EXIT_FAILURE);
	}
	/*XXX TODO XXX Leakage here of level, add an API call to level to do this operation*/
	++w_cursor->handle->db_desc->levels[w_cursor->level_id].num_level_keys[w_cursor->tree_id];
	if (!new_leaf)
		return true;

	bool malloced = false;
	struct key_splice *new_pivot = key_splice_create(kv_splice_base_get_key_buf(&new_splice),
							 kv_splice_base_get_key_size(&new_splice), NULL, 0, &malloced);

	assert(malloced);
	wcursor_append_pivot_to_index(1, w_cursor, left_leaf_offt, new_pivot, right_leaf_offt);
	free(new_pivot);
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

static void wcursor_stich_level(struct wcursor_level_write_cursor *w_cursor, int32_t height, char *buf,
				uint32_t buf_size)
{
	struct segment_header *curr_in_mem_segment = (struct segment_header *)buf;
	if (MAX_HEIGHT - 1 == height) {
		w_cursor->handle->db_desc->levels[w_cursor->level_id].last_segment[1] =
			REAL_ADDRESS(w_cursor->last_segment_btree_level_offt[height]);
		assert(w_cursor->last_segment_btree_level_offt[height]);
		curr_in_mem_segment->next_segment = NULL;
	} else {
		assert(w_cursor->last_segment_btree_level_offt[height + 1]);
		curr_in_mem_segment->next_segment = (void *)w_cursor->first_segment_btree_level_offt[height + 1];
	}

	wcursor_write_segment(w_cursor, height, w_cursor->last_segment_btree_level_offt[height], 0, buf_size);
}

void wcursor_append_index_segment(struct wcursor_level_write_cursor *wcursor, int32_t height, char *buf,
				  uint32_t buf_size, uint8_t is_last_segment)
{
	assert(wcursor);
	assert(buf_size == SEGMENT_SIZE);

	if (is_last_segment) {
		wcursor_stich_level(wcursor, height, buf, buf_size);
		return;
	}

	struct segment_header *new_device_segment =
		get_segment_for_lsm_level_IO(wcursor->handle->db_desc, wcursor->level_id, 1);
	uint64_t new_device_segment_offt = ABSOLUTE_ADDRESS(new_device_segment);
	assert(new_device_segment && new_device_segment_offt);

	struct segment_header *current_in_mem_segment = (struct segment_header *)buf;
	current_in_mem_segment->next_segment = (void *)new_device_segment_offt;

	wcursor_write_segment(wcursor, height, wcursor->last_segment_btree_level_offt[height], 0, buf_size);
	wcursor->last_segment_btree_level_offt[height] = new_device_segment_offt;
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

char *wcursor_get_segment_buffer_offt(struct wcursor_level_write_cursor *w_cursor)
{
	assert(w_cursor);
	return (char *)w_cursor->segment_buffer;
}

uint32_t wcursor_get_segment_buffer_size(struct wcursor_level_write_cursor *w_cursor)
{
	assert(w_cursor);
	return sizeof(struct wcursor_seg_buf) * w_cursor->num_rows * w_cursor->num_columns;
}

// Copyright [2021] [FORTH-ICS]
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

#define _GNU_SOURCE

#include "compaction_daemon.h"
#include "../../utilities/dups_list.h"
#include "../allocator/device_structures.h"
#include "../allocator/log_structures.h"
#include "../allocator/redo_undo_log.h"
#include "../allocator/volume_manager.h"
#include "../common/common.h"
#include "../scanner/min_max_heap.h"
#include "../scanner/scanner.h"
#include "btree.h"
#include "conf.h"
#include "dynamic_leaf.h"
#include "gc.h"
#include "index_node.h"
#include "medium_log_LRU_cache.h"
#include "segment_allocator.h"
#include <assert.h>
#include <log.h>
#include <pthread.h>
#include <semaphore.h>
#include <spin_loop.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uthash.h>

static void comp_medium_log_set_max_segment_id(struct comp_level_write_cursor *c)
{
	uint64_t max_segment_id = 0;
	uint64_t max_segment_offt = 0;

	struct medium_log_segment_map *current_entry = NULL;
	struct medium_log_segment_map *tmp = NULL;
	HASH_ITER(hh, c->medium_log_segment_map, current_entry, tmp)
	{
		/* Suprresses possible null pointer dereference of cppcheck*/
		assert(current_entry);
		uint64_t segment_id = current_entry->id;
		if (UINT64_MAX == segment_id) {
			struct segment_header *segment = REAL_ADDRESS(current_entry->dev_offt);
			segment_id = segment->segment_id;
		}

		// cppcheck-suppress unsignedPositive
		if (segment_id >= max_segment_id) {
			max_segment_id = segment_id;
			max_segment_offt = current_entry->dev_offt;
		}
		HASH_DEL(c->medium_log_segment_map, current_entry);
		free(current_entry);
	}
	struct level_descriptor *level_desc = &c->handle->db_desc->levels[c->level_id];
	level_desc->medium_in_place_max_segment_id = max_segment_id;
	level_desc->medium_in_place_segment_dev_offt = max_segment_offt;
	log_debug("Max segment id touched during medium transfer to in place is %lu and corresponding offt: %lu",
		  max_segment_id, max_segment_offt);
}

static void fetch_segment_chunk(struct comp_level_write_cursor *c, uint64_t log_chunk_dev_offt, char *segment_buf,
				ssize_t size)
{
	off_t dev_offt = log_chunk_dev_offt;
	ssize_t bytes_to_read = 0;

	while (bytes_to_read < size) {
		ssize_t bytes = pread(c->handle->db_desc->db_volume->vol_fd, &segment_buf[bytes_to_read],
				      size - bytes_to_read, dev_offt + bytes_to_read);
		if (bytes == -1) {
			log_fatal("Failed to read error code");
			perror("Error");
			BUG_ON();
		}
		bytes_to_read += bytes;
	}

	if (c->level_id != c->handle->db_desc->level_medium_inplace)
		return;

	uint64_t segment_dev_offt = log_chunk_dev_offt - (log_chunk_dev_offt % SEGMENT_SIZE);

	struct medium_log_segment_map *entry = NULL;
	//log_debug("Searching segment offt: %lu log chunk offt %lu mod %lu", segment_dev_offt, log_chunk_dev_offt,
	//	  log_chunk_dev_offt % SEGMENT_SIZE);
	HASH_FIND_PTR(c->medium_log_segment_map, &segment_dev_offt, entry);

	/*Never seen it before*/
	bool found = true;

	if (!entry) {
		entry = calloc(1, sizeof(*entry));
		entry->dev_offt = segment_dev_offt;
		found = false;
	}

	/*Already seen and set its id, nothing to do*/
	if (found && entry->id != UINT64_MAX)
		return;

	entry->dev_offt = segment_dev_offt;
	entry->id = UINT64_MAX;

	if (0 == log_chunk_dev_offt % SEGMENT_SIZE) {
		struct segment_header *segment = (struct segment_header *)segment_buf;
		entry->id = segment->segment_id;
	}

	if (!found)
		HASH_ADD_PTR(c->medium_log_segment_map, dev_offt, entry);
}

static char *fetch_kv_from_LRU(struct write_dynamic_leaf_args *args, struct comp_level_write_cursor *c)
{
	char *segment_chunk = NULL, *kv_in_seg = NULL;
	uint64_t segment_offset, which_chunk, segment_chunk_offt;
	segment_offset = ABSOLUTE_ADDRESS(args->kv_dev_offt) - (ABSOLUTE_ADDRESS(args->kv_dev_offt) % SEGMENT_SIZE);

	which_chunk = (ABSOLUTE_ADDRESS(args->kv_dev_offt) % SEGMENT_SIZE) / LOG_CHUNK_SIZE;

	segment_chunk_offt = segment_offset + (which_chunk * LOG_CHUNK_SIZE);

	if (!chunk_exists_in_LRU(c->medium_log_LRU_cache, segment_chunk_offt)) {
		if (posix_memalign((void **)&segment_chunk, ALIGNMENT_SIZE, LOG_CHUNK_SIZE + KB(4)) != 0) {
			log_fatal("MEMALIGN FAILED");
			BUG_ON();
		}
		fetch_segment_chunk(c, segment_chunk_offt, segment_chunk, LOG_CHUNK_SIZE + KB(4));
		add_to_LRU(c->medium_log_LRU_cache, segment_chunk_offt, segment_chunk);
	} else
		segment_chunk = get_chunk_from_LRU(c->medium_log_LRU_cache, segment_chunk_offt);

	kv_in_seg =
		&segment_chunk[(ABSOLUTE_ADDRESS(args->kv_dev_offt) % SEGMENT_SIZE) - (which_chunk * LOG_CHUNK_SIZE)];

	return kv_in_seg;
}

static uint32_t comp_calc_offt_in_seg(char *buffer_start, char *addr)
{
	uint64_t start = (uint64_t)buffer_start;
	uint64_t end = (uint64_t)addr;

	if (end < start) {
		log_fatal("End should be greater than start!");
		BUG_ON();
	}
	assert(end - start < SEGMENT_SIZE);

	return (end - start) % SEGMENT_SIZE;
}

struct compaction_roots {
	struct node_header *src_root;
	struct node_header *dst_root;
};

static void comp_write_segment(char *buffer, uint64_t dev_offt, uint32_t buf_offt, uint32_t size, int fd)
{
#if 0
	struct node_header *n = (struct node_header *)&buffer[sizeof(struct segment_header)];
	switch (n->type) {
	case rootNode:
	case internalNode: {
		uint32_t decoded = sizeof(struct segment_header);
		while (decoded < SEGMENT_SIZE) {
			if (n->type == paddedSpace)
				break;
			assert(n->type == rootNode || n->type == internalNode);
			n = (struct node_header *)((char *)n + INDEX_NODE_SIZE);
			decoded += (INDEX_NODE_SIZE);
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
		assert(num_leaves == 255);
		break;
	}
	case paddedSpace:
		break;
	default:
			BUG_ON();
	}
#endif
	ssize_t total_bytes_written = buf_offt;
	while (total_bytes_written < size) {
		ssize_t bytes_written = pwrite(fd, &buffer[total_bytes_written], size - total_bytes_written,
					       dev_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to writed segment for leaf nodes reason follows");
			perror("Reason");
			BUG_ON();
		}
		total_bytes_written += bytes_written;
	}
}

static void comp_init_dynamic_leaf(struct bt_dynamic_leaf_node *leaf)
{
	leaf->header.type = leafNode;
	leaf->header.num_entries = 0;
	leaf->header.fragmentation = 0;

	leaf->header.leaf_log_size = 0;
	leaf->header.height = 0;
}

static void comp_init_read_cursor(struct comp_level_read_cursor *c, db_handle *handle, uint32_t level_id,
				  uint32_t tree_id, int fd)
{
	memset(c, 0, sizeof(struct comp_level_read_cursor));
	c->fd = fd;
	c->offset = 0;
	c->handle = handle;
	c->curr_segment = NULL;
	c->level_id = level_id;
	c->tree_id = tree_id;
	c->curr_leaf_entry = 0;
	c->end_of_level = 0;
	c->state = COMP_CUR_FETCH_NEXT_SEGMENT;
}

static void comp_get_next_key(struct comp_level_read_cursor *c)
{
	if (c == NULL) {
		log_fatal("NULL cursor!");
		BUG_ON();
	}

	uint32_t level_leaf_size = c->handle->db_desc->levels[c->level_id].leaf_size;
	if (c->end_of_level)
		return;
	while (1) {
	fsm_entry:
		switch (c->state) {
		case COMP_CUR_CHECK_OFFT: {
			if (c->offset >= c->handle->db_desc->levels[c->level_id].offset[c->tree_id]) {
				log_debug("Done read level %u", c->level_id);
				c->end_of_level = 1;
				assert(c->offset == c->handle->db_desc->levels[c->level_id].offset[c->tree_id]);
				return;
			}
			if (c->offset % SEGMENT_SIZE == 0)
				c->state = COMP_CUR_FETCH_NEXT_SEGMENT;
			else
				c->state = COMP_CUR_FIND_LEAF;
			break;
		}

		case COMP_CUR_FETCH_NEXT_SEGMENT: {
			if (c->curr_segment == NULL) {
				c->curr_segment = c->handle->db_desc->levels[c->level_id].first_segment[c->tree_id];
			} else {
				if (c->curr_segment->next_segment == NULL) {
					assert((uint64_t)c->curr_segment ==
					       (uint64_t)c->handle->db_desc->levels[c->level_id]
						       .last_segment[c->tree_id]);
					log_debug("Done reading level %u cursor offset %lu total offt %lu", c->level_id,
						  c->offset,
						  c->handle->db_desc->levels[c->level_id].offset[c->tree_id]);
					assert(c->offset == c->handle->db_desc->levels[c->level_id].offset[c->tree_id]);
					c->state = COMP_CUR_CHECK_OFFT;
					//TODO replace goto with continue;
					//TODO Rename device_offt
					goto fsm_entry;
				} else
					c->curr_segment =
						(segment_header *)REAL_ADDRESS((uint64_t)c->curr_segment->next_segment);
			}
			/*log_info("Fetching next segment id %llu for [%lu][%lu]", c->curr_segment->segment_id,
				 c->level_id, c->tree_id);*/
			/*read the segment*/

			off_t dev_offt = ABSOLUTE_ADDRESS(c->curr_segment);
			//	log_info("Reading level segment from dev_offt: %llu", dev_offt);
			ssize_t bytes_read = 0; //sizeof(struct segment_header);
			while (bytes_read < SEGMENT_SIZE) {
				ssize_t bytes = pread(c->fd, &c->segment_buf[bytes_read], SEGMENT_SIZE - bytes_read,
						      dev_offt + bytes_read);
				if (-1 == bytes) {
					log_fatal("Failed to read error code");
					perror("Error");
					BUG_ON();
				}
				bytes_read += bytes;
			}
			c->offset += sizeof(struct segment_header);
			c->state = COMP_CUR_FIND_LEAF;
			break;
		}

		case COMP_CUR_DECODE_KV: {
			struct bt_dynamic_leaf_node *leaf =
				(struct bt_dynamic_leaf_node *)((uint64_t)c->segment_buf + (c->offset % SEGMENT_SIZE));
			// slot array entry
			if (c->curr_leaf_entry >= leaf->header.num_entries) {
				// done with this leaf
				c->curr_leaf_entry = 0;
				c->offset += level_leaf_size;
				c->state = COMP_CUR_CHECK_OFFT;
				break;
			}
			struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);

			c->category = slot_array[c->curr_leaf_entry].key_category;
			c->cursor_key.tombstone = slot_array[c->curr_leaf_entry].tombstone;
			char *kv_loc = get_kv_offset(leaf, level_leaf_size, slot_array[c->curr_leaf_entry].index);
			switch (c->category) {
			case SMALL_INPLACE:
			case MEDIUM_INPLACE: {
				// Real key in KV_FORMAT
				c->cursor_key.kv_inplace =
					fill_keybuf(kv_loc, get_kv_format(slot_array[c->curr_leaf_entry].key_category));
				break;
			}
			case MEDIUM_INLOG:
			case BIG_INLOG:
				c->cursor_key.kv_inlog = (struct bt_leaf_entry *)kv_loc;
				c->cursor_key.kv_inlog->dev_offt =
					(uint64_t)REAL_ADDRESS(c->cursor_key.kv_inlog->dev_offt);
				break;
			default:
				log_fatal("Cannot handle this category");
				BUG_ON();
			}
			++c->curr_leaf_entry;
			return;
		}

		case COMP_CUR_FIND_LEAF: {
			/*read four bytes to check what is the node format*/
			nodeType_t type = *(uint32_t *)(&c->segment_buf[c->offset % SEGMENT_SIZE]);
			switch (type) {
			case leafNode:
			case leafRootNode:
				//__sync_fetch_and_add(&leaves, 1);
				//log_info("Found a leaf!");
				c->state = COMP_CUR_DECODE_KV;
				goto fsm_entry;

			case rootNode:
			case internalNode:
				/*log_info("Found an internal");*/
				c->offset += INDEX_NODE_SIZE;
				c->state = COMP_CUR_CHECK_OFFT;
				goto fsm_entry;

			case paddedSpace:
				/*log_info("Found padded space of size %llu",
					 (SEGMENT_SIZE - (c->offset % SEGMENT_SIZE)));*/
				c->offset += (SEGMENT_SIZE - (c->offset % SEGMENT_SIZE));
				c->state = COMP_CUR_CHECK_OFFT;
				goto fsm_entry;
			default:
				log_fatal("Faulty read cursor of level %u Wrong node type %u offset "
					  "was %lu total level offset %lu faulty segment offt: %lu",
					  c->level_id, type, c->offset,
					  c->handle->db_desc->levels[c->level_id].offset[0],
					  ABSOLUTE_ADDRESS(c->curr_segment));
				BUG_ON();
			}

			break;
		}
		default:
			log_fatal("Error state");
			BUG_ON();
		}
	}
}

static void comp_init_write_cursor(struct comp_level_write_cursor *c, struct db_handle *handle, int level_id, int fd)
{
	memset(c, 0, sizeof(struct comp_level_write_cursor));
	c->level_id = level_id;
	c->tree_height = 0;
	c->fd = fd;
	c->handle = handle;

	comp_get_space(c, 0, leafNode);
	assert(c->last_segment_btree_level_offt[0]);
	c->first_segment_btree_level_offt[0] = c->last_segment_btree_level_offt[0];

	for (int i = 1; i < MAX_HEIGHT; ++i) {
		comp_get_space(c, i, internalNode);
		index_init_node(DO_NOT_ADD_GUARD, (struct index_node *)c->last_index[i], internalNode);
		c->first_segment_btree_level_offt[i] = c->last_segment_btree_level_offt[i];
		assert(c->last_segment_btree_level_offt[i]);
	}
}

/*mini allocator*/
static void comp_get_space(struct comp_level_write_cursor *c, uint32_t height, nodeType_t type)
{
	assert(height < MAX_HEIGHT);

	struct level_descriptor *level_desc = &c->handle->db_desc->levels[c->level_id];
	uint32_t level_leaf_size = level_desc->leaf_size;
	switch (type) {
	case leafNode:
	case leafRootNode: {
		uint32_t remaining_space;
		if (c->segment_offt[0] == 0)
			remaining_space = 0;
		else if (c->segment_offt[0] % SEGMENT_SIZE == 0)
			remaining_space = 0;
		else
			remaining_space = SEGMENT_SIZE - c->segment_offt[0] % SEGMENT_SIZE;
		if (remaining_space < level_leaf_size) {
			if (remaining_space > 0) {
				*(uint32_t *)&c->segment_buf[0][c->segment_offt[0] % SEGMENT_SIZE] = paddedSpace;
				c->segment_offt[0] += remaining_space;
			}

			struct segment_header *new_device_segment =
				get_segment_for_lsm_level_IO(c->handle->db_desc, c->level_id, 1);
			struct segment_header *current_segment_mem_buffer =
				(struct segment_header *)&c->segment_buf[0][0];

			if (c->segment_offt[height] != 0) {
				current_segment_mem_buffer->next_segment = (void *)ABSOLUTE_ADDRESS(new_device_segment);

				assert(new_device_segment);
				assert(current_segment_mem_buffer->next_segment);
				comp_write_segment(c->segment_buf[0], c->last_segment_btree_level_offt[0], 0,
						   SEGMENT_SIZE, c->fd);
			}

			memset(&c->segment_buf[0][0], 0x00, sizeof(struct segment_header));

			c->last_segment_btree_level_offt[0] = ABSOLUTE_ADDRESS(new_device_segment);
			c->segment_offt[0] = sizeof(struct segment_header);
			current_segment_mem_buffer->segment_id = c->segment_id_cnt++;
			current_segment_mem_buffer->nodetype = type;
		}
		c->last_leaf = (struct bt_dynamic_leaf_node *)(&c->segment_buf[0][(c->segment_offt[0] % SEGMENT_SIZE)]);
		comp_init_dynamic_leaf(c->last_leaf);
		c->segment_offt[0] += level_leaf_size;
		break;
	}
	case internalNode:
	case rootNode: {
		uint32_t remaining_space;
		if (c->segment_offt[height] == 0)
			remaining_space = 0;
		else if (c->segment_offt[height] % SEGMENT_SIZE == 0)
			remaining_space = 0;
		else
			remaining_space = SEGMENT_SIZE - (c->segment_offt[height] % SEGMENT_SIZE);

		if (remaining_space < INDEX_NODE_SIZE) {
			if (remaining_space > 0) {
				*(uint32_t *)(&c->segment_buf[height][c->segment_offt[height] % SEGMENT_SIZE]) =
					paddedSpace;
				c->segment_offt[height] += remaining_space;
			}

			struct segment_header *new_device_segment =
				get_segment_for_lsm_level_IO(c->handle->db_desc, c->level_id, 1);
			struct segment_header *current_segment_mem_buffer =
				(struct segment_header *)&c->segment_buf[height][0];

			if (c->segment_offt[height] != 0) {
				current_segment_mem_buffer->next_segment = (void *)ABSOLUTE_ADDRESS(new_device_segment);

				assert(new_device_segment);
				assert(current_segment_mem_buffer->next_segment);

				comp_write_segment(c->segment_buf[height], c->last_segment_btree_level_offt[height], 0,
						   SEGMENT_SIZE, c->fd);
			}

			memset(&c->segment_buf[height][0], 0x00, sizeof(struct segment_header));
			c->segment_offt[height] += sizeof(struct segment_header);
			c->last_segment_btree_level_offt[height] = ABSOLUTE_ADDRESS(new_device_segment);
			current_segment_mem_buffer->segment_id = c->segment_id_cnt++;
			current_segment_mem_buffer->nodetype = type;
		}
		c->last_index[height] =
			(struct index_node *)&c->segment_buf[height][c->segment_offt[height] % SEGMENT_SIZE];
		c->segment_offt[height] += INDEX_NODE_SIZE;
		break;
	}
	default:
		log_fatal("Wrong type");
		BUG_ON();
	}
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

	log_debug("Measured %lu offset in level %lu", measure_level_bytes, db_desc->levels[level_id].offset[tree_id]);
	assert(segment == db_desc->levels[level_id].last_segment[tree_id]);
	assert(measure_level_bytes == db_desc->levels[level_id].offset[tree_id]);
}
#endif

static void comp_close_write_cursor(struct comp_level_write_cursor *c)
{
	uint32_t level_leaf_size = c->handle->db_desc->levels[c->level_id].leaf_size;
	for (int32_t i = 0; i < MAX_HEIGHT; ++i) {
		uint32_t *type;
		//log_debug("i = %u tree height: %u", i, c->tree_height);

		if (i <= c->tree_height) {
			assert(c->segment_offt[i] > 4096);
			if (i == 0 && c->segment_offt[i] % SEGMENT_SIZE != 0) {
				type = (uint32_t *)((uint64_t)c->last_leaf + level_leaf_size);
				//log_info("Marking padded space for %u segment offt %llu", i, c->segment_offt[0]);
				*type = paddedSpace;
			} else if (i > 0 && c->segment_offt[i] % SEGMENT_SIZE != 0) {
				type = (uint32_t *)(((char *)c->last_index[i]) + INDEX_NODE_SIZE);
				// log_info("Marking padded space for %u segment offt %llu entries of
				// last node %llu", i,
				//	 c->segment_offt[i], c->last_index[i]->header.num_entries);
				*type = paddedSpace;
			}
		} else {
			type = (uint32_t *)&c->segment_buf[i][sizeof(struct segment_header)];
			*type = paddedSpace;
			//log_debug("Marking full padded space for level_id %u tree height %u", c->level_id,
			//	  c->tree_height);
		}

		if (i == c->tree_height) {
			log_debug("Merged level has a height off %u", c->tree_height);

			if (!index_set_type((struct index_node *)c->last_index[i], rootNode)) {
				log_fatal("Error setting node type");
				BUG_ON();
			}
			uint32_t offt = comp_calc_offt_in_seg(c->segment_buf[i], (char *)c->last_index[i]);
			c->root_offt = c->last_segment_btree_level_offt[i] + offt;
			c->handle->db_desc->levels[c->level_id].root_r[1] = REAL_ADDRESS(c->root_offt);
		}

		struct segment_header *segment_in_mem_buffer = (struct segment_header *)c->segment_buf[i];
		//segment_in_mem_buffer->segment_id = c->segment_id_cnt++;
		//assert(c->segment_id_cnt != 251);
		/* segment_in_mem_buffer->nodetype = paddedSpace; */

		if (MAX_HEIGHT - 1 == i) {
			c->handle->db_desc->levels[c->level_id].last_segment[1] =
				REAL_ADDRESS(c->last_segment_btree_level_offt[i]);
			assert(c->last_segment_btree_level_offt[i]);
			segment_in_mem_buffer->next_segment = NULL;
		} else {
			assert(c->last_segment_btree_level_offt[i + 1]);
			segment_in_mem_buffer->next_segment = (void *)c->first_segment_btree_level_offt[i + 1];
		}
		comp_write_segment(c->segment_buf[i], c->last_segment_btree_level_offt[i], 0, SEGMENT_SIZE, c->fd);
	}

#if 0
	assert_level_segments(c->handle->db_desc, c->level_id, 1);
#endif
}

static void comp_append_pivot_to_index(int32_t height, struct comp_level_write_cursor *c, uint64_t left_node_offt,
				       struct pivot_key *pivot, uint64_t right_node_offt)
{
	//log_debug("Append pivot %.*s left child offt %lu right child offt %lu", pivot->size, pivot->data,
	//	  left_node_offt, right_node_offt);

	if (c->tree_height < height)
		c->tree_height = height;

	struct index_node *node = (struct index_node *)c->last_index[height];

	if (index_is_empty(node)) {
		index_add_guard(node, left_node_offt);
		index_set_height(node, height);
	}

	struct pivot_pointer right = { .child_offt = right_node_offt };

	struct insert_pivot_req ins_pivot_req = { .node = node, .key = pivot, .right_child = &right };
	while (!index_append_pivot(&ins_pivot_req)) {
		uint32_t offt_l = comp_calc_offt_in_seg(c->segment_buf[height], (char *)c->last_index[height]);
		uint64_t left_index_offt = c->last_segment_btree_level_offt[height] + offt_l;

		struct pivot_key *pivot_copy = index_remove_last_pivot_key(node);
		struct pivot_pointer *piv_pointer =
			(struct pivot_pointer *)&((char *)pivot_copy)[PIVOT_KEY_SIZE(pivot_copy)];
		comp_get_space(c, height, internalNode);
		ins_pivot_req.node = (struct index_node *)c->last_index[height];
		index_init_node(DO_NOT_ADD_GUARD, ins_pivot_req.node, internalNode);
		index_add_guard(ins_pivot_req.node, piv_pointer->child_offt);
		index_set_height(ins_pivot_req.node, height);

		/*last leaf updated*/
		uint32_t offt_r = comp_calc_offt_in_seg(c->segment_buf[height], (char *)c->last_index[height]);
		uint64_t right_index_offt = c->last_segment_btree_level_offt[height] + offt_r;
		comp_append_pivot_to_index(height + 1, c, left_index_offt, pivot_copy, right_index_offt);
		free(pivot_copy);
	}
}

static void comp_init_medium_log(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	log_debug("Initializing medium log for db: %s", db_desc->db_superblock->db_name);
	struct segment_header *s = seg_get_raw_log_segment(db_desc, MEDIUM_LOG, level_id, tree_id);
	db_desc->medium_log.head_dev_offt = ABSOLUTE_ADDRESS(s);
	db_desc->medium_log.tail_dev_offt = db_desc->medium_log.head_dev_offt;
	db_desc->medium_log.size = sizeof(segment_header);
	init_log_buffer(&db_desc->medium_log, MEDIUM_LOG);
	struct segment_header *seg_in_mem = (struct segment_header *)db_desc->medium_log.tail[0]->buf;
	seg_in_mem->segment_id = 0;
	seg_in_mem->prev_segment = NULL;
	seg_in_mem->next_segment = NULL;
}

static int comp_append_medium_L1(struct comp_level_write_cursor *c, struct comp_parallax_key *in,
				 struct comp_parallax_key *out)
{
	if (c->level_id != 1)
		return 0;
	if (in->kv_category != MEDIUM_INPLACE)
		return 0;

	struct db_descriptor *db_desc = c->handle->db_desc;
	if (db_desc->medium_log.head_dev_offt == 0 && db_desc->medium_log.tail_dev_offt == 0 &&
	    db_desc->medium_log.size == 0) {
		comp_init_medium_log(c->handle->db_desc, c->level_id, 1);
	}
	struct bt_insert_req ins_req;
	ins_req.metadata.handle = c->handle;
	ins_req.metadata.log_offset = 0;

	ins_req.metadata.kv_size = sizeof(uint32_t) + sizeof(uint32_t); // key_size | value_size
	ins_req.metadata.kv_size += GET_KEY_SIZE(in->kv_inplace) + GET_VALUE_SIZE(in->kv_inplace); // key | value
	ins_req.metadata.cat = MEDIUM_INLOG;
	ins_req.metadata.level_id = c->level_id;
	ins_req.metadata.tree_id = 1;
	ins_req.metadata.append_to_log = 1;
	ins_req.metadata.gc_request = 0;
	ins_req.metadata.recovery_request = 0;
	ins_req.metadata.special_split = 0;
	ins_req.metadata.key_format = KV_FORMAT;
	ins_req.metadata.tombstone = 0;
	ins_req.key_value_buf = in->kv_inplace;
	ins_req.metadata.reorganized_leaf_pos_INnode = NULL;
	/*For Tebis-parallax currently*/
	ins_req.metadata.segment_full_event = 0;
	ins_req.metadata.log_segment_addr = 0;
	ins_req.metadata.log_offset_full_event = 0;
	ins_req.metadata.segment_id = 0;
	ins_req.metadata.end_of_log = 0;
	ins_req.metadata.log_padding = 0;

	struct log_operation log_op;
	log_op.metadata = &ins_req.metadata;
	log_op.optype_tolog = insertOp;
	log_op.ins_req = &ins_req;

	char *log_location = append_key_value_to_log(&log_op);

	if (GET_KEY_SIZE(in->kv_inplace) >= PREFIX_SIZE)
		memcpy(out->kvsep.prefix, GET_KEY_OFFSET(in->kv_inplace), PREFIX_SIZE);
	else {
		memset(out->kvsep.prefix, 0x00, PREFIX_SIZE);
		memcpy(out->kvsep.prefix, GET_KEY_OFFSET(in->kv_inplace), GET_KEY_SIZE(in->kv_inplace));
	}
	out->kvsep.dev_offt = (uint64_t)log_location;
	out->kv_category = MEDIUM_INLOG;
	out->kv_type = KV_INLOG;
	out->kv_inlog = &out->kvsep;
	out->tombstone = 0;

	return 1;
}

static void comp_append_entry_to_leaf_node(struct comp_level_write_cursor *cursor, struct comp_parallax_key *kv)
{
	struct comp_parallax_key trans_medium;
	struct write_dynamic_leaf_args write_leaf_args;
	struct comp_parallax_key *curr_key = kv;
	uint64_t left_leaf_offt = 0;
	uint64_t right_leaf_offt = 0;
	uint32_t level_leaf_size = cursor->handle->db_desc->levels[cursor->level_id].leaf_size;
	uint32_t kv_size = 0;
	uint8_t append_to_medium_log = 0;

	if (comp_append_medium_L1(cursor, kv, &trans_medium)) {
		curr_key = &trans_medium;
		append_to_medium_log = 1;
	}

	write_leaf_args.level_medium_inplace = cursor->handle->db_desc->level_medium_inplace;
	switch (curr_key->kv_type) {
	case KV_INPLACE:
		kv_size = sizeof(uint32_t) + sizeof(uint32_t); // key_size | value_size
		kv_size += GET_KEY_SIZE(curr_key->kv_inplace) + GET_VALUE_SIZE(curr_key->kv_inplace); // key | value
		write_leaf_args.kv_dev_offt = 0;
		write_leaf_args.key_value_size = kv_size;
		write_leaf_args.level_id = cursor->level_id;
		write_leaf_args.kv_format = KV_FORMAT;
		write_leaf_args.cat = curr_key->kv_category;
		write_leaf_args.key_value_buf = curr_key->kv_inplace;
		write_leaf_args.tombstone = curr_key->tombstone;
		//log_info("Appending key in_place %u:%s", write_leaf_args.key_value_size,
		//	 write_leaf_args.key_value_buf + sizeof(uint32_t));
		break;

	case KV_INLOG:
		kv_size = sizeof(struct bt_leaf_entry);
		write_leaf_args.kv_dev_offt = curr_key->kv_inlog->dev_offt;
		write_leaf_args.key_value_buf = (char *)curr_key->kv_inlog;
		write_leaf_args.key_value_size = kv_size;
		write_leaf_args.level_id = cursor->level_id;
		write_leaf_args.kv_format = KV_PREFIX;
		write_leaf_args.cat = curr_key->kv_category;
		write_leaf_args.tombstone = curr_key->tombstone;
		break;
	default:
		log_fatal("Unknown key_type (IN_PLACE,IN_LOG) instead got %u", curr_key->kv_type);
		BUG_ON();
	}

	if (write_leaf_args.cat == MEDIUM_INLOG &&
	    write_leaf_args.level_id == cursor->handle->db_desc->level_medium_inplace) {
		write_leaf_args.key_value_buf = fetch_kv_from_LRU(&write_leaf_args, cursor);
		assert(GET_KEY_SIZE(write_leaf_args.key_value_buf) <= MAX_KEY_SIZE);
		write_leaf_args.cat = MEDIUM_INPLACE;

		kv_size = sizeof(uint32_t) + sizeof(uint32_t); // key_size | value_size
		kv_size += GET_KEY_SIZE(write_leaf_args.key_value_buf) +
			   GET_VALUE_SIZE(write_leaf_args.key_value_buf); // key | value
		write_leaf_args.key_value_size = kv_size;
		curr_key->kv_type = KV_INPLACE;
		curr_key->kv_category = MEDIUM_INPLACE;
		curr_key->kv_inplace = write_leaf_args.key_value_buf;
		write_leaf_args.kv_format = KV_FORMAT;
#if MEASURE_MEDIUM_INPLACE
		__sync_fetch_and_add(&cursor->handle->db_desc->count_medium_inplace, 1);
#endif
	}

	struct split_level_leaf split_metadata = { .leaf = cursor->last_leaf,
						   .leaf_size = level_leaf_size,
						   .kv_size = kv_size,
						   .level_id = cursor->level_id,
						   .key_type = curr_key->kv_type,
						   .cat = curr_key->kv_category,
						   .level_medium_inplace =
							   cursor->handle->db_desc->level_medium_inplace };

	int new_leaf = 0;
	if (is_dynamic_leaf_full(split_metadata)) {
		// log_info("Time for a split!");
		/*keep current aka left leaf offt*/
		uint32_t offt_l = comp_calc_offt_in_seg(cursor->segment_buf[0], (char *)cursor->last_leaf);
		left_leaf_offt = cursor->last_segment_btree_level_offt[0] + offt_l;
		comp_get_space(cursor, 0, leafNode);
		/*last leaf updated*/
		uint32_t offt_r = comp_calc_offt_in_seg(cursor->segment_buf[0], (char *)cursor->last_leaf);
		right_leaf_offt = cursor->last_segment_btree_level_offt[0] + offt_r;
		new_leaf = 1;
	}

	write_leaf_args.leaf = cursor->last_leaf;
	write_leaf_args.dest = get_leaf_log_offset(cursor->last_leaf, level_leaf_size);
	write_leaf_args.middle = cursor->last_leaf->header.num_entries;

	write_data_in_dynamic_leaf(&write_leaf_args);
	// just append and leave
	++cursor->last_leaf->header.num_entries;
#if ENABLE_BLOOM_FILTERS
// TODO XXX
#endif
	// TODO SIZE
	cursor->handle->db_desc->levels[cursor->level_id].level_size[1] += write_leaf_args.key_value_size;

	if (new_leaf) {
		// log_info("keys are %llu for level %u",
		// c->handle->db_desc->levels[c->level_id].level_size[1],
		//	 c->level_id);

		// constructing the pivot key out of the keys, pivot key follows different format than KV_PREFIX/KV_FORMAT
		// first retrieve the kv_formated kv
		char *kv_formated_kv = kv->kv_inplace;
		if (!append_to_medium_log) {
			switch (write_leaf_args.kv_format) {
			case KV_FORMAT:
				kv_formated_kv = write_leaf_args.key_value_buf;
				break;
			case KV_PREFIX:
				if (cursor->level_id == 1 && curr_key->kv_category == MEDIUM_INPLACE)
					kv_formated_kv = curr_key->kv_inplace;
				else {
					// do a page fault to find the pivot
					kv_formated_kv = (char *)curr_key->kv_inlog->dev_offt;
				}
				break;
			default:
				BUG_ON();
			}
		}
		struct pivot_key new_pivot;
		new_pivot.size = GET_KEY_SIZE(kv_formated_kv);
		memcpy(new_pivot.data, GET_KEY_OFFSET(kv_formated_kv), new_pivot.size);

		comp_append_pivot_to_index(1, cursor, left_leaf_offt, &new_pivot, right_leaf_offt);
	}
}

struct compaction_request {
	db_descriptor *db_desc;
	volume_descriptor *volume_desc;
	par_db_options *db_options;
	uint64_t l0_start;
	uint64_t l0_end;
	uint8_t src_level;
	uint8_t src_tree;
	uint8_t dst_level;
	uint8_t dst_tree;
};

void mark_segment_space(db_handle *handle, struct dups_list *list, uint8_t level_id, uint8_t tree_id)
{
	struct dups_node *list_iter;
	struct dups_list *calculate_diffs;
	struct large_log_segment_gc_entry *temp_segment_entry;
	uint64_t segment_dev_offt;
	calculate_diffs = init_dups_list();

	MUTEX_LOCK(&handle->db_desc->segment_ht_lock);

	for (list_iter = list->head; list_iter; list_iter = list_iter->next) {
		segment_dev_offt = ABSOLUTE_ADDRESS(list_iter->dev_offt);

		struct large_log_segment_gc_entry *search_segment;
		HASH_FIND(hh, handle->db_desc->segment_ht, &segment_dev_offt, sizeof(segment_dev_offt), search_segment);

		assert(list_iter->kv_size > 0);
		if (search_segment) {
			// If the segment is already in the hash table just increase the garbage bytes.
			search_segment->garbage_bytes += list_iter->kv_size;
			assert(search_segment->garbage_bytes < SEGMENT_SIZE);
		} else {
			// This is the first time we detect garbage bytes in this segment,
			// allocate a node and insert it in the hash table.
			temp_segment_entry = calloc(1, sizeof(struct large_log_segment_gc_entry));
			temp_segment_entry->segment_dev_offt = segment_dev_offt;
			temp_segment_entry->garbage_bytes = list_iter->kv_size;
			temp_segment_entry->segment_moved = 0;
			HASH_ADD(hh, handle->db_desc->segment_ht, segment_dev_offt,
				 sizeof(temp_segment_entry->segment_dev_offt), temp_segment_entry);
		}

		struct dups_node *node = find_element(calculate_diffs, segment_dev_offt);

		if (node)
			node->kv_size += list_iter->kv_size;
		else
			append_node(calculate_diffs, segment_dev_offt, list_iter->kv_size);
	}

	MUTEX_UNLOCK(&handle->db_desc->segment_ht_lock);

	for (struct dups_node *persist_blob_metadata = calculate_diffs->head; persist_blob_metadata;
	     persist_blob_metadata = persist_blob_metadata->next) {
		uint64_t txn_id = handle->db_desc->levels[level_id].allocation_txn_id[tree_id];
		struct rul_log_entry entry = { .dev_offt = persist_blob_metadata->dev_offt,
					       .txn_id = txn_id,
					       .op_type = BLOB_GARBAGE_BYTES,
					       .blob_garbage_bytes = persist_blob_metadata->kv_size };
		rul_add_entry_in_txn_buf(handle->db_desc, &entry);
	}
}

static void *compaction(void *_comp_req);

void *compaction_daemon(void *args)
{
	struct db_handle *handle = (struct db_handle *)args;
	struct db_descriptor *db_desc = handle->db_desc;
	struct compaction_request *comp_req = NULL;
	pthread_setname_np(pthread_self(), "compactiond");

	int next_L0_tree_to_compact = 0;
	while (1) {
		/*special care for Level 0 to 1*/
		sem_wait(&db_desc->compaction_daemon_interrupts);
		if (db_desc->db_state == DB_TERMINATE_COMPACTION_DAEMON) {
			log_warn("Compaction daemon instructed to exit because DB %s is closing, "
				 "Bye bye!...",
				 db_desc->db_superblock->db_name);
			db_desc->db_state = DB_IS_CLOSING;
			return NULL;
		}
		struct level_descriptor *level_0 = &handle->db_desc->levels[0];
		struct level_descriptor *src_level = &handle->db_desc->levels[1];

		int L0_tree = next_L0_tree_to_compact;
		// is level-0 full and not already compacting?
		if (level_0->tree_status[L0_tree] == NO_COMPACTION &&
		    level_0->level_size[L0_tree] >= level_0->max_level_size) {
			// Can I issue a compaction to L1?
			int L1_tree = 0;
			if (src_level->tree_status[L1_tree] == NO_COMPACTION &&
			    src_level->level_size[L1_tree] < src_level->max_level_size) {
				/*mark them as compacting L0*/
				level_0->tree_status[L0_tree] = COMPACTION_IN_PROGRESS;
				/*mark them as compacting L1*/
				src_level->tree_status[L1_tree] = COMPACTION_IN_PROGRESS;

				/*start a compaction*/
				comp_req = (struct compaction_request *)calloc(1, sizeof(struct compaction_request));
				assert(comp_req);
				comp_req->db_desc = handle->db_desc;
				comp_req->volume_desc = handle->volume_desc;
				comp_req->db_options = &handle->db_options;
				comp_req->src_level = 0;
				comp_req->src_tree = L0_tree;
				comp_req->dst_level = 1;
				comp_req->dst_tree = 1;
				if (++next_L0_tree_to_compact >= NUM_TREES_PER_LEVEL)
					next_L0_tree_to_compact = 0;
			}
		}
		/*can I set a different active tree for L0*/
		int active_tree = db_desc->levels[0].active_tree;
		if (db_desc->levels[0].tree_status[active_tree] == COMPACTION_IN_PROGRESS) {
			int next_active_tree = active_tree != (NUM_TREES_PER_LEVEL - 1) ? active_tree + 1 : 0;
			if (db_desc->levels[0].tree_status[next_active_tree] == NO_COMPACTION) {
				/*Acquire guard lock and wait writers to finish*/
				if (RWLOCK_WRLOCK(&db_desc->levels[0].guard_of_level.rx_lock)) {
					log_fatal("Failed to acquire guard lock");
					BUG_ON();
				}
				spin_loop(&(db_desc->levels[0].active_operations), 0);
				/*fill L0 recovery log  info*/
				db_desc->small_log_start_segment_dev_offt = db_desc->small_log.tail_dev_offt;
				db_desc->small_log_start_offt_in_segment = db_desc->small_log.size % SEGMENT_SIZE;

				/*fill big log recovery  info*/
				db_desc->big_log_start_segment_dev_offt = db_desc->big_log.tail_dev_offt;
				db_desc->big_log_start_offt_in_segment = db_desc->big_log.size % SEGMENT_SIZE;
				/*done now atomically change active tree*/

				db_desc->levels[0].active_tree = next_active_tree;
				db_desc->levels[0].scanner_epoch += 1;
				db_desc->levels[0].epoch[active_tree] = db_desc->levels[0].scanner_epoch;
				log_info("Next active tree %u for L0 of DB: %s", next_active_tree,
					 db_desc->db_superblock->db_name);
				/*Acquire a new transaction id for the next_active_tree*/
				db_desc->levels[0].allocation_txn_id[next_active_tree] = rul_start_txn(db_desc);
				/*Release guard lock*/
				if (RWLOCK_UNLOCK(&db_desc->levels[0].guard_of_level.rx_lock)) {
					log_fatal("Failed to acquire guard lock");
					BUG_ON();
				}

				MUTEX_LOCK(&db_desc->client_barrier_lock);
				if (pthread_cond_broadcast(&db_desc->client_barrier) != 0) {
					log_fatal("Failed to wake up stopped clients");
					BUG_ON();
				}
				MUTEX_UNLOCK(&db_desc->client_barrier_lock);
			}
		}

		if (comp_req) {
			/*Start a compaction from L0 to L1. Flush L0 prior to compaction from L0 to L1*/
			log_info("Flushing L0 for region:%s tree:[0][%u]", db_desc->db_superblock->db_name,
				 comp_req->src_tree);
			pr_flush_L0(db_desc, comp_req->src_tree);
			db_desc->levels[1].allocation_txn_id[1] = rul_start_txn(db_desc);
			comp_req->dst_tree = 1;
			assert(db_desc->levels[0].root_w[comp_req->src_tree] != NULL ||
			       db_desc->levels[0].root_r[comp_req->src_tree] != NULL);
			if (pthread_create(&db_desc->levels[0].compaction_thread[comp_req->src_tree], NULL, compaction,
					   comp_req) != 0) {
				log_fatal("Failed to start compaction");
				BUG_ON();
			}
			comp_req = NULL;
		}

		// rest of levels
		for (int level_id = 1; level_id < MAX_LEVELS - 1; ++level_id) {
			src_level = &db_desc->levels[level_id];
			struct level_descriptor *dst_level = &db_desc->levels[level_id + 1];
			uint8_t tree_1 = 0;

			if (src_level->tree_status[tree_1] == NO_COMPACTION &&
			    src_level->level_size[tree_1] >= src_level->max_level_size) {
				uint8_t tree_2 = 0;

				if (dst_level->tree_status[tree_2] == NO_COMPACTION &&
				    dst_level->level_size[tree_2] < dst_level->max_level_size) {
					src_level->tree_status[tree_1] = COMPACTION_IN_PROGRESS;
					dst_level->tree_status[tree_2] = COMPACTION_IN_PROGRESS;
					/*start a compaction*/
					struct compaction_request *comp_req_p = (struct compaction_request *)calloc(
						1, sizeof(struct compaction_request));
					assert(comp_req_p);
					comp_req_p->db_desc = db_desc;
					comp_req_p->volume_desc = handle->volume_desc;
					comp_req_p->db_options = &handle->db_options;
					comp_req_p->src_level = level_id;
					comp_req_p->src_tree = tree_1;
					comp_req_p->dst_level = level_id + 1;

					comp_req_p->dst_tree = 1;

					/*Acquire a txn_id for the allocations of the compaction*/
					db_desc->levels[comp_req_p->dst_level].allocation_txn_id[comp_req_p->dst_tree] =
						rul_start_txn(db_desc);

					assert(db_desc->levels[level_id].root_w[0] != NULL ||
					       db_desc->levels[level_id].root_r[0] != NULL);
					if (pthread_create(&db_desc->levels[comp_req_p->dst_level]
								    .compaction_thread[comp_req_p->dst_tree],
							   NULL, compaction, comp_req_p) != 0) {
						log_fatal("Failed to start compaction");
						BUG_ON();
					}
				}
			}
		}
	}
}

static void swap_levels(struct level_descriptor *src, struct level_descriptor *dst, int src_active_tree,
			int dst_active_tree)
{
	dst->first_segment[dst_active_tree] = src->first_segment[src_active_tree];
	src->first_segment[src_active_tree] = NULL;

	dst->last_segment[dst_active_tree] = src->last_segment[src_active_tree];
	src->last_segment[src_active_tree] = NULL;

	dst->offset[dst_active_tree] = src->offset[src_active_tree];
	src->offset[src_active_tree] = 0;

	dst->level_size[dst_active_tree] = src->level_size[src_active_tree];
	src->level_size[src_active_tree] = 0;

	while (!__sync_bool_compare_and_swap(&dst->root_w[dst_active_tree], dst->root_w[dst_active_tree],
					     src->root_w[src_active_tree])) {
	}
	// dst->root_w[dst_active_tree] = src->root_w[src_active_tree];
	src->root_w[src_active_tree] = NULL;

	while (!__sync_bool_compare_and_swap(&dst->root_r[dst_active_tree], dst->root_r[dst_active_tree],
					     src->root_r[src_active_tree])) {
	}
	// dst->root_r[dst_active_tree] = src->root_r[src_active_tree];
	src->root_r[src_active_tree] = NULL;

	return;
}

static void comp_fill_heap_node(struct compaction_request *comp_req, struct comp_level_read_cursor *cur,
				struct sh_heap_node *nd)
{
	nd->level_id = cur->level_id;
	nd->active_tree = comp_req->src_tree;
	nd->cat = cur->category;
	nd->tombstone = cur->cursor_key.tombstone;
	switch (nd->cat) {
	case SMALL_INPLACE:
	case MEDIUM_INPLACE:
		nd->type = KV_FORMAT;
		nd->KV = cur->cursor_key.kv_inplace;
		nd->kv_size = sizeof(uint32_t) + sizeof(uint32_t); // key_size | value_size
		nd->kv_size += GET_KEY_SIZE(nd->KV) + GET_VALUE_SIZE(nd->KV); // key | value
		break;
	case BIG_INLOG:
	case MEDIUM_INLOG:
		nd->type = KV_PREFIX;
		// log_info("Prefix %.12s dev_offt %llu", cur->cursor_key.in_log->prefix,
		//	 cur->cursor_key.in_log->device_offt);
		nd->KV = (char *)cur->cursor_key.kv_inlog;
		nd->kv_size = sizeof(struct bt_leaf_entry);
		break;
	default:
		log_fatal("UNKNOWN_LOG_CATEGORY");
		BUG_ON();
	}
}

static void comp_fill_parallax_key(struct sh_heap_node *nd, struct comp_parallax_key *curr_key)
{
	curr_key->kv_category = nd->cat;
	curr_key->tombstone = nd->tombstone;
	assert(nd->KV);
	switch (nd->cat) {
	case SMALL_INPLACE:
	case MEDIUM_INPLACE:
		curr_key->kv_inplace = nd->KV;
		curr_key->kv_type = KV_INPLACE;
		break;
	case BIG_INLOG:
	case MEDIUM_INLOG:
		curr_key->kv_inlog = (struct bt_leaf_entry *)nd->KV;
		curr_key->kv_type = KV_INLOG;
		break;
	default:
		log_info("Unhandle/Unknown category");
		BUG_ON();
	}
}

static void print_heap_node_key(struct sh_heap_node *nd)
{
	switch (nd->cat) {
	case SMALL_INPLACE:
	case MEDIUM_INPLACE:
		log_debug("In place Key is %u:%s", *(uint32_t *)nd->KV, (char *)nd->KV + sizeof(uint32_t));
		break;
	case BIG_INLOG:
	case MEDIUM_INLOG:;
		char *full_key = (char *)((struct bt_leaf_entry *)nd->KV)->dev_offt;

		log_debug("In log Key prefix is %.*s full key size: %u  full key data %.*s", PREFIX_SIZE,
			  (char *)nd->KV, KEY_SIZE(full_key), KEY_SIZE(full_key), full_key + sizeof(uint32_t));
		break;
	default:
		log_fatal("Unhandle/Unknown category");
		BUG_ON();
	}
}

static void choose_compaction_roots(struct db_handle *handle, struct compaction_request *comp_req,
				    struct compaction_roots *comp_roots)
{
	if (handle->db_desc->levels[comp_req->src_level].root_w[comp_req->src_tree] != NULL)
		comp_roots->src_root = handle->db_desc->levels[comp_req->src_level].root_w[comp_req->src_tree];
	else if (handle->db_desc->levels[comp_req->src_level].root_r[comp_req->src_tree] != NULL)
		comp_roots->src_root = handle->db_desc->levels[comp_req->src_level].root_r[comp_req->src_tree];
	else {
		log_fatal("NULL src root for compaction from level's tree [%u][%u] to "
			  "level's tree[%u][%u] for db %s",
			  comp_req->src_level, comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree,
			  handle->db_desc->db_superblock->db_name);
		BUG_ON();
	}

	if (handle->db_desc->levels[comp_req->dst_level].root_w[0] != NULL)
		comp_roots->dst_root = handle->db_desc->levels[comp_req->dst_level].root_w[0];
	else if (handle->db_desc->levels[comp_req->dst_level].root_r[0] != NULL)
		comp_roots->dst_root = handle->db_desc->levels[comp_req->dst_level].root_r[0];
	else {
		comp_roots->dst_root = NULL;
	}
}

static void lock_to_update_levels_after_compaction(struct compaction_request *comp_req)
{
	if (RWLOCK_WRLOCK(&(comp_req->db_desc->levels[comp_req->src_level].guard_of_level.rx_lock))) {
		log_fatal("Failed to acquire guard lock");
		BUG_ON();
	}

	if (RWLOCK_WRLOCK(&(comp_req->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock))) {
		log_fatal("Failed to acquire guard lock");
		BUG_ON();
	}
	spin_loop(&comp_req->db_desc->levels[comp_req->src_level].active_operations, 0);
	spin_loop(&comp_req->db_desc->levels[comp_req->dst_level].active_operations, 0);
}

static void unlock_to_update_levels_after_compaction(struct compaction_request *comp_req)
{
	if (RWLOCK_UNLOCK(&(comp_req->db_desc->levels[comp_req->src_level].guard_of_level.rx_lock))) {
		log_fatal("Failed to acquire guard lock");
		BUG_ON();
	}

	if (RWLOCK_UNLOCK(&(comp_req->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock))) {
		log_fatal("Failed to acquire guard lock");
		BUG_ON();
	}
}

static void compact_level_direct_IO(struct db_handle *handle, struct compaction_request *comp_req)
{
	struct compaction_roots comp_roots = { .src_root = NULL, .dst_root = NULL };

	choose_compaction_roots(handle, comp_req, &comp_roots);
	/*used for L0 only as src*/
	struct level_scanner *level_src = NULL;
	struct comp_level_read_cursor *l_src = NULL;
	struct comp_level_read_cursor *l_dst = NULL;
	struct comp_level_write_cursor *merged_level = NULL;

	if (comp_req->src_level == 0) {
		RWLOCK_WRLOCK(&handle->db_desc->levels[0].guard_of_level.rx_lock);
		spin_loop(&handle->db_desc->levels[0].active_operations, 0);
		pr_flush_log_tail(comp_req->db_desc, &comp_req->db_desc->big_log);
#if MEDIUM_LOG_UNSORTED
		pr_flush_log_tail(comp_req->db_desc, &comp_req->db_desc->medium_log);
#endif
		RWLOCK_UNLOCK(&handle->db_desc->levels[0].guard_of_level.rx_lock);

		log_debug("Initializing L0 scanner");
		level_src = _init_compaction_buffer_scanner(handle, comp_req->src_level, comp_roots.src_root, NULL);
	} else {
		if (posix_memalign((void **)&l_src, ALIGNMENT, sizeof(struct comp_level_read_cursor)) != 0) {
			log_fatal("Posix memalign failed");
			perror("Reason: ");
			BUG_ON();
		}
		comp_init_read_cursor(l_src, handle, comp_req->src_level, 0, FD);
		comp_get_next_key(l_src);
		assert(!l_src->end_of_level);
	}

	if (comp_roots.dst_root) {
		if (posix_memalign((void **)&l_dst, ALIGNMENT, sizeof(struct comp_level_read_cursor)) != 0) {
			log_fatal("Posix memalign failed");
			perror("Reason: ");
			BUG_ON();
		}
		comp_init_read_cursor(l_dst, handle, comp_req->dst_level, 0, FD);
		comp_get_next_key(l_dst);
		assert(!l_dst->end_of_level);
	}

	log_debug("Initializing write cursor for level %u", comp_req->dst_level);
	if (posix_memalign((void **)&merged_level, ALIGNMENT, sizeof(struct comp_level_write_cursor)) != 0) {
		log_fatal("Posix memalign failed");
		perror("Reason: ");
		BUG_ON();
	}

	assert(0 == handle->db_desc->levels[comp_req->dst_level].offset[comp_req->dst_tree]);
	comp_init_write_cursor(merged_level, handle, comp_req->dst_level, FD);

	//initialize LRU cache for storing chunks of segments when medium log goes in place
	if (merged_level->level_id == handle->db_desc->level_medium_inplace)
		merged_level->medium_log_LRU_cache = init_LRU(handle);

	log_debug("Src [%u][%u] size = %lu", comp_req->src_level, comp_req->src_tree,
		  handle->db_desc->levels[comp_req->src_level].level_size[comp_req->src_tree]);
	if (comp_roots.dst_root)
		log_debug("Dst [%u][%u] size = %lu", comp_req->dst_level, 0,
			  handle->db_desc->levels[comp_req->dst_level].level_size[0]);
	else {
		log_debug("Empty dst [%u][%u]", comp_req->dst_level,
			  0); // TODO: (@geostyl) do we really need this 0 as second argument?
	}
	// initialize and fill min_heap properly
	struct sh_heap *m_heap = sh_alloc_heap();
	sh_init_heap(m_heap, comp_req->src_level, MIN_HEAP);
	struct sh_heap_node nd_src = { .KV = NULL, .level_id = 0, .active_tree = 0, .duplicate = 0, .type = KV_PREFIX };
	struct sh_heap_node nd_dst = { .KV = NULL, .level_id = 0, .active_tree = 0, .duplicate = 0, .type = KV_PREFIX };
	struct sh_heap_node nd_min = { .KV = NULL, .level_id = 0, .active_tree = 0, .duplicate = 0, .type = KV_PREFIX };
	// init Li cursor
	if (level_src) {
		nd_src.KV = level_src->keyValue;
		nd_src.level_id = comp_req->src_level;
		nd_src.type = level_src->kv_format;
		nd_src.cat = level_src->cat;
		nd_src.kv_size = level_src->kv_size;
		nd_src.tombstone = level_src->tombstone;
		nd_src.active_tree = comp_req->src_tree;
		log_debug("Initializing heap from SRC L0");
	} else {
		log_debug("Initializing heap from SRC read cursor level %u with key:", comp_req->src_level);
		comp_fill_heap_node(comp_req, l_src, &nd_src);
	}

	nd_src.db_desc = comp_req->db_desc;
	sh_insert_heap_node(m_heap, &nd_src);
	// init Li+1 cursor (if any)
	if (l_dst) {
		comp_fill_heap_node(comp_req, l_dst, &nd_dst);
		// log_debug("Initializing heap from DST read cursor level %u", comp_req->dst_level);
		print_heap_node_key(&nd_dst);
		nd_dst.db_desc = comp_req->db_desc;
		sh_insert_heap_node(m_heap, &nd_dst);
	}

	while (1) {
		handle->db_desc->dirty = 0x01;
		// This is to synchronize compactions with flush
		RWLOCK_RDLOCK(&handle->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock);
		if (!sh_remove_top(m_heap, &nd_min)) {
			RWLOCK_UNLOCK(&handle->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock);
			break;
		}

		if (!nd_min.duplicate) {
			struct comp_parallax_key key = { 0 };
			comp_fill_parallax_key(&nd_min, &key);
			comp_append_entry_to_leaf_node(merged_level, &key);
		}

		/*refill from the appropriate level*/
		if (nd_min.level_id == comp_req->src_level) {
			if (nd_min.level_id == 0) {
				if (level_scanner_get_next(level_src) != END_OF_DATABASE) {
					// log_info("Refilling from L0");
					nd_min.KV = level_src->keyValue;
					nd_min.level_id = comp_req->src_level;
					nd_min.type = level_src->kv_format;
					nd_min.cat = level_src->cat;
					nd_min.tombstone = level_src->tombstone;
					nd_min.kv_size = level_src->kv_size;
					nd_min.active_tree = comp_req->src_tree;
					nd_min.db_desc = comp_req->db_desc;
					sh_insert_heap_node(m_heap, &nd_min);
				}

			} else {
				comp_get_next_key(l_src);
				if (!l_src->end_of_level) {
					comp_fill_heap_node(comp_req, l_src, &nd_min);
					// log_info("Refilling from SRC level read cursor");
					nd_min.db_desc = comp_req->db_desc;
					sh_insert_heap_node(m_heap, &nd_min);
				}
			}
		} else if (l_dst) {
			comp_get_next_key(l_dst);
			if (!l_dst->end_of_level) {
				comp_fill_heap_node(comp_req, l_dst, &nd_min);
				// log_info("Refilling from DST level read cursor key is %s",
				// nd_min.KV + 4);
				nd_min.db_desc = comp_req->db_desc;
				sh_insert_heap_node(m_heap, &nd_min);
			}
		}

		RWLOCK_UNLOCK(&handle->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock);
	}

	if (level_src)
		close_compaction_buffer_scanner(level_src);
	else
		free(l_src);

	if (comp_roots.dst_root)
		free(l_dst);

	mark_segment_space(handle, m_heap->dups, comp_req->dst_level, 1);
	comp_close_write_cursor(merged_level);

	sh_destroy_heap(m_heap);
	merged_level->handle->db_desc->levels[comp_req->dst_level].root_w[1] =
		(struct node_header *)REAL_ADDRESS(merged_level->root_offt);
	assert(merged_level->handle->db_desc->levels[comp_req->dst_level].root_w[1]->type == rootNode);

	if (merged_level->level_id == handle->db_desc->level_medium_inplace) {
		comp_medium_log_set_max_segment_id(merged_level);
		destroy_LRU(merged_level->medium_log_LRU_cache);
	}
	free(merged_level);

	/***************************************************************/
	struct level_descriptor *ld = &comp_req->db_desc->levels[comp_req->dst_level];
	struct db_handle hd = { .db_desc = comp_req->db_desc, .volume_desc = comp_req->volume_desc };

	lock_to_update_levels_after_compaction(comp_req);

	uint64_t space_freed = 0;
	/*Free L_(i+1)*/
	if (l_dst) {
		uint64_t txn_id = comp_req->db_desc->levels[comp_req->dst_level].allocation_txn_id[comp_req->dst_tree];
		/*free dst (L_i+1) level*/
		space_freed = seg_free_level(comp_req->db_desc, txn_id, comp_req->dst_level, 0);

		log_debug("Freed space %lu MB from db:%s destination level %u", space_freed / (1024 * 1024L),
			  comp_req->db_desc->db_superblock->db_name, comp_req->dst_level);
	}
	/*Free and zero L_i*/
	uint64_t txn_id = comp_req->db_desc->levels[comp_req->dst_level].allocation_txn_id[comp_req->dst_tree];
	space_freed = seg_free_level(hd.db_desc, txn_id, comp_req->src_level, comp_req->src_tree);
	log_debug("Freed space %lu MB from db:%s source level %u", space_freed / (1024 * 1024L),
		  comp_req->db_desc->db_superblock->db_name, comp_req->src_level);
	seg_zero_level(hd.db_desc, comp_req->src_level, comp_req->src_tree);

#if ENABLE_BLOOM_FILTERS
	if (dst_root) {
		log_debug("Freeing previous bloom filter for dst level %u", comp_req->dst_level);
		bloom_free(&handle.db_desc->levels[comp_req->src_level].bloom_filter[0]);
	}
	ld->bloom_filter[0] = ld->bloom_filter[1];
	memset(&ld->bloom_filter[1], 0x00, sizeof(struct bloom));
#endif

#if !MEDIUM_LOG_UNSORTED
	if (comp_req->dst_level == 1) {
		log_info("Flushing medium log");
		pr_flush_log_tail(comp_req->db_desc, &comp_req->db_desc->medium_log);
	}
#endif
	/*Finally persist compaction */
	pr_flush_compaction(comp_req->db_desc, comp_req->dst_level, comp_req->dst_tree);
	log_debug("Flushed compaction[%u][%u] successfully", comp_req->dst_level, comp_req->dst_tree);
	/*set L'_(i+1) as L_(i+1)*/
	ld->first_segment[0] = ld->first_segment[1];
	ld->first_segment[1] = NULL;
	ld->last_segment[0] = ld->last_segment[1];
	ld->last_segment[1] = NULL;
	ld->offset[0] = ld->offset[1];
	ld->offset[1] = 0;

	if (ld->root_w[1] != NULL)
		ld->root_r[0] = ld->root_w[1];
	else if (ld->root_r[1] != NULL)
		ld->root_r[0] = ld->root_r[1];
	else {
		log_fatal("Where is the root?");
		BUG_ON();
	}

	ld->root_w[0] = NULL;
	ld->level_size[0] = ld->level_size[1];
	ld->level_size[1] = 0;
	ld->root_w[1] = NULL;
	ld->root_r[1] = NULL;

	unlock_to_update_levels_after_compaction(comp_req);
}

static void compact_with_empty_destination_level(struct compaction_request *comp_req)
{
	log_debug("Empty level %d time for an optimization :-)", comp_req->dst_level);

	lock_to_update_levels_after_compaction(comp_req);

	struct level_descriptor *leveld_src = &comp_req->db_desc->levels[comp_req->src_level];
	struct level_descriptor *leveld_dst = &comp_req->db_desc->levels[comp_req->dst_level];

	swap_levels(leveld_src, leveld_dst, comp_req->src_tree, 1);

	pr_flush_compaction(comp_req->db_desc, comp_req->dst_level, comp_req->dst_tree);
	swap_levels(leveld_dst, leveld_dst, 1, 0);
	log_debug("Flushed compaction (Swap levels) successfully from src[%u][%u] to dst[%u][%u]", comp_req->src_level,
		  comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree);

#if ENABLE_BLOOM_FILTERS
	log_info("Swapping also bloom filter");
	leveld_dst->bloom_filter[0] = leveld_src->bloom_filter[0];
	memset(&leveld_src->bloom_filter[0], 0x00, sizeof(struct bloom));
#endif
	unlock_to_update_levels_after_compaction(comp_req);

	log_debug("Swapped levels %d to %d successfully", comp_req->src_level, comp_req->dst_level);
	log_debug("After swapping src tree[%d][%d] size is %lu", comp_req->src_level, 0, leveld_src->level_size[0]);
	log_debug("After swapping dst tree[%d][%d] size is %lu", comp_req->dst_level, 0, leveld_dst->level_size[0]);
	assert(leveld_dst->first_segment != NULL);
}

void *compaction(void *_comp_req)
{
	db_handle handle;
	struct compaction_request *comp_req = (struct compaction_request *)_comp_req;
	db_descriptor *db_desc = comp_req->db_desc;
	pthread_setname_np(pthread_self(), "comp_thread");
	log_info("starting compaction from level's tree [%u][%u] to level's tree[%u][%u]", comp_req->src_level,
		 comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree);
	/*Initialize a scan object*/
	handle.db_desc = comp_req->db_desc;
	handle.volume_desc = comp_req->volume_desc;
	memcpy(&handle.db_options, comp_req->db_options, sizeof(struct par_db_options));
	// optimization check if level below is empty
	struct node_header *dst_root = NULL;
	if (handle.db_desc->levels[comp_req->dst_level].root_w[0] != NULL)
		dst_root = handle.db_desc->levels[comp_req->dst_level].root_w[0];
	else if (handle.db_desc->levels[comp_req->dst_level].root_r[0] != NULL)
		dst_root = handle.db_desc->levels[comp_req->dst_level].root_r[0];
	else {
		dst_root = NULL;
	}

	if (comp_req->src_level == 0 || comp_req->dst_level == handle.db_desc->level_medium_inplace || dst_root)
		compact_level_direct_IO(&handle, comp_req);
	else
		compact_with_empty_destination_level(comp_req);

	log_debug("DONE Compaction from level's tree [%u][%u] to level's tree[%u][%u] "
		  "cleaning src level",
		  comp_req->src_level, comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree);

	db_desc->levels[comp_req->src_level].tree_status[comp_req->src_tree] = NO_COMPACTION;
	db_desc->levels[comp_req->dst_level].tree_status[0] = NO_COMPACTION;

	/*wake up clients*/
	if (comp_req->src_level == 0) {
		log_info("src level %d dst level %d src_tree %d dst_tree %d", comp_req->src_level, comp_req->dst_level,
			 comp_req->src_tree, comp_req->dst_tree);
		MUTEX_LOCK(&comp_req->db_desc->client_barrier_lock);
		if (pthread_cond_broadcast(&db_desc->client_barrier) != 0) {
			log_fatal("Failed to wake up stopped clients");
			BUG_ON();
		}
	}
	MUTEX_UNLOCK(&db_desc->client_barrier_lock);
	sem_post(&db_desc->compaction_daemon_interrupts);
	free(comp_req);
	return NULL;
}

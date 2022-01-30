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

#define _GNU_SOURCE /* See feature_test_macros(7) */

#include "../../utilities/dups_list.h"
#include "../allocator/device_structures.h"
#include "../allocator/log_structures.h"
#include "../allocator/redo_undo_log.h"
#include "../allocator/volume_manager.h"
#include "../scanner/min_max_heap.h"
#include "../scanner/scanner.h"
#include "btree.h"
#include "conf.h"
#include "dynamic_leaf.h"
#include "gc.h"
#include "medium_log_LRU_cache.h"
#include "segment_allocator.h"

#include <assert.h>
#include <log.h>
#include <pthread.h>
#include <semaphore.h>
#include <spin_loop.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uthash.h>

/*
 * Checks for pending compactions. It is responsible to check for dependencies
 * between two levels before triggering a compaction.
*/

struct comp_level_write_cursor {
	char segment_buf[MAX_HEIGHT][SEGMENT_SIZE];
	uint64_t segment_offt[MAX_HEIGHT];
	uint64_t dev_offt[MAX_HEIGHT];
	struct index_node *last_index[MAX_HEIGHT];
	struct bt_dynamic_leaf_node *last_leaf;
	struct chunk_LRU_cache *medium_log_LRU_cache;
	uint64_t root_offt;
	db_handle *handle;
	uint32_t level_id;
	uint32_t tree_height;
	int fd;
};

enum comp_level_read_cursor_state {
	COMP_CUR_INIT,
	COMP_CUR_FIND_LEAF,
	COMP_CUR_FETCH_NEXT_SEGMENT,
	COMP_CUR_DECODE_KV,
	COMP_CUR_CHECK_OFFT
};

struct comp_kv_prefix *prefix_2_comp_kv_prefix(struct prefix *p, enum log_category cat)
{
	struct comp_kv_prefix *c_prefix;
	switch (cat) {
	case SMALL_INPLACE:
	case MEDIUM_INPLACE:
		log_warn("Impossible conversion");
		return NULL;
	case MEDIUM_INLOG:
	case BIG_INLOG:
		c_prefix = (struct comp_kv_prefix *)p->prefix;
		break;
	default:
		log_fatal("Wrong category");
		exit(EXIT_FAILURE);
	}
	return c_prefix;
}

struct comp_parallax_key {
	union {
		struct bt_leaf_entry *kv_inlog;
		char *kv_inplace;
	};
	struct bt_leaf_entry kvsep;
	enum log_category kv_category;
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
	uint32_t curr_leaf_entry;
	int fd;
	enum log_category category;
	enum comp_level_read_cursor_state state;
	char end_of_level;
};

static void fetch_segment(struct comp_level_write_cursor *c, char *segment_buf, uint64_t log_chunk_dev_offt,
			  ssize_t size)
{
	off_t dev_offt = log_chunk_dev_offt;
	ssize_t bytes_to_read = 0;
	ssize_t bytes = 0;

	while (bytes_to_read < size) {
		bytes = pread(c->handle->db_desc->db_volume->vol_fd, &segment_buf[bytes_to_read], size - bytes_to_read,
			      dev_offt + bytes_to_read);
		if (bytes == -1) {
			log_fatal("Failed to read error code");
			perror("Error");
			assert(0);
			exit(EXIT_FAILURE);
		}
		bytes_to_read += bytes;
	}
	if (c->level_id == c->handle->db_desc->level_medium_inplace) {
		struct segment_header *segment = (struct segment_header *)segment_buf;
		struct level_descriptor *level_desc = &c->handle->db_desc->levels[c->level_id];

		if (!(log_chunk_dev_offt % SEGMENT_SIZE)) {
			if (segment->segment_id > level_desc->medium_in_place_max_segment_id) {
				level_desc->medium_in_place_max_segment_id = segment->segment_id;
				level_desc->medium_in_place_segment_dev_offt = dev_offt;
			}
		}
	}
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
			exit(EXIT_FAILURE);
		}
		fetch_segment(c, segment_chunk, segment_chunk_offt, LOG_CHUNK_SIZE + KB(4));
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
		exit(EXIT_FAILURE);
	}
	uint32_t ret = (end - start) % SEGMENT_SIZE;
	return ret;
}

struct compaction_roots {
	struct node_header *src_root;
	struct node_header *dst_root;
};

static void comp_write_segment(char *buffer, uint64_t dev_offt, uint32_t buf_offt, uint32_t size, int fd)
{
#if 0
  struct node_header *n = (struct node_header *)&buffer[buf_offt];
  switch (n->type) {
  case rootNode:
  case internalNode: {
    uint32_t decoded = buf_offt;
    while (decoded < SEGMENT_SIZE) {

      if (n->type == paddedSpace)
        break;
      assert(n->type == rootNode || n->type == internalNode);
      n = (struct node_header *)((uint64_t)n + INDEX_NODE_SIZE +
                                 KEY_BLOCK_SIZE);
      decoded += (INDEX_NODE_SIZE + KEY_BLOCK_SIZE);
    }
    break;
  }
  case leafNode:
  case leafRootNode: {
    int num_leaves = 0;
		int padded = 0;
    uint32_t decoded = buf_offt;
    while (decoded < SEGMENT_SIZE) {

      if (n->type == paddedSpace) {
        log_warn("Found padded space in leaf segment ok");
				padded = 1;
				break;
      }
      if (n->type != leafNode && n->type != leafRootNode) {
        log_fatal("Corruption expected leaf got %u decoded was %u", n->type,
                  decoded);
        assert(0);
      }
      ++num_leaves;
      n = (struct node_header *)((uint64_t)n + LEAF_NODE_SIZE);
      decoded += LEAF_NODE_SIZE;
    }
		if(padded)
			break;
    assert(num_leaves == 511);
    break;
  }
  case paddedSpace:
    break;
  default:
    assert(0);
  }
#endif
	ssize_t total_bytes_written = buf_offt;
	ssize_t bytes_written = 0;
	while (total_bytes_written < size) {
		bytes_written = pwrite(fd, &buffer[total_bytes_written], size - total_bytes_written,
				       dev_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to writed segment for leaf nodes reason follows");
			perror("Reason");
			exit(EXIT_FAILURE);
		}
		total_bytes_written += bytes_written;
	}
}

static void comp_init_dynamic_leaf(struct bt_dynamic_leaf_node *leaf)
{
	leaf->header.type = leafNode;
	leaf->header.num_entries = 0;
	leaf->header.fragmentation = 0;

	leaf->header.first_IN_log_header = NULL; /*unused field in leaves*/
	leaf->header.last_IN_log_header = NULL; /*unused field in leaves*/
	leaf->header.leaf_log_size = 0;
	leaf->header.height = 0;
}

static void comp_init_read_cursor(struct comp_level_read_cursor *c, db_handle *handle, uint32_t level_id,
				  uint32_t tree_id, int fd)
{
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
	uint32_t level_leaf_size = c->handle->db_desc->levels[c->level_id].leaf_size;
	if (c == NULL) {
		log_fatal("NULL cursor!");
		assert(0);
		exit(EXIT_FAILURE);
	}
	if (c->end_of_level)
		return;
	while (1) {
	fsm_entry:
		switch (c->state) {
		case COMP_CUR_CHECK_OFFT: {
			if (c->offset >= c->handle->db_desc->levels[c->level_id].offset[c->tree_id]) {
				log_info("Done read level %u", c->level_id);
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
					log_info("Done reading level %lu cursor offset %llu total offt %llu",
						 c->level_id, c->offset,
						 c->handle->db_desc->levels[c->level_id].offset[c->tree_id]);
					assert(c->offset == c->handle->db_desc->levels[c->level_id].offset[c->tree_id]);
					c->state = COMP_CUR_CHECK_OFFT;
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
			ssize_t bytes = 0;
			while (bytes_read < SEGMENT_SIZE) {
				bytes = pread(c->fd, &c->segment_buf[bytes_read], SEGMENT_SIZE - bytes_read,
					      dev_offt + bytes_read);
				if (-1 == bytes) {
					log_fatal("Failed to read error code");
					perror("Error");
					assert(0);
					exit(EXIT_FAILURE);
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
			} else {
				struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);

				c->category = slot_array[c->curr_leaf_entry].key_category;
				c->cursor_key.tombstone = slot_array[c->curr_leaf_entry].tombstone;
				char *kv_loc =
					get_kv_offset(leaf, level_leaf_size, slot_array[c->curr_leaf_entry].index);
				switch (c->category) {
				case SMALL_INPLACE:
				case MEDIUM_INPLACE: {
					// Real key in KV_FORMAT
					c->cursor_key.kv_inplace =
						fill_keybuf(kv_loc, slot_array[c->curr_leaf_entry].kv_loc);
					break;
				}
				case MEDIUM_INLOG:
				case BIG_INLOG: {
					// fill_prefix(&c->cursor_key.P, kv_loc,
					// slot_array[c->curr_leaf_entry].bitmap);
					// c->category);
					c->cursor_key.kv_inlog = (struct bt_leaf_entry *)kv_loc;
					c->cursor_key.kv_inlog->dev_offt =
						(uint64_t)REAL_ADDRESS(c->cursor_key.kv_inlog->dev_offt);
					// log_info("prefix is %.12s dev_offt %llu",
					// c->cursor_key.in_log->prefix,
					//	 c->cursor_key.in_log->device_offt);
					break;
				}
				default:
					log_fatal("Cannot handle this category");
					assert(0);
					exit(EXIT_FAILURE);
				}
				++c->curr_leaf_entry;
				return;
			}
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

			case keyBlockHeader:
				/*log_info("Found a keyblock header");*/
				c->offset += KEY_BLOCK_SIZE;
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
					  "was %llu total level offset %llu faulty segment offt: %llu",
					  c->level_id, type, c->offset,
					  c->handle->db_desc->levels[c->level_id].offset[0],
					  ABSOLUTE_ADDRESS(c->curr_segment));
				assert(0);
				exit(EXIT_FAILURE);
			}

			break;
		}
		default:
			log_fatal("Error state");
			assert(0);
			exit(EXIT_FAILURE);
		}
	}
}

static void comp_init_write_cursor(struct comp_level_write_cursor *c, struct db_handle *handle, int level_id, int fd)
{
	c->level_id = level_id;
	c->tree_height = 0;
	c->fd = fd;
	c->handle = handle;
	struct level_descriptor *level_desc = &c->handle->db_desc->levels[c->level_id];
	uint32_t level_leaf_size = level_desc->leaf_size;

	for (int i = 0; i < MAX_HEIGHT; ++i) {
		struct segment_header *device_segment =
			get_segment_for_lsm_level_IO(c->handle->db_desc, c->level_id, 1);
		memset(&c->segment_buf[0][0], 0x00, sizeof(struct segment_header));

		c->dev_offt[i] = ABSOLUTE_ADDRESS(device_segment);
		c->segment_offt[i] = sizeof(struct segment_header);
		if (i == 0) {
			c->last_index[0] = NULL;
			c->last_leaf =
				(struct bt_dynamic_leaf_node *)&c->segment_buf[0][c->segment_offt[0] % SEGMENT_SIZE];
			comp_init_dynamic_leaf(c->last_leaf);
			c->segment_offt[0] += level_leaf_size;
		} else {
			c->last_index[i] = (struct index_node *)&c->segment_buf[i][c->segment_offt[i] % SEGMENT_SIZE];

			/*initialization*/
			c->last_index[i]->header.type = internalNode;
			c->last_index[i]->header.height = i;
			c->last_index[i]->header.num_entries = 0;
			c->last_index[i]->header.fragmentation = 0;
			/*private key log for index nodes*/
			uint64_t index_log_dev_offt =
				c->dev_offt[i] + c->segment_offt[i] % SEGMENT_SIZE + INDEX_NODE_SIZE;

			IN_log_header *tmp = (IN_log_header *)&c->segment_buf[i][index_log_dev_offt % SEGMENT_SIZE];
			tmp->type = keyBlockHeader;
			tmp->next = NULL;
			c->last_index[i]->header.first_IN_log_header = (IN_log_header *)index_log_dev_offt;
			c->last_index[i]->header.last_IN_log_header = c->last_index[i]->header.first_IN_log_header;
			c->last_index[i]->header.key_log_size = sizeof(IN_log_header);
			c->segment_offt[i] += INDEX_NODE_SIZE + KEY_BLOCK_SIZE;
		}
	}
}

static void comp_close_write_cursor(struct comp_level_write_cursor *c)
{
	uint32_t level_leaf_size = c->handle->db_desc->levels[c->level_id].leaf_size;
	for (uint32_t i = 0; i < MAX_HEIGHT; ++i) {
		uint32_t *type;
		//log_info("i = %lu tree height: %lu", i, c->tree_height);
		if (i <= c->tree_height) {
			if (i == 0 && c->segment_offt[i] % SEGMENT_SIZE != 0) {
				type = (uint32_t *)((uint64_t)c->last_leaf + level_leaf_size);
				//log_info("Marking padded space for %u segment offt %llu", i, c->segment_offt[0]);
				*type = paddedSpace;
			} else if (i > 0 && c->segment_offt[i] % SEGMENT_SIZE != 0) {
				type = (uint32_t *)((uint64_t)(c->last_index[i]) + INDEX_NODE_SIZE + KEY_BLOCK_SIZE);
				// log_info("Marking padded space for %u segment offt %llu entries of
				// last node %llu", i,
				//	 c->segment_offt[i], c->last_index[i]->header.num_entries);
				*type = paddedSpace;
			}
		} else {
			type = (uint32_t *)&c->segment_buf[i][sizeof(struct segment_header)];
			*type = paddedSpace;
			//log_info("Marking full padded space for leaves segment offt %llu", i, c->segment_offt[i]);
		}

		if (i == c->tree_height) {
			// log_info("Merged level has a height off %u", c->tree_height);
			c->last_index[i]->header.type = rootNode;
			uint32_t offt = comp_calc_offt_in_seg(c->segment_buf[i], (char *)c->last_index[i]);
			c->root_offt = c->dev_offt[i] + offt;
			c->handle->db_desc->levels[c->level_id].root_r[1] = REAL_ADDRESS(c->root_offt);
		}

		struct segment_header *segment_in_mem_buffer = (struct segment_header *)c->segment_buf[i];

		if (MAX_HEIGHT - 1 == i) {
			c->handle->db_desc->levels[c->level_id].last_segment[1] = REAL_ADDRESS(c->dev_offt[i]);
			segment_in_mem_buffer->next_segment = NULL;
		} else {
			assert(c->dev_offt[i + 1]);
			segment_in_mem_buffer->next_segment = (void *)c->dev_offt[i + 1];
		}

		comp_write_segment(c->segment_buf[i], c->dev_offt[i], 0, SEGMENT_SIZE, c->fd);
		// log_info("Dumped buffer %u at dev_offt %llu",i,c->dev_offt[i]);
	}

	return;
}

/*mini allocator*/
static void comp_get_space(struct comp_level_write_cursor *c, uint32_t height, nodeType_t type)
{
	struct level_descriptor *level_desc = &c->handle->db_desc->levels[c->level_id];
	uint32_t level_leaf_size = level_desc->leaf_size;
	switch (type) {
	case leafNode:
	case leafRootNode: {
		uint32_t remaining_space;
		if (c->segment_offt[0] > 0 && c->segment_offt[0] % SEGMENT_SIZE == 0)
			remaining_space = 0;
		else
			remaining_space = SEGMENT_SIZE - (c->segment_offt[0] % SEGMENT_SIZE);
		if (remaining_space < level_leaf_size) {
			if (remaining_space > 0) {
				*(uint32_t *)(&c->segment_buf[0][c->segment_offt[0] % SEGMENT_SIZE]) = paddedSpace;
				c->segment_offt[0] += remaining_space;
			}

			struct segment_header *new_device_segment =
				get_segment_for_lsm_level_IO(c->handle->db_desc, c->level_id, 1);
			struct segment_header *current_segment_mem_buffer =
				(struct segment_header *)&c->segment_buf[0][0];
			current_segment_mem_buffer->next_segment = (void *)ABSOLUTE_ADDRESS(new_device_segment);

			comp_write_segment(c->segment_buf[0], c->dev_offt[0], 0, SEGMENT_SIZE, c->fd);
			memset(&c->segment_buf[0][0], 0x00, sizeof(struct segment_header));

			c->dev_offt[0] = ABSOLUTE_ADDRESS(new_device_segment);
			c->segment_offt[0] += sizeof(struct segment_header);
		}
		c->last_leaf = (struct bt_dynamic_leaf_node *)(&c->segment_buf[0][(c->segment_offt[0] % SEGMENT_SIZE)]);
		comp_init_dynamic_leaf(c->last_leaf);
		c->segment_offt[0] += level_leaf_size;
		break;
	}
	case internalNode:
	case rootNode: {
		uint32_t remaining_space;
		if (c->segment_offt[height] > 0 && c->segment_offt[height] % SEGMENT_SIZE == 0)
			remaining_space = 0;
		else
			remaining_space = SEGMENT_SIZE - (c->segment_offt[height] % SEGMENT_SIZE);

		if (remaining_space < (INDEX_NODE_SIZE + KEY_BLOCK_SIZE)) {
			if (remaining_space > 0) {
				*(uint32_t *)(&c->segment_buf[height][c->segment_offt[height] % SEGMENT_SIZE]) =
					paddedSpace;
				c->segment_offt[height] += remaining_space;
			}

			struct segment_header *new_device_segment =
				get_segment_for_lsm_level_IO(c->handle->db_desc, c->level_id, 1);
			struct segment_header *current_segment_mem_buffer =
				(struct segment_header *)&c->segment_buf[height][0];
			current_segment_mem_buffer->next_segment = (void *)ABSOLUTE_ADDRESS(new_device_segment);

			comp_write_segment(c->segment_buf[0], c->dev_offt[0], 0, SEGMENT_SIZE, c->fd);
			memset(&c->segment_buf[0][0], 0x00, sizeof(struct segment_header));
			c->segment_offt[height] += sizeof(struct segment_header);
			c->dev_offt[height] = ABSOLUTE_ADDRESS(new_device_segment);
		}
		c->last_index[height] =
			(struct index_node *)&c->segment_buf[height][c->segment_offt[height] % SEGMENT_SIZE];

		/*initialization*/
		c->last_index[height]->header.type = type;
		c->last_index[height]->header.height = height;
		c->last_index[height]->header.num_entries = 0;
		c->last_index[height]->header.fragmentation = 0;
		/*private key log for index nodes*/
		uint64_t index_log_dev_offt =
			c->dev_offt[height] + c->segment_offt[height] % SEGMENT_SIZE + INDEX_NODE_SIZE;

		IN_log_header *tmp = (IN_log_header *)&c->segment_buf[height][index_log_dev_offt % SEGMENT_SIZE];
		tmp->type = keyBlockHeader;
		tmp->next = NULL;
		c->last_index[height]->header.first_IN_log_header = (IN_log_header *)index_log_dev_offt;
		//(IN_log_header *)((uint64_t)c->dev_offt[height] + ((uint64_t)bh %
		// SEGMENT_SIZE));
		c->last_index[height]->header.last_IN_log_header = c->last_index[height]->header.first_IN_log_header;
		c->last_index[height]->header.key_log_size = sizeof(IN_log_header);
		c->segment_offt[height] += INDEX_NODE_SIZE + KEY_BLOCK_SIZE;
		break;
	}
	default:
		log_fatal("Wrong type");
		exit(EXIT_FAILURE);
	}
}

static void comp_append_pivot_to_index(struct comp_level_write_cursor *c, uint64_t left_node_offt,
				       uint64_t right_node_offt, char *pivot, uint32_t height)
{
	uint32_t pivot_size = sizeof(uint32_t) + KEY_SIZE(pivot);
	assert(pivot_size < MAX_KEY_SIZE);
	uint64_t left_index_offt;
	uint64_t right_index_offt;
	uint32_t new_index = 0;
	char *new_pivot = NULL;
	char *new_pivot_buf = NULL;

	uint32_t remaining_in_index_log;
	if (c->last_index[height]->header.key_log_size % KEY_BLOCK_SIZE == 0)
		remaining_in_index_log = 0;
	else
		remaining_in_index_log = KEY_BLOCK_SIZE - (c->last_index[height]->header.key_log_size % KEY_BLOCK_SIZE);

	if (c->tree_height < height)
		c->tree_height = height;

	if (c->last_index[height]->header.num_entries >= (uint32_t)index_order || remaining_in_index_log < pivot_size) {
		// node if full
		/*keep current aka left leaf offt*/

		uint32_t offt_l = comp_calc_offt_in_seg(c->segment_buf[height], (char *)c->last_index[height]);
		left_index_offt = c->dev_offt[height] + offt_l;
		uint64_t offt = c->last_index[height]->p[c->last_index[height]->header.num_entries - 1].pivot;

		new_pivot = &c->segment_buf[height][offt % SEGMENT_SIZE];
		// assert(*(uint32_t *)new_pivot > 0);
		new_pivot_buf = (char *)malloc(*(uint32_t *)new_pivot + sizeof(uint32_t));
		memcpy(new_pivot_buf, new_pivot, *(uint32_t *)new_pivot + sizeof(uint32_t));
		// log_info("Done adding pivot %s for height %u", new_pivot + 4, height);
		--c->last_index[height]->header.num_entries;
		comp_get_space(c, height, internalNode);
		/*last leaf updated*/
		uint32_t offt_r = comp_calc_offt_in_seg(c->segment_buf[height], (char *)c->last_index[height]);
		right_index_offt = c->dev_offt[height] + offt_r;
		new_index = 1;
	}
	/*copy pivot*/
	uint64_t pivot_offt = (uint64_t)c->last_index[height]->header.last_IN_log_header +
			      (c->last_index[height]->header.key_log_size % KEY_BLOCK_SIZE);

	// log_info("pivot location at the device within the segment %llu", pivot_offt
	// % SEGMENT_SIZE);
	char *pivot_addr = &c->segment_buf[height][(uint64_t)pivot_offt % SEGMENT_SIZE];

	memcpy(pivot_addr, pivot, pivot_size);
	// log_info("Adding pivot %u:%s for height %u num entries %u", pivot_size,
	// pivot + 4, height,
	// c->last_index[height]->header.numberOfEntriesInNode);

	c->last_index[height]->header.key_log_size += pivot_size;
	// assert(*(uint32_t *)(pivot_addr) > 0);
	// assert(*(uint32_t *)(pivot) > 0);
	++c->last_index[height]->header.num_entries;
	uint32_t idx = c->last_index[height]->header.num_entries - 1;
	c->last_index[height]->p[idx].left[0] = left_node_offt;
	c->last_index[height]->p[idx].pivot = pivot_offt;
	c->last_index[height]->p[idx].right[0] = right_node_offt;

	if (new_index) {
		comp_append_pivot_to_index(c, left_index_offt, right_index_offt, new_pivot_buf, height + 1);
		free(new_pivot_buf);
	}
}

static void comp_init_medium_log(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	log_info("Initializing medium log for db: %s", db_desc->db_superblock->db_name);
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

	ins_req.metadata.kv_size = sizeof(uint32_t) + KEY_SIZE(in->kv_inplace);
	ins_req.metadata.kv_size += VALUE_SIZE(in->kv_inplace + ins_req.metadata.kv_size) + sizeof(uint32_t);
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
	// log_info("Appending to medium log during compaction");
	char *log_location = append_key_value_to_log(&log_op);
	out->kv_inlog = &out->kvsep;
	if (ins_req.metadata.kv_size >= PREFIX_SIZE)
		memcpy(out->kv_inlog, in->kv_inplace + sizeof(uint32_t), PREFIX_SIZE);
	else {
		memset(out->kv_inlog, 0x00, PREFIX_SIZE);
		memcpy(out->kv_inlog, in->kv_inplace + sizeof(uint32_t), ins_req.metadata.kv_size);
	}

	out->kv_category = MEDIUM_INLOG;
	out->kv_type = KV_INLOG;
	out->kv_inlog->dev_offt = (uint64_t)log_location;
	out->tombstone = 0;
	//log_info("Compact key %s", ins_req.key_value_buf + 4);
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
		kv_size = sizeof(uint32_t) + KEY_SIZE(curr_key->kv_inplace);
		kv_size += VALUE_SIZE(curr_key->kv_inplace + kv_size) + sizeof(uint32_t);
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
		assert(0);
	}

	if (write_leaf_args.cat == MEDIUM_INLOG &&
	    write_leaf_args.level_id == cursor->handle->db_desc->level_medium_inplace) {
		kv_size = sizeof(uint32_t) + KEY_SIZE(curr_key->kv_inlog->dev_offt);
		kv_size += VALUE_SIZE(curr_key->kv_inlog->dev_offt + kv_size) + sizeof(uint32_t);
		write_leaf_args.key_value_size = kv_size;
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
		left_leaf_offt = cursor->dev_offt[0] + offt_l;
		comp_get_space(cursor, 0, leafNode);
		/*last leaf updated*/
		uint32_t offt_r = comp_calc_offt_in_seg(cursor->segment_buf[0], (char *)cursor->last_leaf);
		right_leaf_offt = cursor->dev_offt[0] + offt_r;
		new_leaf = 1;
	}

	write_leaf_args.leaf = cursor->last_leaf;
	write_leaf_args.dest = get_leaf_log_offset(cursor->last_leaf, level_leaf_size);
	write_leaf_args.middle = cursor->last_leaf->header.num_entries;

#if MEASURE_MEDIUM_INPLACE
	if (write_leaf_args.cat == MEDIUM_INLOG &&
	    write_leaf_args.level_id == c->handle->db_desc->level_medium_inplace) {
		__sync_fetch_and_add(&cursor->handle->db_desc->count_medium_inplace, 1);
	}
#endif

	if (write_leaf_args.cat == MEDIUM_INLOG &&
	    write_leaf_args.level_id == cursor->handle->db_desc->level_medium_inplace)
		write_leaf_args.key_value_buf = fetch_kv_from_LRU(&write_leaf_args, cursor);

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
		if (append_to_medium_log) {
			comp_append_pivot_to_index(cursor, left_leaf_offt, right_leaf_offt, kv->kv_inplace, 1);
		} else {
			switch (write_leaf_args.kv_format) {
			case KV_FORMAT:
				comp_append_pivot_to_index(cursor, left_leaf_offt, right_leaf_offt,
							   write_leaf_args.key_value_buf, 1);
				break;
			case KV_PREFIX:
				if (cursor->level_id == 1 && curr_key->kv_category == MEDIUM_INPLACE)
					comp_append_pivot_to_index(cursor, left_leaf_offt, right_leaf_offt,
								   curr_key->kv_inplace, 1);
				else {
					// do a page fault to find the pivot
					char *pivot_addr = (char *)curr_key->kv_inlog->dev_offt;
					comp_append_pivot_to_index(cursor, left_leaf_offt, right_leaf_offt, pivot_addr,
								   1);
				}
				break;
			}
		}
	}
}

struct compaction_request {
	db_descriptor *db_desc;
	volume_descriptor *volume_desc;
	uint64_t l0_start;
	uint64_t l0_end;
	uint8_t src_level;
	uint8_t src_tree;
	uint8_t dst_level;
	uint8_t dst_tree;
};

void mark_segment_space(db_handle *handle, struct dups_list *list)
{
	struct dups_node *list_iter;
	struct large_log_segment_gc_entry *temp_segment_entry;
	uint64_t segment_dev_offt;

	MUTEX_LOCK(&handle->db_desc->segment_ht_lock);

	for (list_iter = list->head; list_iter; list_iter = list_iter->next) {
		segment_dev_offt = ABSOLUTE_ADDRESS(list_iter->dev_offset);

		struct large_log_segment_gc_entry *search_segment;
		HASH_FIND(hh, handle->db_desc->segment_ht, &segment_dev_offt, sizeof(segment_dev_offt), search_segment);

		if (search_segment) {
			// If the segment is already in the hash table just increase the garbage bytes.
			search_segment->garbage_bytes += list_iter->kv_size;
			assert(search_segment->garbage_bytes < SEGMENT_SIZE);
		} else {
			// This is the first time we detect garbage bytes in this segment,
			// allocate a node and insert it in the hash table.
			temp_segment_entry = malloc(sizeof(struct large_log_segment_gc_entry));
			if (!temp_segment_entry) {
				log_fatal("Malloc return NULL!");
				exit(EXIT_FAILURE);
			}

			temp_segment_entry->segment_dev_offt = segment_dev_offt;
			temp_segment_entry->garbage_bytes = list_iter->kv_size;
			temp_segment_entry->segment_moved = 0;
			HASH_ADD(hh, handle->db_desc->segment_ht, segment_dev_offt,
				 sizeof(temp_segment_entry->segment_dev_offt), temp_segment_entry);
		}
	}

	MUTEX_UNLOCK(&handle->db_desc->segment_ht_lock);
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
		if (db_desc->stat == DB_TERMINATE_COMPACTION_DAEMON) {
			log_warn("Compaction daemon instructed to exit because DB %s is closing, "
				 "Bye bye!...",
				 db_desc->db_superblock->db_name);
			db_desc->stat = DB_IS_CLOSING;
			return NULL;
		}
		struct level_descriptor *level_0 = &handle->db_desc->levels[0];
		struct level_descriptor *level_1 = &handle->db_desc->levels[1];

		int L0_tree = next_L0_tree_to_compact;
		// is level-0 full and not already spilling?
		if (level_0->tree_status[L0_tree] == NO_COMPACTION &&
		    level_0->level_size[L0_tree] >= level_0->max_level_size) {
			// Can I issue a spill to L1?
			int L1_tree = 0;
			if (level_1->tree_status[L1_tree] == NO_COMPACTION &&
			    level_1->level_size[L1_tree] < level_1->max_level_size) {
				/*mark them as spilling L0*/
				level_0->tree_status[L0_tree] = COMPACTION_IN_PROGRESS;
				/*mark them as spilling L1*/
				level_1->tree_status[L1_tree] = COMPACTION_IN_PROGRESS;

				/*start a compaction*/
				comp_req = (struct compaction_request *)calloc(1, sizeof(struct compaction_request));
				assert(comp_req);
				comp_req->db_desc = handle->db_desc;
				comp_req->volume_desc = handle->volume_desc;
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
				if (RWLOCK_WRLOCK(&(db_desc->levels[0].guard_of_level.rx_lock))) {
					log_fatal("Failed to acquire guard lock");
					exit(EXIT_FAILURE);
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
					exit(EXIT_FAILURE);
				}

				MUTEX_LOCK(&db_desc->client_barrier_lock);
				if (pthread_cond_broadcast(&db_desc->client_barrier) != 0) {
					log_fatal("Failed to wake up stopped clients");
					exit(EXIT_FAILURE);
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
				exit(EXIT_FAILURE);
			}
			comp_req = NULL;
		}

		// rest of levels
		for (int level_id = 1; level_id < MAX_LEVELS - 1; ++level_id) {
			level_1 = &db_desc->levels[level_id];
			struct level_descriptor *level_2 = &db_desc->levels[level_id + 1];
			uint8_t tree_1 = 0; // level_1->active_tree;
			uint8_t tree_2 = 0; // level_2->active_tree;

			if (level_1->tree_status[tree_1] == NO_COMPACTION &&
			    level_1->level_size[tree_1] >= level_1->max_level_size) {
				if (level_2->tree_status[tree_2] == NO_COMPACTION &&
				    level_2->level_size[tree_2] < level_2->max_level_size) {
					level_1->tree_status[tree_1] = COMPACTION_IN_PROGRESS;
					level_2->tree_status[tree_2] = COMPACTION_IN_PROGRESS;
					/*start a compaction*/
					struct compaction_request *comp_req_p = (struct compaction_request *)calloc(
						1, sizeof(struct compaction_request));
					assert(comp_req_p);
					comp_req_p->db_desc = db_desc;
					comp_req_p->volume_desc = handle->volume_desc;
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
						exit(EXIT_FAILURE);
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
		nd->kv_size = sizeof(uint32_t) + KEY_SIZE(nd->KV);
		nd->kv_size += VALUE_SIZE(nd->KV + nd->kv_size) + sizeof(uint32_t);
		break;
	case BIG_INLOG:
	case MEDIUM_INLOG:
		nd->type = KV_PREFIX;
		// log_info("Prefix %.12s dev_offt %llu", cur->cursor_key.in_log->prefix,
		//	 cur->cursor_key.in_log->device_offt);
		nd->KV = cur->cursor_key.kv_inlog;
		nd->kv_size = sizeof(struct bt_leaf_entry);
		break;
	default:
		log_fatal("UNKNOWN_LOG_CATEGORY");
		exit(EXIT_FAILURE);
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
		curr_key->kv_inlog = nd->KV;
		curr_key->kv_type = KV_INLOG;
		break;
	default:
		log_info("Unhandle/Unknown category");
		exit(EXIT_FAILURE);
	}
}

static void print_heap_node_key(struct sh_heap_node *nd)
{
	switch (nd->cat) {
	case SMALL_INPLACE:
	case MEDIUM_INPLACE:
		log_info("In place Key is %u:%s", *(uint32_t *)nd->KV, nd->KV + sizeof(uint32_t));
		break;
	case BIG_INLOG:
	case MEDIUM_INLOG:
		log_info("In log Key prefix is %.12s device offt %llu", nd->KV, *(uint64_t *)(nd->KV + PREFIX_SIZE));
		break;
	default:
		log_info("Unhandle/Unknown category");
		exit(EXIT_FAILURE);
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
		exit(EXIT_FAILURE);
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
		exit(EXIT_FAILURE);
	}

	if (RWLOCK_WRLOCK(&(comp_req->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock))) {
		log_fatal("Failed to acquire guard lock");
		exit(EXIT_FAILURE);
	}
	spin_loop(&comp_req->db_desc->levels[comp_req->src_level].active_operations, 0);
	spin_loop(&comp_req->db_desc->levels[comp_req->dst_level].active_operations, 0);
}

static void unlock_to_update_levels_after_compaction(struct compaction_request *comp_req)
{
	if (RWLOCK_UNLOCK(&(comp_req->db_desc->levels[comp_req->src_level].guard_of_level.rx_lock))) {
		log_fatal("Failed to acquire guard lock");
		exit(EXIT_FAILURE);
	}

	if (RWLOCK_UNLOCK(&(comp_req->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock))) {
		log_fatal("Failed to acquire guard lock");
		exit(EXIT_FAILURE);
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

		log_info("Initializing L0 scanner");
		level_src = _init_spill_buffer_scanner(handle, comp_req->src_level, comp_roots.src_root, NULL);
	} else {
		if (posix_memalign((void **)&l_src, ALIGNMENT, sizeof(struct comp_level_read_cursor)) != 0) {
			log_fatal("Posix memalign failed");
			perror("Reason: ");
			exit(EXIT_FAILURE);
		}
		comp_init_read_cursor(l_src, handle, comp_req->src_level, 0, FD);
		comp_get_next_key(l_src);
		assert(!l_src->end_of_level);
	}

	if (comp_roots.dst_root) {
		if (posix_memalign((void **)&l_dst, ALIGNMENT, sizeof(struct comp_level_read_cursor)) != 0) {
			log_fatal("Posix memalign failed");
			perror("Reason: ");
			exit(EXIT_FAILURE);
		}
		comp_init_read_cursor(l_dst, handle, comp_req->dst_level, 0, FD);
		comp_get_next_key(l_dst);
		assert(!l_dst->end_of_level);
	}

	log_info("Initializing write cursor for level %u", comp_req->dst_level);
	if (posix_memalign((void **)&merged_level, ALIGNMENT, sizeof(struct comp_level_write_cursor)) != 0) {
		log_fatal("Posix memalign failed");
		perror("Reason: ");
		exit(EXIT_FAILURE);
	}
	assert(0 == handle->db_desc->levels[comp_req->dst_level].offset[comp_req->dst_tree]);
	comp_init_write_cursor(merged_level, handle, comp_req->dst_level, FD);

	//initialize LRU cache for storing chunks of segments when medium log goes in place
	if (merged_level->level_id == handle->db_desc->level_medium_inplace)
		merged_level->medium_log_LRU_cache = init_LRU();

	log_info("Src [%u][%u] size = %llu", comp_req->src_level, comp_req->src_tree,
		 handle->db_desc->levels[comp_req->src_level].level_size[comp_req->src_tree]);
	if (comp_roots.dst_root)
		log_info("Dst [%u][%u] size = %llu", comp_req->dst_level, 0,
			 handle->db_desc->levels[comp_req->dst_level].level_size[0]);
	else
		log_info("Empty dst [%u][%u]", comp_req->dst_level, 0);

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
		log_info("Initializing heap from SRC L0");
	} else {
		log_info("Initializing heap from SRC read cursor level %u with key:", comp_req->src_level);
		comp_fill_heap_node(comp_req, l_src, &nd_src);
	}

	print_heap_node_key(&nd_src);
	nd_src.db_desc = comp_req->db_desc;
	sh_insert_heap_node(m_heap, &nd_src);
	// init Li+1 cursor (if any)
	if (l_dst) {
		comp_fill_heap_node(comp_req, l_dst, &nd_dst);
		log_info("Initializing heap from DST read cursor level %u", comp_req->dst_level);
		print_heap_node_key(&nd_dst);
		nd_dst.db_desc = comp_req->db_desc;
		sh_insert_heap_node(m_heap, &nd_dst);
	}
	// ############################################################################
	enum sh_heap_status stat = GOT_HEAP;

	do {
		// TODO: Remove dirty
		handle->db_desc->dirty = 0x01;
		if (handle->db_desc->stat == DB_IS_CLOSING) {
			log_info("DB %s is closing compaction thread exiting...",
				 handle->db_desc->db_superblock->db_name);
			if (l_src)
				free(l_src);
			if (l_dst)
				free(l_dst);
			return;
		}
		// This is to synchronize compactions with flush
		RWLOCK_RDLOCK(&handle->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock);
		stat = sh_remove_top(m_heap, &nd_min);

		if (stat == EMPTY_HEAP) {
			RWLOCK_UNLOCK(&handle->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock);
			break;
		}

		if (!nd_min.duplicate) {
			struct comp_parallax_key key;
			memset(&key, 0, sizeof(key));
			comp_fill_parallax_key(&nd_min, &key);
			comp_append_entry_to_leaf_node(merged_level, &key);
		}
		// log_info("level size
		// %llu",comp_req->db_desc->levels[comp_req->dst_level].level_size[comp_req->dst_tree]);
		/*refill from the appropriate level*/
		if (nd_min.level_id == comp_req->src_level) {
			if (nd_min.level_id == 0) {
				if (_get_next_KV(level_src) != END_OF_DATABASE) {
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
	} while (stat != EMPTY_HEAP);

	if (level_src)
		_close_spill_buffer_scanner(level_src);
	else
		free(l_src);

	if (comp_roots.dst_root)
		free(l_dst);

	mark_segment_space(handle, m_heap->dups);
	comp_close_write_cursor(merged_level);

	sh_destroy_heap(m_heap);
	merged_level->handle->db_desc->levels[comp_req->dst_level].root_w[1] =
		(struct node_header *)REAL_ADDRESS(merged_level->root_offt);
	assert(merged_level->handle->db_desc->levels[comp_req->dst_level].root_w[1]->type == rootNode);

	if (merged_level->level_id == handle->db_desc->level_medium_inplace)
		destroy_LRU(merged_level->medium_log_LRU_cache);

	free(merged_level);

	/***************************************************************/
	struct level_descriptor *ld = &comp_req->db_desc->levels[comp_req->dst_level];
	struct db_handle hd = { .db_desc = comp_req->db_desc, .volume_desc = comp_req->volume_desc };

	lock_to_update_levels_after_compaction(comp_req);

	uint64_t space_freed;
	/*Free L_(i+1)*/
	if (l_dst) {
		uint64_t txn_id = comp_req->db_desc->levels[comp_req->dst_level].allocation_txn_id[comp_req->dst_tree];
		/*free dst (L_i+1) level*/
		space_freed = seg_free_level(comp_req->db_desc, txn_id, comp_req->dst_level, 0);

		log_info("Freed space %llu MB from db:%s destination level %u", space_freed / (1024 * 1024),
			 comp_req->db_desc->db_superblock->db_name, comp_req->dst_level);
	}
	/*Free and zero L_i*/
	uint64_t txn_id = comp_req->db_desc->levels[comp_req->dst_level].allocation_txn_id[comp_req->dst_tree];
	space_freed = seg_free_level(hd.db_desc, txn_id, comp_req->src_level, comp_req->src_tree);
	log_info("Freed space %llu MB from db:%s source level %u", space_freed / (1024 * 1024),
		 comp_req->db_desc->db_superblock->db_name, comp_req->src_level);
	seg_zero_level(hd.db_desc, comp_req->src_level, comp_req->src_tree);

#if ENABLE_BLOOM_FILTERS
	if (dst_root) {
		log_info("Freeing previous bloom filter for dst level %u", comp_req->dst_level);
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
	log_info("Flushed compaction[%u][%u] successfully", comp_req->dst_level, comp_req->dst_tree);
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
		assert(0);
		exit(EXIT_FAILURE);
	}

	ld->root_w[0] = NULL;
	ld->level_size[0] = ld->level_size[1];
	ld->level_size[1] = 0;
	ld->root_w[1] = NULL;
	ld->root_r[1] = NULL;

	unlock_to_update_levels_after_compaction(comp_req);
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

	// optimization check if level below is empty
	struct node_header *dst_root = NULL;
	if (handle.db_desc->levels[comp_req->dst_level].root_w[0] != NULL)
		dst_root = handle.db_desc->levels[comp_req->dst_level].root_w[0];
	else if (handle.db_desc->levels[comp_req->dst_level].root_r[0] != NULL)
		dst_root = handle.db_desc->levels[comp_req->dst_level].root_r[0];
	else {
		dst_root = NULL;
	}

	if (comp_req->src_level == 0 || comp_req->dst_level == handle.db_desc->level_medium_inplace)
		compact_level_direct_IO(&handle, comp_req);
	else if (dst_root)
		compact_level_direct_IO(&handle, comp_req);
	else {
		log_info("Empty level %d time for an optimization :-)", comp_req->dst_level);

		lock_to_update_levels_after_compaction(comp_req);

		struct level_descriptor *leveld_src = &comp_req->db_desc->levels[comp_req->src_level];
		struct level_descriptor *leveld_dst = &comp_req->db_desc->levels[comp_req->dst_level];

		swap_levels(leveld_src, leveld_dst, comp_req->src_tree, 1);

		pr_flush_compaction(comp_req->db_desc, comp_req->dst_level, comp_req->dst_tree);
		swap_levels(leveld_dst, leveld_dst, 1, 0);
		log_info("Flushed compaction[%u][%u] (Swap levels) successfully", comp_req->dst_level,
			 comp_req->dst_tree);

#if ENABLE_BLOOM_FILTERS
		log_info("Swapping also bloom filter");
		leveld_dst->bloom_filter[0] = leveld_src->bloom_filter[0];
		memset(&leveld_src->bloom_filter[0], 0x00, sizeof(struct bloom));
#endif
		unlock_to_update_levels_after_compaction(comp_req);

		log_info("Swapped levels %d to %d successfully", comp_req->src_level, comp_req->dst_level);
		log_info("After swapping src tree[%d][%d] size is %llu", comp_req->src_level, 0,
			 leveld_src->level_size[0]);
		log_info("After swapping dst tree[%d][%d] size is %llu", comp_req->dst_level, 0,
			 leveld_dst->level_size[0]);
		assert(leveld_dst->first_segment != NULL);
	}

	log_info("DONE Compaction from level's tree [%u][%u] to level's tree[%u][%u] "
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
			exit(EXIT_FAILURE);
		}
	}
	MUTEX_UNLOCK(&db_desc->client_barrier_lock);
	sem_post(&db_desc->compaction_daemon_interrupts);
	free(comp_req);
	return NULL;
}

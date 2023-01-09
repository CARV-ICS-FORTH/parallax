#include "level_read_cursor.h"
#include "../common/common.h"
#include "../scanner/min_max_heap.h"
#include "../scanner/scanner.h"
#include "btree_node.h"
#include "dynamic_leaf.h"
#include "index_node.h"
#include <assert.h>
#include <log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void wcursor_fill_heap_node_from_L0(struct rcursor_level_read_cursor *r_cursor, struct sh_heap_node *heap_node)
{
	heap_node->level_id = r_cursor->level_id;
	heap_node->active_tree = r_cursor->tree_id;
	heap_node->splice = r_cursor->L0_cursor->L0_scanner->splice;
}

static void wcursor_fill_heap_node_from_device(struct rcursor_level_read_cursor *r_cursor, struct sh_heap_node *h_node)
{
	h_node->level_id = r_cursor->level_id;
	h_node->active_tree = r_cursor->tree_id;
	h_node->splice = r_cursor->splice;
}

void wcursor_fill_heap_node(struct rcursor_level_read_cursor *r_cursor, struct sh_heap_node *h_node)
{
	h_node->db_desc = r_cursor->handle->db_desc;
	0 == r_cursor->level_id ? wcursor_fill_heap_node_from_L0(r_cursor, h_node) :
				  wcursor_fill_heap_node_from_device(r_cursor, h_node);
}

struct rcursor_level_read_cursor *rcursor_init_cursor(db_handle *handle, uint32_t level_id, uint32_t tree_id,
						      int file_desc)
{
	struct rcursor_level_read_cursor *r_cursor = calloc(1UL, sizeof(struct rcursor_level_read_cursor));

	r_cursor->level_id = level_id;
	r_cursor->tree_id = tree_id;
	r_cursor->handle = handle;
	r_cursor->is_end_of_level = false;

	if (0 == level_id) {
		r_cursor->L0_cursor = calloc(1UL, sizeof(struct rcursor_L0_cursor));
		r_cursor->L0_cursor->L0_scanner = level_scanner_init_compaction_scanner(handle, level_id, tree_id);
		return r_cursor;
	}

	r_cursor->device_cursor = NULL;
	if (posix_memalign((void **)&r_cursor->device_cursor, ALIGNMENT, sizeof(struct rcursor_device_cursor)) != 0) {
		log_fatal("Posix memalign failed");
		perror("Reason: ");
		BUG_ON();
	}
	memset(r_cursor->device_cursor, 0xFF, sizeof(struct rcursor_device_cursor));

	r_cursor->device_cursor->fd = file_desc;
	r_cursor->device_cursor->offset = 0;
	r_cursor->device_cursor->curr_segment = NULL;
	r_cursor->device_cursor->curr_leaf_entry = 0;
	r_cursor->device_cursor->state = COMP_CUR_FETCH_NEXT_SEGMENT;
	rcursor_get_next_kv(r_cursor);
	return r_cursor;
}

static bool rcursor_get_next_KV_from_L0(struct rcursor_level_read_cursor *r_cursor)
{
	return level_scanner_get_next(r_cursor->L0_cursor->L0_scanner);
}

static bool rcursor_get_next_kv_from_device(struct rcursor_level_read_cursor *r_cursor)
{
	struct rcursor_device_cursor *device_cursor = r_cursor->device_cursor;

	uint32_t level_leaf_size = r_cursor->handle->db_desc->levels[r_cursor->level_id].leaf_size;
	if (r_cursor->is_end_of_level)
		return false;
	while (1) {
	fsm_entry:
		switch (device_cursor->state) {
		case COMP_CUR_CHECK_OFFT: {
			if (device_cursor->offset >=
			    r_cursor->handle->db_desc->levels[r_cursor->level_id].offset[r_cursor->tree_id]) {
				log_debug("Done read level %u", r_cursor->level_id);
				r_cursor->is_end_of_level = true;
				assert(device_cursor->offset ==
				       r_cursor->handle->db_desc->levels[r_cursor->level_id].offset[r_cursor->tree_id]);
				return false;
			}
			if (device_cursor->offset % SEGMENT_SIZE == 0)
				device_cursor->state = COMP_CUR_FETCH_NEXT_SEGMENT;
			else
				device_cursor->state = COMP_CUR_FIND_LEAF;
			break;
		}

		case COMP_CUR_FETCH_NEXT_SEGMENT: {
			if (device_cursor->curr_segment == NULL) {
				device_cursor->curr_segment = r_cursor->handle->db_desc->levels[r_cursor->level_id]
								      .first_segment[r_cursor->tree_id];
			} else {
				if (device_cursor->curr_segment->next_segment == NULL) {
					assert((uint64_t)device_cursor->curr_segment ==
					       (uint64_t)r_cursor->handle->db_desc->levels[r_cursor->level_id]
						       .last_segment[r_cursor->tree_id]);
					log_debug("Done reading level %u cursor offset %lu total offt %lu",
						  r_cursor->level_id, device_cursor->offset,
						  r_cursor->handle->db_desc->levels[r_cursor->level_id]
							  .offset[r_cursor->tree_id]);
					assert(device_cursor->offset ==
					       r_cursor->handle->db_desc->levels[r_cursor->level_id]
						       .offset[r_cursor->tree_id]);
					device_cursor->state = COMP_CUR_CHECK_OFFT;
					//TODO replace goto with continue;
					//TODO Rename device_offt
					goto fsm_entry;
				} else
					device_cursor->curr_segment = (segment_header *)REAL_ADDRESS(
						(uint64_t)device_cursor->curr_segment->next_segment);
			}
			/*log_info("Fetching next segment id %llu for [%lu][%lu]", c->curr_segment->segment_id,
				 c->level_id, c->tree_id);*/
			/*read the segment*/

			off_t dev_offt = ABSOLUTE_ADDRESS(device_cursor->curr_segment);
			//	log_info("Reading level segment from dev_offt: %llu", dev_offt);
			ssize_t bytes_read = 0; //sizeof(struct segment_header);
			while (bytes_read < SEGMENT_SIZE) {
				ssize_t bytes = pread(device_cursor->fd, &device_cursor->segment_buf[bytes_read],
						      SEGMENT_SIZE - bytes_read, dev_offt + bytes_read);
				if (-1 == bytes) {
					log_fatal("Failed to read error code");
					perror("Error");
					BUG_ON();
				}
				bytes_read += bytes;
			}
			device_cursor->offset += sizeof(struct segment_header);
			device_cursor->state = COMP_CUR_FIND_LEAF;
			break;
		}

		case COMP_CUR_DECODE_KV: {
			struct leaf_node *leaf = (struct leaf_node *)((uint64_t)device_cursor->segment_buf +
								      (device_cursor->offset % SEGMENT_SIZE));
			// slot array entry
			if (device_cursor->curr_leaf_entry >= dl_get_leaf_num_entries(leaf)) {
				// done with this leaf
				device_cursor->curr_leaf_entry = 0;
				device_cursor->offset += level_leaf_size;
				device_cursor->state = COMP_CUR_CHECK_OFFT;
				break;
			}
			r_cursor->splice = dl_get_general_splice(leaf, device_cursor->curr_leaf_entry++);
			return true;
		}

		case COMP_CUR_FIND_LEAF: {
			/*read four bytes to check what is the node format*/
			nodeType_t type =
				*(uint32_t *)(&device_cursor->segment_buf[device_cursor->offset % SEGMENT_SIZE]);
			switch (type) {
			case leafNode:
			case leafRootNode:
				//__sync_fetch_and_add(&leaves, 1);
				//log_info("Found a leaf!");
				device_cursor->state = COMP_CUR_DECODE_KV;
				goto fsm_entry;

			case rootNode:
			case internalNode:
				/*log_info("Found an internal");*/
				device_cursor->offset += index_node_get_size();
				device_cursor->state = COMP_CUR_CHECK_OFFT;
				goto fsm_entry;

			case paddedSpace:
				/*log_info("Found padded space of size %llu",
					 (SEGMENT_SIZE - (c->offset % SEGMENT_SIZE)));*/
				device_cursor->offset += (SEGMENT_SIZE - (device_cursor->offset % SEGMENT_SIZE));
				device_cursor->state = COMP_CUR_CHECK_OFFT;
				goto fsm_entry;
			default:
				log_fatal("Faulty read cursor of level %u Wrong node type %u offset "
					  "was %lu total level offset %lu faulty segment offt: %lu",
					  r_cursor->level_id, type, device_cursor->offset,
					  r_cursor->handle->db_desc->levels[r_cursor->level_id].offset[0],
					  ABSOLUTE_ADDRESS(device_cursor->curr_segment));
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

bool rcursor_get_next_kv(struct rcursor_level_read_cursor *r_cursor)
{
	if (NULL == r_cursor) {
		log_fatal("NULL cursor!");
		BUG_ON();
	}
	return 0 == r_cursor->level_id ? rcursor_get_next_KV_from_L0(r_cursor) :
					 rcursor_get_next_kv_from_device(r_cursor);
}

void rcursor_close_cursor(struct rcursor_level_read_cursor *r_cursor)
{
	if (NULL == r_cursor)
		return;

	if (0 == r_cursor->level_id) {
		level_scanner_close(r_cursor->L0_cursor->L0_scanner);
		free(r_cursor->L0_cursor);
		free(r_cursor);
		return;
	}
	free(r_cursor->device_cursor);
	free(r_cursor);
}

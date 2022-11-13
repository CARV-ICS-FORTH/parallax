#include "level_read_cursor.h"
#include "index_node.h"
#include <assert.h>
#include <log.h>
#include <string.h>
#include <unistd.h>

void comp_init_read_cursor(struct comp_level_read_cursor *c, db_handle *handle, uint32_t level_id, uint32_t tree_id,
			   int fd)
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

void comp_get_next_key(struct comp_level_read_cursor *c)
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
				c->cursor_key.kv_inlog = (struct kv_seperation_splice *)kv_loc;
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
				c->offset += index_node_get_size();
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

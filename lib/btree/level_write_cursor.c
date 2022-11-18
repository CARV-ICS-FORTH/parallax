#include "level_write_cursor.h"
#include "dynamic_leaf.h"
#include "index_node.h"
#include "kv_pairs.h"
#include "level_cursor.h"
#include "medium_log_LRU_cache.h"
#include "segment_allocator.h"
#include <assert.h>
#include <log.h>
#include <string.h>
#include <unistd.h>

static void WCURSOR_write_segment(char *buffer, uint64_t dev_offt, uint32_t buf_offt, uint32_t size, int fd)
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

static void WCURSOR_init_dynamic_leaf(struct bt_dynamic_leaf_node *leaf)
{
	leaf->header.type = leafNode;
	leaf->header.num_entries = 0;
	leaf->header.fragmentation = 0;

	leaf->header.leaf_log_size = 0;
	leaf->header.height = 0;
}

static void WCURSOR_get_space(struct WCURSOR_level_write_cursor *w_cursor, uint32_t height, nodeType_t type)
{
	assert(height < MAX_HEIGHT);

	struct level_descriptor *level_desc = &w_cursor->handle->db_desc->levels[w_cursor->level_id];
	uint32_t level_leaf_size = level_desc->leaf_size;
	switch (type) {
	case leafNode:
	case leafRootNode: {
		uint32_t remaining_space = remaining_space = SEGMENT_SIZE - w_cursor->segment_offt[0] % SEGMENT_SIZE;
		if (w_cursor->segment_offt[0] == 0 || w_cursor->segment_offt[0] % SEGMENT_SIZE == 0)
			remaining_space = 0;

		if (remaining_space < level_leaf_size) {
			if (remaining_space > 0) {
				*(uint32_t *)&w_cursor->segment_buf[0][w_cursor->segment_offt[0] % SEGMENT_SIZE] =
					paddedSpace;
				w_cursor->segment_offt[0] += remaining_space;
			}

			struct segment_header *new_device_segment =
				get_segment_for_lsm_level_IO(w_cursor->handle->db_desc, w_cursor->level_id, 1);
			struct segment_header *current_segment_mem_buffer =
				(struct segment_header *)&w_cursor->segment_buf[0][0];

			if (w_cursor->segment_offt[height] != 0) {
				current_segment_mem_buffer->next_segment = (void *)ABSOLUTE_ADDRESS(new_device_segment);

				assert(new_device_segment);
				assert(current_segment_mem_buffer->next_segment);
				WCURSOR_write_segment(w_cursor->segment_buf[0],
						      w_cursor->last_segment_btree_level_offt[0], 0, SEGMENT_SIZE,
						      w_cursor->fd);
			}

			memset(&w_cursor->segment_buf[0][0], 0x00, sizeof(struct segment_header));

			w_cursor->last_segment_btree_level_offt[0] = ABSOLUTE_ADDRESS(new_device_segment);
			w_cursor->segment_offt[0] = sizeof(struct segment_header);
			current_segment_mem_buffer->segment_id = w_cursor->segment_id_cnt++;
			current_segment_mem_buffer->nodetype = type;
		}
		w_cursor->last_leaf =
			(struct bt_dynamic_leaf_node
				 *)(&w_cursor->segment_buf[0][(w_cursor->segment_offt[0] % SEGMENT_SIZE)]);
		WCURSOR_init_dynamic_leaf(w_cursor->last_leaf);
		w_cursor->segment_offt[0] += level_leaf_size;
		break;
	}
	case internalNode:
	case rootNode: {
		uint32_t remaining_space = remaining_space =
			SEGMENT_SIZE - (w_cursor->segment_offt[height] % SEGMENT_SIZE);
		if (w_cursor->segment_offt[height] == 0 || w_cursor->segment_offt[height] % SEGMENT_SIZE == 0)
			remaining_space = 0;

		if (remaining_space < index_node_get_size()) {
			if (remaining_space > 0) {
				*(uint32_t *)(&w_cursor->segment_buf[height][w_cursor->segment_offt[height] %
									     SEGMENT_SIZE]) = paddedSpace;
				w_cursor->segment_offt[height] += remaining_space;
			}

			struct segment_header *new_device_segment =
				get_segment_for_lsm_level_IO(w_cursor->handle->db_desc, w_cursor->level_id, 1);
			struct segment_header *current_segment_mem_buffer =
				(struct segment_header *)&w_cursor->segment_buf[height][0];

			if (w_cursor->segment_offt[height] != 0) {
				current_segment_mem_buffer->next_segment = (void *)ABSOLUTE_ADDRESS(new_device_segment);

				assert(new_device_segment);
				assert(current_segment_mem_buffer->next_segment);

				WCURSOR_write_segment(w_cursor->segment_buf[height],
						      w_cursor->last_segment_btree_level_offt[height], 0, SEGMENT_SIZE,
						      w_cursor->fd);
			}

			memset(&w_cursor->segment_buf[height][0], 0x00, sizeof(struct segment_header));
			w_cursor->segment_offt[height] += sizeof(struct segment_header);
			w_cursor->last_segment_btree_level_offt[height] = ABSOLUTE_ADDRESS(new_device_segment);
			current_segment_mem_buffer->segment_id = w_cursor->segment_id_cnt++;
			current_segment_mem_buffer->nodetype = type;
		}
		w_cursor->last_index[height] =
			(struct index_node *)&w_cursor
				->segment_buf[height][w_cursor->segment_offt[height] % SEGMENT_SIZE];
		w_cursor->segment_offt[height] += index_node_get_size();
		break;
	}
	default:
		log_fatal("Wrong type");
		BUG_ON();
	}
}

struct WCURSOR_level_write_cursor *WCURSOR_init_write_cursor(int level_id, struct db_handle *handle, int tree_id,
							     int file_desc)
{
	struct WCURSOR_level_write_cursor *w_cursor = NULL;
	if (posix_memalign((void **)&w_cursor, ALIGNMENT, sizeof(struct WCURSOR_level_write_cursor)) != 0) {
		log_fatal("Posix memalign failed");
		perror("Reason: ");
		BUG_ON();
	}
	memset(w_cursor, 0x00, sizeof(struct WCURSOR_level_write_cursor));
	w_cursor->level_id = level_id;
	w_cursor->tree_id = tree_id;
	w_cursor->tree_height = 0;
	w_cursor->fd = file_desc;
	w_cursor->handle = handle;

	assert(0 == handle->db_desc->levels[w_cursor->level_id].offset[w_cursor->tree_id]);
	WCURSOR_get_space(w_cursor, 0, leafNode);
	assert(w_cursor->last_segment_btree_level_offt[0]);
	w_cursor->first_segment_btree_level_offt[0] = w_cursor->last_segment_btree_level_offt[0];

	for (int i = 1; i < MAX_HEIGHT; ++i) {
		WCURSOR_get_space(w_cursor, i, internalNode);
		index_init_node(DO_NOT_ADD_GUARD, (struct index_node *)w_cursor->last_index[i], internalNode);
		w_cursor->first_segment_btree_level_offt[i] = w_cursor->last_segment_btree_level_offt[i];
		assert(w_cursor->last_segment_btree_level_offt[i]);
	}
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

	log_debug("Measured %lu offset in level %lu", measure_level_bytes, db_desc->levels[level_id].offset[tree_id]);
	assert(segment == db_desc->levels[level_id].last_segment[tree_id]);
	assert(measure_level_bytes == db_desc->levels[level_id].offset[tree_id]);
}
#endif

static uint32_t WCURSOR_calc_offt_in_seg(char *buffer_start, char *addr)
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

void WCURSOR_flush_write_cursor(struct WCURSOR_level_write_cursor *w_cursor)
{
	uint32_t level_leaf_size = w_cursor->handle->db_desc->levels[w_cursor->level_id].leaf_size;
	for (int32_t i = 0; i < MAX_HEIGHT; ++i) {
		uint32_t *type;
		//log_debug("i = %u tree height: %u", i, c->tree_height);

		if (i <= w_cursor->tree_height) {
			assert(w_cursor->segment_offt[i] > 4096);
			if (i == 0 && w_cursor->segment_offt[i] % SEGMENT_SIZE != 0) {
				type = (uint32_t *)((uint64_t)w_cursor->last_leaf + level_leaf_size);
				//log_info("Marking padded space for %u segment offt %llu", i, c->segment_offt[0]);
				*type = paddedSpace;
			} else if (i > 0 && w_cursor->segment_offt[i] % SEGMENT_SIZE != 0) {
				type = (uint32_t *)(((char *)w_cursor->last_index[i]) + index_node_get_size());
				// log_info("Marking padded space for %u segment offt %llu entries of
				// last node %llu", i,
				//	 c->segment_offt[i], c->last_index[i]->header.num_entries);
				*type = paddedSpace;
			}
		} else {
			type = (uint32_t *)&w_cursor->segment_buf[i][sizeof(struct segment_header)];
			*type = paddedSpace;
			//log_debug("Marking full padded space for level_id %u tree height %u", c->level_id,
			//	  c->tree_height);
		}

		if (i == w_cursor->tree_height) {
			log_debug("Merged level has a height off %u", w_cursor->tree_height);

			if (!index_set_type((struct index_node *)w_cursor->last_index[i], rootNode)) {
				log_fatal("Error setting node type");
				BUG_ON();
			}
			uint32_t offt =
				WCURSOR_calc_offt_in_seg(w_cursor->segment_buf[i], (char *)w_cursor->last_index[i]);
			w_cursor->root_offt = w_cursor->last_segment_btree_level_offt[i] + offt;
			w_cursor->handle->db_desc->levels[w_cursor->level_id].root_r[1] =
				REAL_ADDRESS(w_cursor->root_offt);
		}

		struct segment_header *segment_in_mem_buffer = (struct segment_header *)w_cursor->segment_buf[i];
		//segment_in_mem_buffer->segment_id = c->segment_id_cnt++;
		//assert(c->segment_id_cnt != 251);
		/* segment_in_mem_buffer->nodetype = paddedSpace; */

		if (MAX_HEIGHT - 1 == i) {
			w_cursor->handle->db_desc->levels[w_cursor->level_id].last_segment[1] =
				REAL_ADDRESS(w_cursor->last_segment_btree_level_offt[i]);
			assert(w_cursor->last_segment_btree_level_offt[i]);
			segment_in_mem_buffer->next_segment = NULL;
		} else {
			assert(w_cursor->last_segment_btree_level_offt[i + 1]);
			segment_in_mem_buffer->next_segment = (void *)w_cursor->first_segment_btree_level_offt[i + 1];
		}
		WCURSOR_write_segment(w_cursor->segment_buf[i], w_cursor->last_segment_btree_level_offt[i], 0,
				      SEGMENT_SIZE, w_cursor->fd);
	}

#if 0
	assert_level_segments(c->handle->db_desc, c->level_id, 1);
#endif
}

extern void WCURSOR_close_write_cursor(struct WCURSOR_level_write_cursor *w_cursor)
{
	memset(w_cursor, 0x00, sizeof(struct WCURSOR_level_write_cursor));
	free(w_cursor);
}

static void WCURSOR_append_pivot_to_index(int32_t height, struct WCURSOR_level_write_cursor *c, uint64_t left_node_offt,
					  key_splice_t pivot, uint64_t right_node_offt)
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

	struct insert_pivot_req ins_pivot_req = { .node = node, .key_splice = pivot, .right_child = &right };
	while (!index_append_pivot(&ins_pivot_req)) {
		uint32_t offt_l = WCURSOR_calc_offt_in_seg(c->segment_buf[height], (char *)c->last_index[height]);
		uint64_t left_index_offt = c->last_segment_btree_level_offt[height] + offt_l;

		key_splice_t pivot_copy_splice = index_remove_last_pivot_key(node);
		struct pivot_pointer *piv_pointer = index_get_pivot_pointer(pivot_copy_splice);
		WCURSOR_get_space(c, height, internalNode);
		ins_pivot_req.node = (struct index_node *)c->last_index[height];
		index_init_node(DO_NOT_ADD_GUARD, ins_pivot_req.node, internalNode);
		index_add_guard(ins_pivot_req.node, piv_pointer->child_offt);
		index_set_height(ins_pivot_req.node, height);

		/*last leaf updated*/
		uint32_t offt_r = WCURSOR_calc_offt_in_seg(c->segment_buf[height], (char *)c->last_index[height]);
		uint64_t right_index_offt = c->last_segment_btree_level_offt[height] + offt_r;
		WCURSOR_append_pivot_to_index(height + 1, c, left_index_offt, pivot_copy_splice, right_index_offt);
		free(pivot_copy_splice);
	}
}

static void WCURSOR_init_medium_log(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
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

static struct comp_parallax_key WCURSOR_append_medium_L1(struct WCURSOR_level_write_cursor *w_cursor,
							 struct comp_parallax_key *in_key)
{
	struct comp_parallax_key medium_inlog_kv = { 0 };
	if (w_cursor->level_id != 1)
		return medium_inlog_kv;
	if (in_key->kv_category != MEDIUM_INPLACE)
		return medium_inlog_kv;

	struct db_descriptor *db_desc = w_cursor->handle->db_desc;
	if (db_desc->medium_log.head_dev_offt == 0 && db_desc->medium_log.tail_dev_offt == 0 &&
	    db_desc->medium_log.size == 0) {
		WCURSOR_init_medium_log(w_cursor->handle->db_desc, w_cursor->level_id, 1);
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
	ins_req.metadata.special_split = 0;
	ins_req.metadata.key_format = KV_FORMAT;
	ins_req.metadata.tombstone = 0;
	ins_req.key_value_buf = (char *)in_key->kv_in_place;
	ins_req.metadata.reorganized_leaf_pos_INnode = NULL;
	/*For Tebis-parallax currently*/
	ins_req.metadata.segment_full_event = 0;
	ins_req.metadata.log_segment_addr = 0;
	ins_req.metadata.log_offset_full_event = 0;
	ins_req.metadata.segment_id = 0;
	ins_req.metadata.end_of_log = 0;
	ins_req.metadata.log_padding = 0;

	struct log_operation log_op = { log_op.metadata = &ins_req.metadata, log_op.optype_tolog = insertOp,
					log_op.ins_req = &ins_req, log_op.is_compaction = true };

	char *log_location = append_key_value_to_log(&log_op);

	uint32_t copy_size = get_kv_seperated_prefix_size();
	if (get_key_size(in_key->kv_in_place) < get_kv_seperated_prefix_size()) {
		memset(get_kv_seperated_prefix(&medium_inlog_kv.kv_inlog), 0x00, get_kv_seperated_prefix_size());
		copy_size = get_key_size(in_key->kv_in_place);
	}

	memcpy(get_kv_seperated_prefix(&medium_inlog_kv.kv_inlog), get_key_offset_in_kv(in_key->kv_in_place),
	       copy_size);
	set_kv_seperated_device_offt(&medium_inlog_kv.kv_inlog, (uint64_t)log_location);

	medium_inlog_kv.kv_category = MEDIUM_INLOG;
	medium_inlog_kv.kv_type = KV_INLOG;
	medium_inlog_kv.tombstone = 0;

	return medium_inlog_kv;
}

bool WCURSOR_append_entry_to_leaf_node(struct WCURSOR_level_write_cursor *cursor, struct comp_parallax_key *kv_pair)
{
	struct comp_parallax_key medium_kv_inlog = { 0 };
	struct write_dynamic_leaf_args write_leaf_args = { 0 };
	struct comp_parallax_key *curr_key = kv_pair;
	uint64_t left_leaf_offt = 0;
	uint64_t right_leaf_offt = 0;
	uint32_t level_leaf_size = cursor->handle->db_desc->levels[cursor->level_id].leaf_size;
	uint32_t kv_size = 0;
	uint8_t append_to_medium_log = 0;

	if (cursor->level_id == 1 && kv_pair->kv_category == MEDIUM_INPLACE) {
		medium_kv_inlog = WCURSOR_append_medium_L1(cursor, kv_pair);
		curr_key = &medium_kv_inlog;
		append_to_medium_log = 1;
	}

	write_leaf_args.level_medium_inplace = cursor->handle->db_desc->level_medium_inplace;
	switch (curr_key->kv_type) {
	case KV_INPLACE:
		kv_size = get_kv_size((struct kv_splice *)curr_key->kv_in_place);
		write_leaf_args.kv_dev_offt = 0;
		write_leaf_args.key_value_size = kv_size;
		write_leaf_args.level_id = cursor->level_id;
		write_leaf_args.kv_format = KV_FORMAT;
		write_leaf_args.cat = curr_key->kv_category;
		write_leaf_args.key_value_buf = (char *)curr_key->kv_in_place;
		write_leaf_args.tombstone = curr_key->tombstone;
		//log_info("Appending key in_place %u:%s", write_leaf_args.key_value_size,
		//	 write_leaf_args.key_value_buf + sizeof(uint32_t));
		break;

	case KV_INLOG:
		kv_size = get_kv_seperated_splice_size();
		write_leaf_args.kv_dev_offt = curr_key->kv_inlog.dev_offt;
		write_leaf_args.key_value_buf = (char *)&curr_key->kv_inlog;
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
		assert(get_key_size((struct kv_splice *)write_leaf_args.key_value_buf) <= MAX_KEY_SIZE);
		write_leaf_args.cat = MEDIUM_INPLACE;

		kv_size = get_kv_size((struct kv_splice *)write_leaf_args.key_value_buf);
		write_leaf_args.key_value_size = kv_size;
		curr_key->kv_type = KV_INPLACE;
		curr_key->kv_category = MEDIUM_INPLACE;
		curr_key->kv_in_place = (struct kv_splice *)write_leaf_args.key_value_buf;
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
		uint32_t offt_l = WCURSOR_calc_offt_in_seg(cursor->segment_buf[0], (char *)cursor->last_leaf);
		left_leaf_offt = cursor->last_segment_btree_level_offt[0] + offt_l;
		WCURSOR_get_space(cursor, 0, leafNode);
		/*last leaf updated*/
		uint32_t offt_r = WCURSOR_calc_offt_in_seg(cursor->segment_buf[0], (char *)cursor->last_leaf);
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
	if (!new_leaf)
		return true;
	// log_info("keys are %llu for level %u",
	// c->handle->db_desc->levels[c->level_id].level_size[1],
	//	 c->level_id);

	// constructing the pivot key out of the keys, pivot key follows different format than KV_PREFIX/KV_FORMAT
	// first retrieve the kv_formated kv
	char *kv_formated_kv = (char *)kv_pair->kv_in_place;
	if (!append_to_medium_log) {
		switch (write_leaf_args.kv_format) {
		case KV_FORMAT:
			kv_formated_kv = write_leaf_args.key_value_buf;
			break;
		case KV_PREFIX:
			if (cursor->level_id == 1 && curr_key->kv_category == MEDIUM_INPLACE)
				kv_formated_kv = (char *)curr_key->kv_in_place;
			else {
				// do a page fault to find the pivot
				kv_formated_kv = (char *)get_kv_seperated_device_offt(&curr_key->kv_inlog);
			}
			break;
		default:
			BUG_ON();
		}
	}
	//create a pivot key based on the pivot key format | key_size | key | out of the kv_formated key
	struct kv_splice *kv_buf = (struct kv_splice *)kv_formated_kv;
	bool malloced = false;
	key_splice_t new_pivot =
		create_key_splice(get_key_offset_in_kv(kv_buf), get_key_size(kv_buf), NULL, 0, &malloced);

	WCURSOR_append_pivot_to_index(1, cursor, left_leaf_offt, new_pivot, right_leaf_offt);
	return true;
}

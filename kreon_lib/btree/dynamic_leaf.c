#include <log.h>
#include <assert.h>
#include "dynamic_leaf.h"

void print_all_keys(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size);

struct prefix {
	char *prefix;
	uint32_t len;
};

struct bt_dynamic_leaf_slot_array *get_slot_array_offset(const struct bt_dynamic_leaf_node *leaf)
{
	return (struct bt_dynamic_leaf_slot_array *)(((char *)leaf) + sizeof(struct bt_dynamic_leaf_node));
}

char *get_leaf_log_offset(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size)
{
	return (((char *)leaf) + leaf_size - leaf->header.leaf_log_size);
}

char *get_kv_offset(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size, uint32_t kv_offset)
{
	return (((char *)leaf) + leaf_size - kv_offset);
}

void fill_prefix(struct prefix *key, char *key_loc, enum kv_entry_location key_type)
{
	switch (key_type) {
	case KV_INPLACE:;
		struct splice *key_buf = (struct splice *)key_loc;
		key->prefix = key_buf->data;
		key->len = MIN(key_buf->size, PREFIX_SIZE);
		break;
	case KV_INLOG:
		key->prefix = key_loc + sizeof(uint64_t);
		key->len = PREFIX_SIZE;
		break;
	default:
		assert(0);
	}
}

char *fill_keybuf(char *key_loc, enum kv_entry_location key_type)
{
	switch (key_type) {
	case KV_INPLACE:
		return key_loc;
	case KV_INLOG:
		return REAL_ADDRESS(key_loc);
	default:
		assert(0);
	}
}

struct find_result find_key_in_dynamic_leaf(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size, void *key,
					    uint32_t key_size)
{
	char *buf = malloc(key_size + sizeof(uint32_t));
	struct dl_bsearch_result result = { .middle = 0, .status = INSERT, .op = DYNAMIC_LEAF_FIND };
	struct find_result ret_result = { .kv = NULL, .key_type = KV_INPLACE };
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	struct splice *key_buf = (struct splice *)buf;
	//	BREAKPOINT;
	assert(buf != NULL);
	SERIALIZE_KEY(buf, key, key_size);

	binary_search_dynamic_leaf(leaf, leaf_size, key_buf, &result);
	/* print_all_keys(leaf, leaf_size); */
	if (result.status != FOUND) {
		/* log_info("Middle %d offset %d Numberofentries %d Key Search %*s", result.middle, */
		/* 	 slot_array[result.middle].index, leaf->header.numberOfEntriesInNode, key_buf->size, */
		/* 	 key_buf->data); */
	}

	switch (result.status) {
	case FOUND:
		switch (slot_array[result.middle].bitmap) {
		case KV_INPLACE:
			ret_result.kv = (void *)ABSOLUTE_ADDRESS(
				get_kv_offset(leaf, leaf_size, slot_array[result.middle].index));
			ret_result.key_type = KV_INPLACE;
			break;
		case KV_INLOG:
			ret_result.kv = (char *)&((struct bt_leaf_entry *)get_kv_offset(
							  leaf, leaf_size, slot_array[result.middle].index))
						->pointer;
			ret_result.key_type = KV_INLOG;
			break;
		default:
			assert(0);
		}
		break;
	default:
		break;
		/* log_info("Key not found"); */
		/* log_info("Key not found %*s Key Found %*s Middle %d Status %d", key_buf->size, key_buf->data, */
		/* 	 *(uint32_t *)REAL_ADDRESS(src.kv_entries[src.slot_array[result.middle].index].pointer), */
		/*  REAL_ADDRESS(src.kv_entries[src.slot_array[result.middle].index].pointer) + 4, result.middle, */
		/*  result.status); */
	}

	free(buf);
	return ret_result;
}

void binary_search_dynamic_leaf(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size, struct splice *key_buf,
				struct dl_bsearch_result *result)
{
	struct prefix leaf_key_prefix;
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	char *leaf_key_buf;
	int32_t start = 0, middle = 0, end = leaf->header.numberOfEntriesInNode - 1;
	const int32_t numberOfEntriesInNode = leaf->header.numberOfEntriesInNode;
	uint32_t offset_in_leaf;
	int ret, ret_case;

	while (numberOfEntriesInNode > 0) {
		middle = (start + end) / 2;
		if (middle < 0 || middle >= numberOfEntriesInNode) {
			result->status = ERROR;
			return;
		}

		offset_in_leaf = slot_array[middle].index;
		assert(offset_in_leaf < leaf_size);
		fill_prefix(&leaf_key_prefix, get_kv_offset(leaf, leaf_size, offset_in_leaf),
			    slot_array[middle].bitmap);
		ret = prefix_compare(leaf_key_prefix.prefix, key_buf->data, MIN(leaf_key_prefix.len, key_buf->size));
		ret_case = ret < 0 ? LESS_THAN_ZERO : ret > 0 ? GREATER_THAN_ZERO : EQUAL_TO_ZERO;

		if (ret_case == EQUAL_TO_ZERO) {
			leaf_key_buf =
				fill_keybuf(get_kv_offset(leaf, leaf_size, offset_in_leaf), slot_array[middle].bitmap);
			ret = _tucana_key_cmp(leaf_key_buf, key_buf, KV_FORMAT, KV_FORMAT);

			if (ret == 0) {
				result->middle = middle;
				result->status = FOUND;
				return;
			}

			ret_case = ret < 0 ? LESS_THAN_ZERO : GREATER_THAN_ZERO;
		}

		switch (ret_case) {
		case LESS_THAN_ZERO:
			start = middle + 1;

			if (start > end) {
				if (result->op == DYNAMIC_LEAF_INSERT)
					++middle;

				result->middle = middle;
				result->status = INSERT;
				goto CHECK_IFKV_FOUND;
			}

			break;
		case GREATER_THAN_ZERO:
			end = middle - 1;

			if (start > end) {
				result->middle = middle;
				result->status = INSERT;
				goto CHECK_IFKV_FOUND;
			}

			break;
		}
	}

	if (numberOfEntriesInNode) {
	CHECK_IFKV_FOUND:
		if (result->middle == numberOfEntriesInNode)
			return;

		offset_in_leaf = slot_array[middle].index;
		assert(offset_in_leaf < leaf_size);
		leaf_key_buf = fill_keybuf(get_kv_offset(leaf, leaf_size, offset_in_leaf), slot_array[middle].bitmap);
		ret = _tucana_key_cmp(leaf_key_buf, key_buf, KV_FORMAT, KV_FORMAT);

		if (ret == 0) {
			result->status = FOUND;
			return;
		}
	}
}

void print_all_keys(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size)
{
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	log_info("number of entries %d", leaf->header.numberOfEntriesInNode);
	for (unsigned i = 0; i < leaf->header.numberOfEntriesInNode; ++i) {
		char *key = get_kv_offset(leaf, leaf_size, slot_array[i].index);
		log_info("offset in leaf %d Size%d key %s\n", slot_array[i].index, KEY_SIZE(key), key + 4);
	}
}

static void shift_right_slot_array(struct bt_dynamic_leaf_node *leaf, uint32_t middle)
{
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	const size_t num_items = leaf->header.numberOfEntriesInNode - middle;

	if (num_items == 0)
		return;

	memmove(&slot_array[middle + 1], &slot_array[middle], num_items * sizeof(struct bt_dynamic_leaf_slot_array));
}

uint32_t append_kv_inplace(char *dest, char *buf, uint32_t buf_size)
{
	dest -= buf_size;
	memcpy(dest, buf, buf_size);

	return buf_size;
}

uint32_t append_bt_leaf_entry_inplace(char *dest, uint64_t pointer, char *prefix, uint32_t prefix_size)
{
	dest -= prefix_size;
	memcpy(dest, prefix, prefix_size);

	dest -= sizeof(pointer);
	memcpy(dest, &pointer, sizeof(pointer));

	return sizeof(pointer) + prefix_size;
}

int check_dynamic_leaf_split(struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size, uint32_t kv_size,
			     enum kv_entry_location key_type)
{
	uint32_t leaf_log_size = leaf->header.leaf_log_size;
	uint32_t metadata_size = sizeof(struct bt_dynamic_leaf_node) +
				 (sizeof(struct bt_dynamic_leaf_slot_array) * (leaf->header.numberOfEntriesInNode + 1));
	uint32_t upper_bound = leaf_size - metadata_size;

	switch (key_type) {
	case KV_INPLACE:
		leaf_log_size += kv_size;
		break;
	case KV_INLOG:
		leaf_log_size += sizeof(struct bt_leaf_entry);
		break;
	default:
		assert(0);
	}

	return !(leaf_log_size < upper_bound);
}

struct bt_rebalance_result split_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size, bt_insert_req *req)
{
	struct bt_rebalance_result rep;
	struct bt_dynamic_leaf_node *leaf_copy, *left_leaf, *right_leaf, *old_leaf = leaf;
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	struct bt_dynamic_leaf_slot_array *right_leaf_slot_array, *left_leaf_slot_array;
	char *key_buf, *leaf_log_tail;
	level_descriptor *level = &req->metadata.handle->db_desc->levels[leaf->header.level_id];
	volume_descriptor *volume_desc = req->metadata.handle->volume_desc;
	uint64_t i, j = 0;
	uint32_t key_buf_size;

	/*cow check*/
	if (leaf->header.epoch <= volume_desc->dev_catalogue->epoch) {
		leaf_copy = seg_get_dynamic_leaf_node(volume_desc, level);
		memcpy(leaf_copy, leaf, level->leaf_size);
		leaf_copy->header.epoch = volume_desc->mem_catalogue->epoch;
		leaf = leaf_copy;
	}

	rep.left_dlchild = seg_get_dynamic_leaf_node(volume_desc, level);

	left_leaf = rep.left_dlchild;
	/*Fix left leaf metadata*/
	leaf_log_tail = get_leaf_log_offset(left_leaf, level->leaf_size);
	left_leaf_slot_array = get_slot_array_offset(left_leaf);

	for (i = 0, j = 0; i < leaf->header.numberOfEntriesInNode / 2; ++i, ++j) {
		key_buf = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[i].index), slot_array[i].bitmap);
		uint32_t key_size = KEY_SIZE(key_buf);
		uint32_t value_size = VALUE_SIZE(key_buf + sizeof(uint32_t) + key_size);
		key_buf_size = 2 * sizeof(uint32_t) + key_size + value_size;
		left_leaf->header.leaf_log_size += key_buf_size;
		leaf_log_tail -= key_buf_size;
		memcpy(leaf_log_tail, key_buf, key_buf_size);

		left_leaf_slot_array[j].index = left_leaf->header.leaf_log_size;
		left_leaf_slot_array[j].bitmap = slot_array[i].bitmap;
	}

	/*Fix Right leaf metadata*/
	rep.right_dlchild = seg_get_dynamic_leaf_node(volume_desc, level);
	rep.middle_key_buf =
		fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[leaf->header.numberOfEntriesInNode / 2].index),
			    slot_array[leaf->header.numberOfEntriesInNode / 2].bitmap);

	/* print_all_keys(left_leaf, leaf_size); */

	right_leaf = rep.right_dlchild;
	/*Copy pointers + prefixes*/
	leaf_log_tail = get_leaf_log_offset(right_leaf, leaf_size);
	right_leaf_slot_array = get_slot_array_offset(right_leaf);
	for (i = leaf->header.numberOfEntriesInNode / 2, j = 0; i < leaf->header.numberOfEntriesInNode; ++i, ++j) {
		key_buf = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[i].index), slot_array[i].bitmap);
		uint32_t key_size = KEY_SIZE(key_buf);
		uint32_t value_size = VALUE_SIZE(key_buf + sizeof(uint32_t) + key_size);
		key_buf_size = 2 * sizeof(uint32_t) + key_size + value_size;
		leaf_log_tail -= key_buf_size;
		right_leaf->header.leaf_log_size += key_buf_size;
		memcpy(leaf_log_tail, key_buf, key_buf_size);

		right_leaf_slot_array[j].index = right_leaf->header.leaf_log_size;
		right_leaf_slot_array[j].bitmap = slot_array[i].bitmap;
	}
	rep.left_dlchild->header.height = leaf->header.height;
	rep.left_dlchild->header.numberOfEntriesInNode = leaf->header.numberOfEntriesInNode / 2;

	rep.right_dlchild->header.numberOfEntriesInNode =
		leaf->header.numberOfEntriesInNode - (leaf->header.numberOfEntriesInNode / 2);
	rep.right_dlchild->header.type = leafNode;

	/* print_all_keys(right_leaf, leaf_size); */

	if (leaf->header.type == leafRootNode) {
		rep.left_dlchild->header.type = leafNode;
		rep.stat = LEAF_ROOT_NODE_SPLITTED;
	} else
		rep.stat = LEAF_NODE_SPLITTED;
	seg_free_leaf_node(volume_desc, level, req->metadata.tree_id, (leaf_node *)old_leaf);
	return rep;
}

void write_data_in_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, char *dest, char *key_value_buf,
				uint32_t key_value_size, uint32_t middle)
{
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	uint32_t leaf_log_size = leaf->header.leaf_log_size;
	if (!KV_INPLACE) {
		slot_array[middle].bitmap = KV_INPLACE;
		leaf->header.leaf_log_size += append_kv_inplace(dest, key_value_buf, key_value_size);
	} else if (!KV_INLOG) {
		struct splice *key = (struct splice *)key_value_buf;
		slot_array[middle].bitmap = KV_INLOG;
		leaf->header.leaf_log_size += append_bt_leaf_entry_inplace(dest, ABSOLUTE_ADDRESS(key_value_buf),
									   key->data, MIN(key->size, PREFIX_SIZE));
	} else
		assert(0);

	slot_array[middle].index = leaf->header.leaf_log_size;
	assert(leaf->header.leaf_log_size - leaf_log_size == key_value_size);
}

int8_t insert_in_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, bt_insert_req *req, level_descriptor *level)
{
	struct dl_bsearch_result bsearch = { .middle = 0, .status = INSERT, .op = DYNAMIC_LEAF_INSERT };
	char *leaf_log_tail = get_leaf_log_offset(leaf, level->leaf_size);
	struct splice *key = (struct splice *)req->key_value_buf;
	uint32_t metadata_size = sizeof(struct bt_dynamic_leaf_node) +
				 (sizeof(struct bt_dynamic_leaf_slot_array) * (leaf->header.numberOfEntriesInNode - 1));
	uint32_t upper_bound = level->leaf_size - metadata_size;

	assert(leaf->header.leaf_log_size < upper_bound);

	if (unlikely(leaf->header.numberOfEntriesInNode == 0))
		leaf->header.leaf_log_size = 0;

	binary_search_dynamic_leaf(leaf, level->leaf_size, key, &bsearch);

	switch (bsearch.status) {
	case INSERT:
		shift_right_slot_array(leaf, bsearch.middle);
		write_data_in_dynamic_leaf(leaf, leaf_log_tail, req->key_value_buf, req->metadata.kv_size,
					   bsearch.middle);
		++leaf->header.numberOfEntriesInNode;
		break;
	case FOUND:
		write_data_in_dynamic_leaf(leaf, leaf_log_tail, req->key_value_buf, req->metadata.kv_size,
					   bsearch.middle);
		++leaf->header.fragmentation;
		break;
	default:
		log_fatal("ERROR in insert path%d", bsearch.middle);
		exit(EXIT_FAILURE);
	}

	return bsearch.status;
}

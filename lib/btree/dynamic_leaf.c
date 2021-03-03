#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <log.h>
#include "dynamic_leaf.h"
#include "conf.h"
#include "segment_allocator.h"
#include "../allocator/allocator.h"

void print_all_keys(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size);
char *fill_keybuf(char *key_loc, enum kv_entry_location key_type);

struct prefix {
	char *prefix;
	uint32_t len;
};

struct write_dynamic_leaf_args {
	struct bt_dynamic_leaf_node *leaf;
	char *dest;
	char *key_value_buf;
	uint32_t key_value_size;
	uint32_t middle;
	int level_id;
	int kv_format;
	enum log_category cat;
};

#ifdef DEBUG_DYNAMIC_LEAF
void validate_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, level_descriptor *level, uint32_t kv_size, int flag)
{
	(void)level;
	(void)kv_size;
	(void)flag;
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	/* assert(flag || leaf->header.leaf_log_size + kv_size < */
	/* 		       level->leaf_size - sizeof(struct bt_dynamic_leaf_node) - */
	/* 			       (sizeof(struct bt_dynamic_leaf_slot_array) * leaf->header.num_entries)); */

	for (unsigned i = 0; i < leaf->header.num_entries; ++i) {
		assert(slot_array[i].index <
		       LEVEL0_LEAF_SIZE /* level->leaf_size */ - sizeof(struct bt_dynamic_leaf_node) -
			       (sizeof(struct bt_dynamic_leaf_slot_array) * leaf->header.num_entries));
		assert(*(uint32_t *)fill_keybuf(get_kv_offset(leaf, LEVEL0_LEAF_SIZE /* level->leaf_size */,
							      slot_array[i].index),
						slot_array[i].bitmap) < 40);
		assert(slot_array[i].key_category == BIG_INLOG || slot_array[i].key_category == MEDIUM_INLOG ||
		       slot_array[i].key_category == SMALL_INPLACE);
	}
}
#endif

struct bt_dynamic_leaf_slot_array *get_slot_array_offset(const struct bt_dynamic_leaf_node *leaf)
{
	return (struct bt_dynamic_leaf_slot_array *)(((char *)leaf) + sizeof(struct bt_dynamic_leaf_node));
}

char *get_leaf_log_offset(const struct bt_dynamic_leaf_node *leaf, const uint32_t leaf_size)
{
	return (((char *)leaf) + leaf_size - leaf->header.leaf_log_size);
}

char *get_kv_offset(const struct bt_dynamic_leaf_node *leaf, const uint32_t leaf_size, const uint32_t kv_offset)
{
	return (((char *)leaf) + leaf_size - kv_offset);
}

void fill_prefix(struct prefix *key, char *key_loc, enum kv_entry_location key_type)
{
	switch (key_type) {
	case KV_INPLACE: {
		struct splice *key_buf = (struct splice *)key_loc;
		key->prefix = key_buf->data;
		key->len = MIN(key_buf->size, PREFIX_SIZE);
		break;
	}
	case KV_INLOG:
		key->prefix = ((struct bt_leaf_entry *)key_loc)
				      ->prefix; //((*(uint64_t*) key_loc) + MAPPED) + 4 /* + sizeof(uint64_t) */;
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
	case KV_INLOG: {
		struct bt_leaf_entry *kv = (struct bt_leaf_entry *)key_loc;
		return (char *)REAL_ADDRESS(kv->pointer);
	}
	default:
		assert(0);
		log_fatal("UNKNOWN KEY TYPE");
		exit(EXIT_FAILURE);
	}
}

struct find_result find_key_in_dynamic_leaf(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size, void *key,
					    uint32_t key_size, int level_id)
{
	bt_insert_req req;
	char *buf = malloc(key_size + sizeof(uint32_t));
	struct dl_bsearch_result result = { .middle = 0, .status = INSERT, .op = DYNAMIC_LEAF_FIND };
	struct find_result ret_result = { .kv = NULL, .key_type = KV_INPLACE };
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	assert(buf != NULL);
	SERIALIZE_KEY(buf, key, key_size);

	req.key_value_buf = buf;
	req.metadata.key_format = KV_FORMAT;
	req.metadata.level_id = level_id;
	//validate_dynamic_leaf((void *) leaf, NULL, 0, 0);
	binary_search_dynamic_leaf(leaf, leaf_size, &req, &result);

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
	}

	free(buf);
	return ret_result;
}

void binary_search_dynamic_leaf(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size, bt_insert_req *req,
				struct dl_bsearch_result *result)
{
	struct prefix leaf_key_prefix;
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	char *leaf_key_buf;
	int32_t start = 0, middle = 0, end = leaf->header.num_entries - 1;
	const int32_t numberOfEntriesInNode = leaf->header.num_entries;
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

		char padded_prefix[PREFIX_SIZE];
		struct splice *key_buf = (struct splice *)get_kv_offset(leaf, leaf_size, offset_in_leaf);
		if (slot_array[middle].bitmap == KV_INPLACE && key_buf->size < PREFIX_SIZE) {
			memset(padded_prefix, 0x00, PREFIX_SIZE);
			memcpy(padded_prefix, key_buf->data, key_buf->size);
			leaf_key_prefix.prefix = padded_prefix;
			leaf_key_prefix.len = PREFIX_SIZE;
		} else {
			fill_prefix(&leaf_key_prefix, get_kv_offset(leaf, leaf_size, offset_in_leaf),
				    slot_array[middle].bitmap);
		}
		if (req->metadata.key_format == KV_PREFIX) {
			ret = prefix_compare(leaf_key_prefix.prefix, req->key_value_buf,
					     PREFIX_SIZE /* MIN(leaf_key_prefix.len, key_buf->size) */
			);
		} else {
			if (*(uint32_t *)req->key_value_buf < PREFIX_SIZE) {
				char padded_qkey_prefix[PREFIX_SIZE];
				memset(padded_qkey_prefix, 0x0, PREFIX_SIZE);
				memcpy(padded_qkey_prefix, req->key_value_buf + sizeof(uint32_t),
				       *(uint32_t *)req->key_value_buf);
				ret = prefix_compare(leaf_key_prefix.prefix, padded_qkey_prefix, PREFIX_SIZE);
			} else
				ret = prefix_compare(leaf_key_prefix.prefix, req->key_value_buf + 4,
						     PREFIX_SIZE /*MIN(leaf_key_prefix.len, key_buf->size)*/);
		}

		/* log_info("%d %*s %*s",ret
     * ,PREFIX_SIZE,leaf_key_prefix.prefix,PREFIX_SIZE,req->key_value_buf+4); */

		ret_case = ret < 0 ? LESS_THAN_ZERO : ret > 0 ? GREATER_THAN_ZERO : EQUAL_TO_ZERO;

		if (ret_case == EQUAL_TO_ZERO) {
			char *kv_offset = get_kv_offset(leaf, leaf_size, offset_in_leaf);
			leaf_key_buf = fill_keybuf(kv_offset, slot_array[middle].bitmap);
			if (req->metadata.key_format == KV_PREFIX) {
				struct bt_leaf_entry *kv_entry = (struct bt_leaf_entry *)req->key_value_buf;
				ret = key_cmp(leaf_key_buf, (void *)kv_entry->pointer, KV_FORMAT, KV_FORMAT);
			} else {
				ret = key_cmp(leaf_key_buf, req->key_value_buf, KV_FORMAT, KV_FORMAT);
			}

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
				return;
			}

			break;
		case GREATER_THAN_ZERO:
			end = middle - 1;

			if (start > end) {
				result->middle = middle;
				result->status = INSERT;
				return;
			}

			break;
		}
	}
}

#if 0
void print_all_keys(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size)
{
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	/* log_info("number of entries %d", leaf->header.num_entries); */
	assert(leaf->header.num_entries < 500);
	for (unsigned i = 0; i < leaf->header.num_entries; ++i) {
		char *key = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[i].index), slot_array[i].bitmap);
		assert(KEY_SIZE(key) < 30);
		/* log_info("offset in leaf %d ADDR %llu Size%d key %s\n", slot_array[i].index, get_kv_offset(leaf, leaf_size, slot_array[i].index),KEY_SIZE(key), key + 4); */
	}
	/* log_info("--------------------------------------------"); */
}
#endif

void print_dynamic_leaf(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size)
{
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	log_info("1--------------------------------------------");

	/* log_info("number of entries %d", leaf->header.num_entries); */
	for (unsigned i = 0; i < leaf->header.num_entries; ++i) {
		char *key = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[i].index), slot_array[i].bitmap);
		log_info("offset in leaf %d ADDR %llu Size%d key %s\n", slot_array[i].index,
			 get_kv_offset(leaf, leaf_size, slot_array[i].index), KEY_SIZE(key), key + 4);
	}
	log_info("2--------------------------------------------");
}

#ifdef DEBUG_DYNAMIC_LEAF
void check_sorted_dynamic_leaf(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size)
{
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);

	/* log_info("number of entries %d", leaf->header.num_entries); */
	for (unsigned i = 0; i < leaf->header.num_entries - 1; ++i) {
		char *key = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[i].index), slot_array[i].bitmap);
		char *key2 =
			fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[i + 1].index), slot_array[i + 1].bitmap);
		if (key_cmp(key, key2, KV_FORMAT, KV_FORMAT) > 0) {
			print_dynamic_leaf(leaf, leaf_size);
			assert(0);
		}

		/* log_info("offset in leaf %d ADDR %llu Size%d key %s\n", slot_array[i].index, get_kv_offset(leaf, leaf_size, slot_array[i].index),KEY_SIZE(key), key + 4); */
	}
}
#endif

static void shift_right_slot_array(struct bt_dynamic_leaf_node *leaf, uint32_t middle)
{
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	const size_t num_items = leaf->header.num_entries - middle;
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
	char padded_prefix[PREFIX_SIZE];
	if (prefix_size < PREFIX_SIZE) {
		memset(padded_prefix, 0x00, PREFIX_SIZE);
		memcpy(padded_prefix, prefix, prefix_size);
		prefix = padded_prefix;
		prefix_size = PREFIX_SIZE;
	}
	if (prefix_size)
		dest -= sizeof(pointer);
	*(uint64_t *)dest = pointer;
	dest -= prefix_size;
	memcpy(dest, prefix, prefix_size);
	/* log_info("dest %llu",dest); */
	/* log_info("ADDR %llu pointer %llu",dest,pointer); */
	/* memcpy(dest, &pointer, sizeof(pointer)); */
	/* log_info("%d %s %s",*(uint32_t*) (*(uint64_t*)dest + MAPPED),prefix,((char
   * *)(*(uint64_t*)dest + MAPPED) + 4)); */
	return prefix_size + sizeof(pointer);
}

int check_dynamic_leaf_split(struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size, uint32_t kv_size, int level_id,
			     enum kv_entry_location key_type, enum log_category cat)
{
	uint32_t leaf_log_size = leaf->header.leaf_log_size;
	uint32_t metadata_size = sizeof(struct bt_dynamic_leaf_node) +
				 (sizeof(struct bt_dynamic_leaf_slot_array) * (leaf->header.num_entries + 1));
	uint32_t upper_bound = leaf_size - metadata_size;

	/* log_info("1 leaf addr %llu leaf_log %d upper_bound %d",leaf,leaf_log_size,upper_bound); */
	if (cat == MEDIUM_INLOG && level_id == LEVEL_MEDIUM_INPLACE)
		key_type = KV_INPLACE;

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
	/* log_info("2 leaf addr %llu leaf_log %d upper_bound %d",leaf,leaf_log_size,upper_bound); */

	return !(leaf_log_size < upper_bound);
}

struct bt_rebalance_result split_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size, bt_insert_req *req)
{
	struct bt_rebalance_result rep;
	struct bt_dynamic_leaf_node *leaf_copy, *left_leaf, *right_leaf, *old_leaf = leaf;
	struct bt_dynamic_leaf_slot_array *slot_array, *right_leaf_slot_array, *left_leaf_slot_array;
	int level_id = req->metadata.level_id;
	char *split_buffer = malloc(leaf_size);
	char *key_buf, *leaf_log_tail;
	level_descriptor *level = &req->metadata.handle->db_desc->levels[level_id];
	volume_descriptor *volume_desc = req->metadata.handle->volume_desc;
	uint64_t i, j = 0;
	uint32_t key_buf_size;
	/*cow check*/
#ifdef DEBUG_DYNAMIC_LEAF
	validate_dynamic_leaf(leaf, level, 0, 0);
	check_sorted_dynamic_leaf(leaf, leaf_size);
#endif

	if (leaf->header.epoch <= volume_desc->dev_catalogue->epoch) {
		leaf_copy = seg_get_dynamic_leaf_node(volume_desc, level, req->metadata.tree_id);
		memcpy(leaf_copy, leaf, level->leaf_size);
		leaf_copy->header.epoch = volume_desc->mem_catalogue->epoch;
		leaf = leaf_copy;
		seg_free_leaf_node(volume_desc, level, req->metadata.tree_id, (leaf_node *)old_leaf);
	}

#ifdef DEBUG_DYNAMIC_LEAF
	validate_dynamic_leaf(leaf, level, 0, 0);
#endif

	memcpy(split_buffer, leaf, leaf_size);
	slot_array = get_slot_array_offset((struct bt_dynamic_leaf_node *)split_buffer);
	left_leaf = rep.left_dlchild = leaf;
	leaf = (struct bt_dynamic_leaf_node *)split_buffer;
	/*Fix left leaf metadata*/
	left_leaf->header.type = leafNode;
	left_leaf->header.epoch = volume_desc->mem_catalogue->epoch;
	left_leaf->header.num_entries = 0;
	left_leaf->header.fragmentation = 0;
	left_leaf->header.first_IN_log_header = NULL; /*unused field in leaves*/
	left_leaf->header.last_IN_log_header = NULL; /*unused field in leaves*/
	left_leaf->header.leaf_log_size = 0;
	left_leaf->header.height = 0;

	leaf_log_tail = get_leaf_log_offset(left_leaf, level->leaf_size);
	left_leaf_slot_array = get_slot_array_offset(left_leaf);
	for (i = 0, j = 0; i < leaf->header.num_entries / 2; ++i, ++j) {
		key_buf = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[i].index), slot_array[i].bitmap);
		if (slot_array[i].bitmap == KV_INPLACE) {
			uint32_t key_size = KEY_SIZE(key_buf);
			uint32_t value_size = VALUE_SIZE(key_buf + sizeof(uint32_t) + key_size);
			key_buf_size = 2 * sizeof(uint32_t) + key_size + value_size;
			left_leaf->header.leaf_log_size += key_buf_size;
			leaf_log_tail -= key_buf_size;
			memcpy(leaf_log_tail, key_buf, key_buf_size);
		} else if (slot_array[i].bitmap == KV_INLOG) {
			left_leaf->header.leaf_log_size += sizeof(struct bt_leaf_entry);
			leaf_log_tail -= sizeof(struct bt_leaf_entry);
			memcpy(leaf_log_tail, get_kv_offset(leaf, leaf_size, slot_array[i].index),
			       sizeof(struct bt_leaf_entry));
		}

		left_leaf_slot_array[j].index = left_leaf->header.leaf_log_size;
		left_leaf_slot_array[j].bitmap = slot_array[i].bitmap;
		left_leaf_slot_array[j].key_category = slot_array[i].key_category;
	}

	/*Fix Right leaf metadata*/
	rep.right_dlchild = seg_get_dynamic_leaf_node(volume_desc, level, req->metadata.tree_id);
	rep.middle_key_buf = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[leaf->header.num_entries / 2].index),
					 slot_array[leaf->header.num_entries / 2].bitmap);

	right_leaf = rep.right_dlchild;
	/*Copy pointers + prefixes*/
	leaf_log_tail = get_leaf_log_offset(right_leaf, leaf_size);
	right_leaf_slot_array = get_slot_array_offset(right_leaf);
	for (i = leaf->header.num_entries / 2, j = 0; i < leaf->header.num_entries; ++i, ++j) {
		key_buf = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[i].index), slot_array[i].bitmap);
		if (slot_array[i].bitmap == KV_INPLACE) {
			uint32_t key_size = KEY_SIZE(key_buf);
			uint32_t value_size = VALUE_SIZE(key_buf + sizeof(uint32_t) + key_size);
			key_buf_size = 2 * sizeof(uint32_t) + key_size + value_size;
			leaf_log_tail -= key_buf_size;
			right_leaf->header.leaf_log_size += key_buf_size;
			memcpy(leaf_log_tail, key_buf, key_buf_size);
		} else if (slot_array[i].bitmap == KV_INLOG) {
			right_leaf->header.leaf_log_size += sizeof(struct bt_leaf_entry);
			leaf_log_tail -= sizeof(struct bt_leaf_entry);
			memcpy(leaf_log_tail, get_kv_offset(leaf, leaf_size, slot_array[i].index),
			       sizeof(struct bt_leaf_entry));
		}

		right_leaf_slot_array[j].index = right_leaf->header.leaf_log_size;
		right_leaf_slot_array[j].bitmap = slot_array[i].bitmap;
		right_leaf_slot_array[j].key_category = slot_array[i].key_category;
	}

	rep.left_dlchild->header.height = leaf->header.height;
	rep.left_dlchild->header.num_entries = leaf->header.num_entries / 2;

	rep.right_dlchild->header.num_entries = leaf->header.num_entries - (leaf->header.num_entries / 2);
	rep.right_dlchild->header.type = leafNode;

#ifdef DEBUG_DYNAMIC_LEAF
	validate_dynamic_leaf(left_leaf, level, 0, 0);
	validate_dynamic_leaf(right_leaf, level, 0, 0);
	check_sorted_dynamic_leaf(left_leaf, leaf_size);
	check_sorted_dynamic_leaf(right_leaf, leaf_size);
#endif

	if (leaf->header.type == leafRootNode) {
		rep.left_dlchild->header.type = leafNode;
		rep.stat = LEAF_ROOT_NODE_SPLITTED;
	} else
		rep.stat = LEAF_NODE_SPLITTED;
#ifdef DEBUG_DYNAMIC_LEAF
	print_all_keys(left_leaf, leaf_size);
	print_all_keys(right_leaf, leaf_size);
#endif

	seg_free_leaf_node(volume_desc, level, req->metadata.tree_id, (leaf_node *)old_leaf);
	free(split_buffer);
	return rep;
}

struct bt_rebalance_result special_split_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size,
						      bt_insert_req *req)
{
	struct bt_rebalance_result rep;
	struct bt_dynamic_leaf_node *leaf_copy, *right_leaf, *old_leaf = leaf;
	struct bt_dynamic_leaf_slot_array *slot_array, *right_leaf_slot_array;
	int level_id = req->metadata.level_id;
	char *key_buf, *leaf_log_tail;
	level_descriptor *level = &req->metadata.handle->db_desc->levels[level_id];
	volume_descriptor *volume_desc = req->metadata.handle->volume_desc;
	uint64_t split_point;
	uint32_t key_buf_size;
	/*cow check*/

	if (leaf->header.epoch <= volume_desc->dev_catalogue->epoch) {
		leaf_copy = seg_get_dynamic_leaf_node(volume_desc, level, req->metadata.tree_id);
		memcpy(leaf_copy, leaf, level->leaf_size);
		leaf_copy->header.epoch = volume_desc->mem_catalogue->epoch;
		leaf = leaf_copy;
		seg_free_leaf_node(volume_desc, level, req->metadata.tree_id, (leaf_node *)old_leaf);
	}

	slot_array = get_slot_array_offset(leaf);
	rep.left_dlchild = leaf;

	split_point = leaf->header.num_entries - 1;
	/*Fix Right leaf metadata*/
	rep.right_dlchild = seg_get_dynamic_leaf_node(volume_desc, level, req->metadata.tree_id);
	rep.middle_key_buf = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[split_point].index),
					 slot_array[split_point].bitmap);

	right_leaf = rep.right_dlchild;
	/*Copy pointers + prefixes*/
	leaf_log_tail = get_leaf_log_offset(right_leaf, leaf_size);
	right_leaf_slot_array = get_slot_array_offset(right_leaf);

	key_buf = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[split_point].index),
			      slot_array[split_point].bitmap);

	if (slot_array[split_point].bitmap == KV_INPLACE) {
		uint32_t key_size = KEY_SIZE(key_buf);
		uint32_t value_size = VALUE_SIZE(key_buf + sizeof(uint32_t) + key_size);
		key_buf_size = 2 * sizeof(uint32_t) + key_size + value_size;
		leaf_log_tail -= key_buf_size;
		right_leaf->header.leaf_log_size += key_buf_size;
		memcpy(leaf_log_tail, key_buf, key_buf_size);
	} else if (slot_array[split_point].bitmap == KV_INLOG) {
		right_leaf->header.leaf_log_size += sizeof(struct bt_leaf_entry);
		leaf_log_tail -= sizeof(struct bt_leaf_entry);
		memcpy(leaf_log_tail, get_kv_offset(leaf, leaf_size, slot_array[split_point].index),
		       sizeof(struct bt_leaf_entry));
	}

	right_leaf_slot_array[0].index = right_leaf->header.leaf_log_size;
	right_leaf_slot_array[0].bitmap = slot_array[split_point].bitmap;
	right_leaf_slot_array[0].key_category = slot_array[split_point].key_category;

	rep.left_dlchild->header.height = leaf->header.height;
	rep.left_dlchild->header.num_entries = leaf->header.num_entries - 1;

	rep.right_dlchild->header.num_entries = 1;
	rep.right_dlchild->header.type = leafNode;

	if (leaf->header.type == leafRootNode) {
		rep.left_dlchild->header.type = leafNode;
		rep.stat = LEAF_ROOT_NODE_SPLITTED;
	} else
		rep.stat = LEAF_NODE_SPLITTED;

	seg_free_leaf_node(volume_desc, level, req->metadata.tree_id, (leaf_node *)old_leaf);
	return rep;
}

void write_data_in_dynamic_leaf(struct write_dynamic_leaf_args *args)
{
	struct bt_dynamic_leaf_node *leaf = args->leaf;
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(args->leaf);
	char *key_value_buf = args->key_value_buf;
	char *dest = args->dest;
	uint32_t key_value_size = args->key_value_size;
	int status = UNKNOWN_CATEGORY;
	int middle = args->middle;
	int kv_format = args->kv_format;
	struct bt_dynamic_leaf_slot_array slot;

	if (args->cat == BIG_INLOG || args->cat == MEDIUM_INLOG || args->cat == SMALL_INLOG)
		status = KV_INLOG;
	else
		status = KV_INPLACE;

	if (args->cat == MEDIUM_INLOG && args->level_id == LEVEL_MEDIUM_INPLACE) {
		status = KV_INPLACE;
		args->cat = MEDIUM_INPLACE;
	}

	if (status == KV_INPLACE) {
		slot.bitmap = KV_INPLACE;
		if (kv_format == KV_FORMAT)
			leaf->header.leaf_log_size += append_kv_inplace(dest, key_value_buf, key_value_size);
		else {
			char *pointer = (char *)(*(uint64_t *)(key_value_buf + PREFIX_SIZE));
			uint32_t key_size = *(uint32_t *)pointer;
			uint32_t value_size = *(uint32_t *)(pointer + 4 + key_size);
			leaf->header.leaf_log_size += append_kv_inplace(dest, pointer, 8 + key_size + value_size);
		}
	} else if (status == KV_INLOG) {
		struct splice *key = (struct splice *)key_value_buf;
		struct bt_leaf_entry *serialized = (struct bt_leaf_entry *)key_value_buf;
		slot.bitmap = KV_INLOG;
		if (kv_format == KV_FORMAT) {
			leaf->header.leaf_log_size +=
				append_bt_leaf_entry_inplace(dest, ABSOLUTE_ADDRESS(key_value_buf), key->data,
							     /* PREFIX_SIZE */ MIN(key->size, PREFIX_SIZE));
		} else {
			leaf->header.leaf_log_size +=
				append_bt_leaf_entry_inplace(dest, ABSOLUTE_ADDRESS(serialized->pointer), key_value_buf,
							     /* PREFIX_SIZE */ MIN(key->size, PREFIX_SIZE));
		}
		//Note There is a case where YCSB generates 11 bytes keys and we read invalid bytes from stack.
		//This should be fixed after Eurosys deadline.
	} else
		assert(0);

	slot.index = leaf->header.leaf_log_size;
	slot.key_category = args->cat;
	slot_array[middle] = slot;
}

int reorganize_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size, bt_insert_req *req)
{
	enum log_category cat = req->metadata.cat;
	unsigned kv_size = (cat == BIG_INLOG || cat == MEDIUM_INLOG || cat == SMALL_INLOG) ?
					 sizeof(struct bt_leaf_entry) :
					 req->metadata.kv_size;

	if (leaf->header.fragmentation <= kv_size || req->metadata.level_id != 0)
		return 0;

	struct bt_dynamic_leaf_node *reorganize_buffer = leaf;

	leaf = seg_get_dynamic_leaf_node(req->metadata.handle->volume_desc, &req->metadata.handle->db_desc->levels[0],
					 req->metadata.tree_id);

	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(reorganize_buffer);
	/* validate_dynamic_leaf(reorganize_buffer, &req->metadata.handle->db_desc->levels[req->metadata.level_id], */
	/* 		      req->metadata.kv_size, 0); */

	leaf->header.num_entries = 0;
	leaf->header.fragmentation = 0;
	leaf->header.leaf_log_size = 0;
	leaf->header.height = 0;
	leaf->header.type = reorganize_buffer->header.type;

	char *key_buf;
	unsigned key_buf_size;
	char *leaf_log_tail = get_leaf_log_offset(leaf, leaf_size);
	struct bt_dynamic_leaf_slot_array *leaf_slot_array = get_slot_array_offset(leaf);

	for (uint64_t i = 0; i < reorganize_buffer->header.num_entries; ++i) {
		key_buf = fill_keybuf(get_kv_offset(reorganize_buffer, leaf_size, slot_array[i].index),
				      slot_array[i].bitmap);
		if (slot_array[i].bitmap == KV_INPLACE) {
			uint32_t key_size = KEY_SIZE(key_buf);
			uint32_t value_size = VALUE_SIZE(key_buf + sizeof(uint32_t) + key_size);
			key_buf_size = (2 * sizeof(uint32_t)) + key_size + value_size;
			assert(slot_array[i].key_category == SMALL_INPLACE);
			leaf->header.leaf_log_size += key_buf_size;
			leaf_log_tail -= key_buf_size;
			memcpy(leaf_log_tail, key_buf, key_buf_size);
		} else if (slot_array[i].bitmap == KV_INLOG) {
			leaf->header.leaf_log_size += sizeof(struct bt_leaf_entry);
			leaf_log_tail -= sizeof(struct bt_leaf_entry);
			assert(slot_array[i].key_category != SMALL_INPLACE);
			memcpy(leaf_log_tail, get_kv_offset(reorganize_buffer, leaf_size, slot_array[i].index),
			       sizeof(struct bt_leaf_entry));
		}

		leaf_slot_array[i].index = leaf->header.leaf_log_size;
		leaf_slot_array[i].bitmap = slot_array[i].bitmap;
		leaf_slot_array[i].key_category = slot_array[i].key_category;
	}

	leaf->header.num_entries = reorganize_buffer->header.num_entries;
	/* validate_dynamic_leaf(leaf, &req->metadata.handle->db_desc->levels[req->metadata.level_id], */
	/* 		      req->metadata.kv_size, 0); */

	if (leaf->header.type == leafNode)
		*(req->metadata.reorganized_leaf_pos_INnode) = ABSOLUTE_ADDRESS(leaf);
	else if (leaf->header.type == leafRootNode) {
		req->metadata.handle->db_desc->levels[0].root_w[req->metadata.tree_id] = (node_header *)leaf;
		assert(leaf->header.fragmentation == 0);
	} else
		assert(0);

	assert(leaf->header.epoch > req->metadata.handle->volume_desc->dev_catalogue->epoch);
	return 1;
}

int8_t insert_in_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, bt_insert_req *req, level_descriptor *level)
{
	struct write_dynamic_leaf_args write_leaf_args = { .leaf = leaf,
							   .key_value_buf = req->key_value_buf,
							   .key_value_size = req->metadata.kv_size,
							   .level_id = level->level_id,
							   .kv_format = req->metadata.key_format,
							   .cat = req->metadata.cat };
	struct dl_bsearch_result bsearch = { .middle = 0, .status = INSERT, .op = DYNAMIC_LEAF_INSERT };
	char *leaf_log_tail = get_leaf_log_offset(leaf, level->leaf_size);

	assert(leaf->header.epoch > req->metadata.handle->volume_desc->dev_catalogue->epoch);

	if (unlikely(leaf->header.num_entries == 0))
		leaf->header.leaf_log_size = 0;

	binary_search_dynamic_leaf(leaf, level->leaf_size, req, &bsearch);

	write_leaf_args.dest = leaf_log_tail;
	write_leaf_args.middle = bsearch.middle;

#ifdef DEBUG_DYNAMIC_LEAF
	validate_dynamic_leaf(leaf, level, req->metadata.kv_size, 0);
#endif
	assert(leaf->header.leaf_log_size < LEVEL0_LEAF_SIZE);

	switch (bsearch.status) {
	case INSERT:
		shift_right_slot_array(leaf, bsearch.middle);
		if (write_leaf_args.cat == MEDIUM_INLOG && write_leaf_args.level_id == LEVEL_MEDIUM_INPLACE) {
			__sync_fetch_and_add(&req->metadata.handle->db_desc->count_medium_inplace, 1);
		}

		write_data_in_dynamic_leaf(&write_leaf_args);
		++leaf->header.num_entries;
		break;
	case FOUND:;

		struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);

		if (slot_array[bsearch.middle].key_category == BIG_INLOG ||
		    slot_array[bsearch.middle].key_category == MEDIUM_INLOG ||
		    slot_array[bsearch.middle].key_category == SMALL_INLOG)
			leaf->header.fragmentation += sizeof(struct bt_leaf_entry);
		else {
			char *kv = fill_keybuf(get_kv_offset(leaf, level->leaf_size, slot_array[bsearch.middle].index),
					       slot_array[bsearch.middle].bitmap);
			int key_size = *(uint32_t *)kv;
			int value_size = *(uint32_t *)(kv + 4 + key_size);
			int kv_size = key_size + value_size + 2 * sizeof(uint32_t);
			leaf->header.fragmentation += kv_size;
		}
		write_data_in_dynamic_leaf(&write_leaf_args);
		break;
	default:
		log_fatal("ERROR in insert path%d", bsearch.middle);
		exit(EXIT_FAILURE);
	}

#ifdef DEBUG_DYNAMIC_LEAF
	validate_dynamic_leaf(leaf, level, 0, 1);
	check_sorted_dynamic_leaf(leaf, level->leaf_size);
#endif
	assert(leaf->header.leaf_log_size < LEVEL0_LEAF_SIZE);
	//validate_dynamic_leaf(leaf, level, 0, 1);

	return bsearch.status;
}

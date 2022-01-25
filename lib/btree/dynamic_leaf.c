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

#include "dynamic_leaf.h"
#include "conf.h"
#include "segment_allocator.h"
#include <assert.h>
#include <log.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void print_all_keys(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size);
char *fill_keybuf(char *key_loc, enum kv_entry_location key_type);

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

void print_slot_array(struct bt_dynamic_leaf_slot_array *slot_array, int i)
{
	log_info("slot array index %d offset %d category %d bitmap %d", i, slot_array[i].index,
		 slot_array[i].key_category, slot_array[i].kv_loc);
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
		key->prefix = ((struct bt_leaf_entry *)key_loc)->prefix;
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

struct find_result find_key_in_dynamic_leaf(const struct bt_dynamic_leaf_node *leaf, db_descriptor *db_desc, void *key,
					    uint32_t key_size, int level_id)
{
	bt_insert_req req;
	char buf[MAX_KEY_SIZE + sizeof(uint32_t)];
	struct dl_bsearch_result result = { .middle = 0, .status = INSERT, .op = DYNAMIC_LEAF_FIND, .debug = 0 };
	struct find_result ret_result = { .kv = NULL, .key_type = KV_INPLACE, .kv_category = UNKNOWN_LOG_CATEGORY };
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	db_handle handle = { .db_desc = db_desc, .volume_desc = NULL };
	uint32_t leaf_size = db_desc->levels[level_id].leaf_size;

	assert(buf != NULL);
	SERIALIZE_KEY(buf, key, key_size);

	memset(&req, 0x00, sizeof(req));
	req.key_value_buf = buf;
	req.metadata.key_format = KV_FORMAT;
	req.metadata.level_id = level_id;
	req.metadata.handle = &handle;
	//validate_dynamic_leaf((void *) leaf, NULL, 0, 0);
	req.translate_medium_log = 0;
	binary_search_dynamic_leaf(leaf, leaf_size, &req, &result);

	/* if(result.status != FOUND){ */
	/* 	result.middle = 0; */
	/* 	result.status = INSERT; */
	/* 	result.op = DYNAMIC_LEAF_FIND; */
	/* 	result.debug = 1; */
	/* 	binary_search_dynamic_leaf(leaf, leaf_size, &req, &result); */

	/* } */
	ret_result.tombstone = result.tombstone;

	switch (result.status) {
	case FOUND:
		switch (slot_array[result.middle].kv_loc) {
		case KV_INPLACE:
			ret_result.kv = (void *)ABSOLUTE_ADDRESS(
				get_kv_offset(leaf, leaf_size, slot_array[result.middle].index));
			ret_result.key_type = KV_INPLACE;
			ret_result.kv_category = slot_array[result.middle].key_category;
			break;
		case KV_INLOG:
			ret_result.kv = (char *)&((struct bt_leaf_entry *)get_kv_offset(
							  leaf, leaf_size, slot_array[result.middle].index))
						->pointer;
			ret_result.key_type = KV_INLOG;
			ret_result.kv_category = slot_array[result.middle].key_category;
			break;
		default:
			assert(0);
		}
		break;
	default:
		break;
	}

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
	uint32_t kv_size_in_leaf;

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
		if (slot_array[middle].kv_loc == KV_INPLACE && key_buf->size < PREFIX_SIZE) {
			memset(padded_prefix, 0x00, PREFIX_SIZE);
			memcpy(padded_prefix, key_buf->data, key_buf->size);
			leaf_key_prefix.prefix = padded_prefix;
			leaf_key_prefix.len = PREFIX_SIZE;
		} else {
			fill_prefix(&leaf_key_prefix, get_kv_offset(leaf, leaf_size, offset_in_leaf),
				    slot_array[middle].kv_loc);
		}

		if (req->metadata.key_format == KV_PREFIX) {
			ret = prefix_compare(leaf_key_prefix.prefix, req->key_value_buf, PREFIX_SIZE);

		} else {
			if (*(uint32_t *)req->key_value_buf < PREFIX_SIZE) {
				kv_size_in_leaf = strlen(leaf_key_prefix.prefix) + 1;
				/* if the size of keys is equal don't compare there padded part
				 *this fixes corner case where parallax compares same keys but one is padded
				 */
				if (kv_size_in_leaf == *(uint32_t *)req->key_value_buf)
					ret = prefix_compare(leaf_key_prefix.prefix,
							     req->key_value_buf + sizeof(uint32_t), kv_size_in_leaf);
				else {
					char padded_qkey_prefix[PREFIX_SIZE];
					memset(padded_qkey_prefix, 0x0, PREFIX_SIZE);
					memcpy(padded_qkey_prefix, req->key_value_buf + sizeof(uint32_t),
					       *(uint32_t *)req->key_value_buf);
					ret = prefix_compare(leaf_key_prefix.prefix, padded_qkey_prefix, PREFIX_SIZE);
				}
			} else {
				if (result->debug == 1)
					log_debug("%s %s", leaf_key_prefix.prefix, req->key_value_buf + 4);

				ret = prefix_compare(leaf_key_prefix.prefix, req->key_value_buf + 4, PREFIX_SIZE);
			}
		}

		ret_case = ret < 0 ? LESS_THAN_ZERO : ret > 0 ? GREATER_THAN_ZERO : EQUAL_TO_ZERO;
		struct bt_kv_log_address L = { .addr = NULL, .in_tail = 0, .tail_id = UINT8_MAX };

		if (ret_case == EQUAL_TO_ZERO) {
			char *kv_offset = get_kv_offset(leaf, leaf_size, offset_in_leaf);

			leaf_key_buf = fill_keybuf(kv_offset, slot_array[middle].kv_loc);
			switch (slot_array[middle].key_category) {
#if MEDIUM_LOG_UNSORTED
			case MEDIUM_INLOG:
				if (req->metadata.level_id)
					L.addr = (void *)leaf_key_buf;
				else
					L = bt_get_kv_log_address(&req->metadata.handle->db_desc->medium_log,
								  ABSOLUTE_ADDRESS(leaf_key_buf));
				L.log_desc = &req->metadata.handle->db_desc->medium_log;
				break;
#endif
				//Stub for big log direct IO, this function is called now
				//only in L0
			case BIG_INLOG:
				if (req->metadata.level_id)
					L.addr = (void *)leaf_key_buf;
				else
					L = bt_get_kv_log_address(&req->metadata.handle->db_desc->big_log,
								  ABSOLUTE_ADDRESS(leaf_key_buf));
				L.log_desc = &req->metadata.handle->db_desc->big_log;

				break;
			default:
				L.addr = leaf_key_buf;
				break;
			}

			switch (req->metadata.key_format) {
			case KV_PREFIX: {
				struct bt_leaf_entry *kv_entry = (struct bt_leaf_entry *)req->key_value_buf;
				ret = key_cmp(L.addr, (void *)kv_entry->pointer, KV_FORMAT, KV_FORMAT);
				break;
			}
			case KV_FORMAT:

				//log_info("Comparing index key %u:%s with query key :%u:%s", *(uint32_t *)L.addr,
				//	 L.addr + 4, *(uint32_t *)req->key_value_buf, req->key_value_buf + 4);
				ret = key_cmp(L.addr, req->key_value_buf, KV_FORMAT, KV_FORMAT);
				break;
			default:
				log_fatal("Corrupted key type");
				exit(EXIT_FAILURE);
			}

			if (L.in_tail)
				bt_done_with_value_log_address(L.log_desc, &L);

			if (ret == 0) {
				result->middle = middle;
				result->status = FOUND;
				result->tombstone = slot_array[middle].tombstone;
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

#ifdef DEBUG_DYNAMIC_LEAF
void print_all_keys(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size)
{
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	/* log_info("number of entries %d", leaf->header.num_entries); */
	assert(leaf->header.num_entries < 500);
	for (unsigned i = 0; i < leaf->header.num_entries; ++i) {
		char *key = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[i].index), slot_array[i].kv_loc);
		assert(KEY_SIZE(key) < 30);
		log_debug("Key %*s", KEY_SIZE(key), key + 4);
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
		char *key = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[i].index), slot_array[i].kv_loc);
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

	return prefix_size + sizeof(pointer);
}

int is_dynamic_leaf_full(struct split_level_leaf split_metadata)
{
	uint32_t leaf_log_size = split_metadata.leaf->header.leaf_log_size;
	uint32_t metadata_size = sizeof(struct bt_dynamic_leaf_node) + (sizeof(struct bt_dynamic_leaf_slot_array) *
									(split_metadata.leaf->header.num_entries + 1));
	uint32_t upper_bound = split_metadata.leaf_size - metadata_size;

	/* log_info("1 leaf addr %llu leaf_log %d upper_bound %d",leaf,leaf_log_size,upper_bound); */
	if (split_metadata.cat == MEDIUM_INLOG && split_metadata.level_id == split_metadata.level_medium_inplace)
		split_metadata.key_type = KV_INPLACE;

	switch (split_metadata.key_type) {
	case KV_INPLACE:
		leaf_log_size += split_metadata.kv_size;
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
	struct bt_dynamic_leaf_node *left_leaf, *right_leaf, *old_leaf = leaf;
	struct bt_dynamic_leaf_slot_array *slot_array, *right_leaf_slot_array, *left_leaf_slot_array;
	int level_id = req->metadata.level_id;
	char *split_buffer = malloc(leaf_size);
	char *key_buf, *leaf_log_tail, *middle_key_buf = NULL;
	level_descriptor *level = &req->metadata.handle->db_desc->levels[level_id];
	struct db_descriptor *db_desc = req->metadata.handle->db_desc;
	uint64_t i, j = 0;
	uint32_t key_buf_size;
	/*cow check*/
#ifdef DEBUG_DYNAMIC_LEAF
	validate_dynamic_leaf(leaf, level, 0, 0);
	check_sorted_dynamic_leaf(leaf, leaf_size);
#endif

	memcpy(split_buffer, leaf, leaf_size);
	slot_array = get_slot_array_offset((struct bt_dynamic_leaf_node *)split_buffer);
	left_leaf = rep.left_dlchild = leaf;
	leaf = (struct bt_dynamic_leaf_node *)split_buffer;
	/*Fix left leaf metadata*/
	left_leaf->header.type = leafNode;
	left_leaf->header.num_entries = 0;
	left_leaf->header.fragmentation = 0;
	left_leaf->header.first_IN_log_header = NULL; /*unused field in leaves*/
	left_leaf->header.last_IN_log_header = NULL; /*unused field in leaves*/
	left_leaf->header.leaf_log_size = 0;
	left_leaf->header.height = 0;

	leaf_log_tail = get_leaf_log_offset(left_leaf, level->leaf_size);
	left_leaf_slot_array = get_slot_array_offset(left_leaf);
	for (i = 0, j = 0; i < leaf->header.num_entries / 2; ++i, ++j) {
		key_buf = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[i].index), slot_array[i].kv_loc);
		if (slot_array[i].kv_loc == KV_INPLACE) {
			uint32_t key_size = KEY_SIZE(key_buf);
			uint32_t value_size = VALUE_SIZE(key_buf + sizeof(uint32_t) + key_size);
			key_buf_size = 2 * sizeof(uint32_t) + key_size + value_size;
			left_leaf->header.leaf_log_size += key_buf_size;
			leaf_log_tail -= key_buf_size;
			memcpy(leaf_log_tail, key_buf, key_buf_size);
		} else if (slot_array[i].kv_loc == KV_INLOG) {
			left_leaf->header.leaf_log_size += sizeof(struct bt_leaf_entry);
			leaf_log_tail -= sizeof(struct bt_leaf_entry);
			memcpy(leaf_log_tail, get_kv_offset(leaf, leaf_size, slot_array[i].index),
			       sizeof(struct bt_leaf_entry));
		}

		left_leaf_slot_array[j].index = left_leaf->header.leaf_log_size;
		left_leaf_slot_array[j].kv_loc = slot_array[i].kv_loc;
		left_leaf_slot_array[j].key_category = slot_array[i].key_category;
		left_leaf_slot_array[j].tombstone = slot_array[i].tombstone;
	}

	/*Fix Right leaf metadata*/
	rep.right_dlchild = seg_get_dynamic_leaf_node(db_desc, level_id, req->metadata.tree_id);
	middle_key_buf = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[leaf->header.num_entries / 2].index),
				     slot_array[leaf->header.num_entries / 2].kv_loc);

	//Stub for big log direct IO, this function is called na/now
	//only in L0
	struct bt_kv_log_address L = { .addr = NULL, .in_tail = 0, .tail_id = UINT8_MAX };
	switch (slot_array[leaf->header.num_entries / 2].key_category) {
#if MEDIUM_LOG_UNSORTED
	case MEDIUM_INLOG:
		L = bt_get_kv_log_address(&req->metadata.handle->db_desc->medium_log, ABSOLUTE_ADDRESS(middle_key_buf));
		//log_info("Pivot is %u:%s",*(uint32_t*)L.addr,L.addr+4);
		assert(*(uint32_t *)L.addr < 25);
		break;
#endif
	case BIG_INLOG:
		L = bt_get_kv_log_address(&req->metadata.handle->db_desc->big_log, ABSOLUTE_ADDRESS(middle_key_buf));
		break;
	default:
		L.addr = middle_key_buf;
		break;
	}

	uint32_t key_size = KEY_SIZE(L.addr);
	memcpy(rep.middle_key + sizeof(key_size), L.addr + sizeof(key_size), key_size);
	*(uint32_t *)rep.middle_key = key_size;
	assert(key_size + sizeof(key_size) < sizeof(rep.middle_key));

	if (L.in_tail) {
		struct log_descriptor *log_desc = NULL;
		//#if MEDIUM_LOG_UNSORTED
		switch (slot_array[leaf->header.num_entries / 2].key_category) {
		case BIG_INLOG:
			log_desc = &req->metadata.handle->db_desc->big_log;
			break;
		case MEDIUM_INLOG:
			log_desc = &req->metadata.handle->db_desc->medium_log;
			break;
		default:
			log_fatal("Unhandled case");
			exit(EXIT_FAILURE);
			//#endif
		}
		bt_done_with_value_log_address(log_desc, &L);
	}
	//Stub end

	right_leaf = rep.right_dlchild;
	/*Copy pointers + prefixes*/
	leaf_log_tail = get_leaf_log_offset(right_leaf, leaf_size);
	right_leaf_slot_array = get_slot_array_offset(right_leaf);
	for (i = leaf->header.num_entries / 2, j = 0; i < leaf->header.num_entries; ++i, ++j) {
		key_buf = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[i].index), slot_array[i].kv_loc);
		if (slot_array[i].kv_loc == KV_INPLACE) {
			key_size = KEY_SIZE(key_buf);
			uint32_t value_size = VALUE_SIZE(key_buf + sizeof(uint32_t) + key_size);
			key_buf_size = 2 * sizeof(uint32_t) + key_size + value_size;
			leaf_log_tail -= key_buf_size;
			right_leaf->header.leaf_log_size += key_buf_size;
			memcpy(leaf_log_tail, key_buf, key_buf_size);
		} else if (slot_array[i].kv_loc == KV_INLOG) {
			right_leaf->header.leaf_log_size += sizeof(struct bt_leaf_entry);
			leaf_log_tail -= sizeof(struct bt_leaf_entry);
			memcpy(leaf_log_tail, get_kv_offset(leaf, leaf_size, slot_array[i].index),
			       sizeof(struct bt_leaf_entry));
		}

		right_leaf_slot_array[j].index = right_leaf->header.leaf_log_size;
		right_leaf_slot_array[j].kv_loc = slot_array[i].kv_loc;
		right_leaf_slot_array[j].key_category = slot_array[i].key_category;
		right_leaf_slot_array[j].tombstone = slot_array[i].tombstone;
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
	log_debug("left leaf");
	print_all_keys(left_leaf, leaf_size);
	log_debug("right leaf");
	print_all_keys(right_leaf, leaf_size);
#endif

	seg_free_leaf_node(db_desc, level_id, req->metadata.tree_id, (leaf_node *)old_leaf);
	free(split_buffer);

	return rep;
}

struct bt_rebalance_result special_split_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size,
						      bt_insert_req *req)
{
	struct bt_rebalance_result rep;
	struct bt_dynamic_leaf_node *right_leaf, *old_leaf = leaf;
	struct bt_dynamic_leaf_slot_array *slot_array, *right_leaf_slot_array;
	int level_id = req->metadata.level_id;
	char *key_buf, *leaf_log_tail, *middle_key_buf = NULL;
	struct db_descriptor *db_desc = req->metadata.handle->db_desc;
	uint64_t split_point;
	uint32_t key_buf_size;
	/*cow check*/

	slot_array = get_slot_array_offset(leaf);
	rep.left_dlchild = leaf;

	split_point = leaf->header.num_entries - 1;
	/*Fix Right leaf metadata*/
	rep.right_dlchild = seg_get_dynamic_leaf_node(db_desc, level_id, req->metadata.tree_id);

	char *key_loc = get_kv_offset(leaf, leaf_size, slot_array[split_point].index);
	//medium log tail stub
	if (req->metadata.level_id == 1 && slot_array[split_point].key_category == MEDIUM_INLOG) {
		struct bt_leaf_entry *kv = (struct bt_leaf_entry *)key_loc;

		struct bt_kv_log_address L =
			bt_get_kv_medium_log_address(&req->metadata.handle->db_desc->medium_log, kv->pointer);
		middle_key_buf = L.addr;
	} else {
		middle_key_buf = fill_keybuf(key_loc, slot_array[split_point].kv_loc);
	}
	assert(KEY_SIZE(middle_key_buf) < 40);

	KEY_SIZE(rep.middle_key) = KEY_SIZE(middle_key_buf);
	memcpy(&rep.middle_key[4], middle_key_buf + 4, KEY_SIZE(rep.middle_key));

	right_leaf = rep.right_dlchild;
	/*Copy pointers + prefixes*/
	leaf_log_tail = get_leaf_log_offset(right_leaf, leaf_size);
	right_leaf_slot_array = get_slot_array_offset(right_leaf);

	key_buf = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[split_point].index),
			      slot_array[split_point].kv_loc);

	if (slot_array[split_point].kv_loc == KV_INPLACE) {
		uint32_t key_size = KEY_SIZE(key_buf);
		uint32_t value_size = VALUE_SIZE(key_buf + sizeof(uint32_t) + key_size);
		key_buf_size = 2 * sizeof(uint32_t) + key_size + value_size;
		leaf_log_tail -= key_buf_size;
		right_leaf->header.leaf_log_size += key_buf_size;
		memcpy(leaf_log_tail, key_buf, key_buf_size);
	} else if (slot_array[split_point].kv_loc == KV_INLOG) {
		right_leaf->header.leaf_log_size += sizeof(struct bt_leaf_entry);
		leaf_log_tail -= sizeof(struct bt_leaf_entry);
		memcpy(leaf_log_tail, get_kv_offset(leaf, leaf_size, slot_array[split_point].index),
		       sizeof(struct bt_leaf_entry));
	}

	right_leaf_slot_array[0].index = right_leaf->header.leaf_log_size;
	right_leaf_slot_array[0].kv_loc = slot_array[split_point].kv_loc;
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

	seg_free_leaf_node(db_desc, level_id, req->metadata.tree_id, (leaf_node *)old_leaf);
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

	if (args->cat == MEDIUM_INLOG && args->level_id == args->level_medium_inplace) {
		status = KV_INPLACE;
		args->cat = MEDIUM_INPLACE;
		assert(args->kv_format == KV_PREFIX);
	}

	if (status == KV_INPLACE) {
		slot.kv_loc = KV_INPLACE;
		if (kv_format == KV_FORMAT) {
			leaf->header.leaf_log_size += append_kv_inplace(dest, key_value_buf, key_value_size);
		} else {
			char *pointer = key_value_buf;
			uint32_t key_size = KEY_SIZE(pointer);
			uint32_t value_size = VALUE_SIZE(pointer + key_size + sizeof(uint32_t));
			//log_info("Toumpa time Key is %u:%s value size %u",key_size,pointer+4,value_size);
			leaf->header.leaf_log_size += append_kv_inplace(dest, pointer, 8 + key_size + value_size);
		}
	} else if (status == KV_INLOG) {
		struct splice *key = (struct splice *)key_value_buf;
		struct bt_leaf_entry *serialized = (struct bt_leaf_entry *)key_value_buf;
		slot.kv_loc = KV_INLOG;
		if (args->level_id == 0 && args->cat == BIG_INLOG && kv_format == KV_FORMAT) {
			assert(args->kv_dev_offt != 0);
			leaf->header.leaf_log_size += append_bt_leaf_entry_inplace(dest, args->kv_dev_offt, key->data,
										   MIN(key->size, PREFIX_SIZE));
		}
#if MEDIUM_LOG_UNSORTED
		else if (args->level_id == 0 && args->cat == MEDIUM_INLOG && kv_format == KV_FORMAT) {
			assert(args->kv_dev_offt != 0);
			leaf->header.leaf_log_size += append_bt_leaf_entry_inplace(dest, args->kv_dev_offt, key->data,
										   MIN(key->size, PREFIX_SIZE));
		}
#endif
		else {
			if (kv_format == KV_FORMAT) {
				leaf->header.leaf_log_size += append_bt_leaf_entry_inplace(
					dest, ABSOLUTE_ADDRESS(key_value_buf), key->data, MIN(key->size, PREFIX_SIZE));
			} else {
				leaf->header.leaf_log_size +=
					append_bt_leaf_entry_inplace(dest, ABSOLUTE_ADDRESS(serialized->pointer),
								     key_value_buf, MIN(key->size, PREFIX_SIZE));
			}
		}
	} else
		assert(0);

	slot.index = leaf->header.leaf_log_size;
	slot.key_category = args->cat;
	slot.tombstone = args->tombstone;
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

	leaf = seg_get_dynamic_leaf_node(req->metadata.handle->db_desc, 0, req->metadata.tree_id);

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
				      slot_array[i].kv_loc);
		if (slot_array[i].kv_loc == KV_INPLACE) {
			uint32_t key_size = KEY_SIZE(key_buf);
			uint32_t value_size = VALUE_SIZE(key_buf + sizeof(uint32_t) + key_size);
			key_buf_size = (2 * sizeof(uint32_t)) + key_size + value_size;
			assert(slot_array[i].key_category == SMALL_INPLACE ||
			       slot_array[i].key_category == MEDIUM_INPLACE);
			leaf->header.leaf_log_size += key_buf_size;
			leaf_log_tail -= key_buf_size;
			memcpy(leaf_log_tail, key_buf, key_buf_size);
		} else if (slot_array[i].kv_loc == KV_INLOG) {
			leaf->header.leaf_log_size += sizeof(struct bt_leaf_entry);
			leaf_log_tail -= sizeof(struct bt_leaf_entry);
			assert(slot_array[i].key_category != SMALL_INPLACE &&
			       slot_array[i].key_category != MEDIUM_INPLACE);
			memcpy(leaf_log_tail, get_kv_offset(reorganize_buffer, leaf_size, slot_array[i].index),
			       sizeof(struct bt_leaf_entry));
		}

		leaf_slot_array[i].index = leaf->header.leaf_log_size;
		leaf_slot_array[i].kv_loc = slot_array[i].kv_loc;
		leaf_slot_array[i].key_category = slot_array[i].key_category;
		leaf_slot_array[i].tombstone = slot_array[i].tombstone;
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

	return 1;
}

int8_t insert_in_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, bt_insert_req *req, level_descriptor *level)
{
	struct write_dynamic_leaf_args write_leaf_args = { .leaf = leaf,
							   .key_value_buf = req->key_value_buf,
							   .kv_dev_offt = req->kv_dev_offt,
							   .key_value_size = req->metadata.kv_size,
							   .level_id = level->level_id,
							   .kv_format = req->metadata.key_format,
							   .level_medium_inplace =
								   req->metadata.handle->db_desc->level_medium_inplace,
							   .cat = req->metadata.cat,
							   .tombstone = req->metadata.tombstone };
	struct dl_bsearch_result bsearch = { .middle = 0, .status = INSERT, .op = DYNAMIC_LEAF_INSERT, .debug = 0 };
	char *leaf_log_tail = get_leaf_log_offset(leaf, level->leaf_size);

	if (unlikely(leaf->header.num_entries == 0))
		leaf->header.leaf_log_size = 0;
	req->translate_medium_log = 1;
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
#if MEASURE_MEDIUM_INPLACE
		if (write_leaf_args.cat == MEDIUM_INLOG && write_leaf_args.level_id == LEVEL_MEDIUM_INPLACE) {
			__sync_fetch_and_add(&req->metadata.handle->db_desc->count_medium_inplace, 1);
		}
#endif

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
					       slot_array[bsearch.middle].kv_loc);
			if (kv == NULL) {
				log_fatal("Encountered NULL kv in leaf");
				assert(0);
				exit(EXIT_FAILURE);
			}

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

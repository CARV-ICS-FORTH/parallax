// Copyright [1] [FORTH-ICS]
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
#include "../btree/kv_pairs.h"
#include "../common/common.h"
#include "btree.h"
#include "btree_node.h"
#include "key_splice.h"
#include "parallax/structures.h"
#include "segment_allocator.h"
#include <assert.h>
#include <log.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool dl_check_leaf(struct bt_dynamic_leaf_node *leaf);
void print_all_keys(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size);

enum kv_entry_location get_kv_format(enum kv_category cat)
{
	switch (cat) {
	case SMALL_INPLACE:
	case MEDIUM_INPLACE:
		return KV_INPLACE;
	case MEDIUM_INLOG:
	case BIG_INLOG:
		return KV_INLOG;
	default:
		BUG_ON();
	}
}

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
		struct kv_splice *key_buf = (struct kv_splice *)key_loc;
		key->prefix = key_buf->data;
		key->len = MIN(key_buf->key_size, PREFIX_SIZE);
		break;
	}
	case KV_INLOG:
		key->prefix = ((struct kv_seperation_splice *)key_loc)->prefix;
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
		struct kv_seperation_splice *kv = (struct kv_seperation_splice *)key_loc;
		return (char *)REAL_ADDRESS(kv->dev_offt);
	}
	default:
		assert(0);
		log_fatal("UNKNOWN KEY TYPE");
		BUG_ON();
	}
}

struct find_result find_key_in_dynamic_leaf(const struct bt_dynamic_leaf_node *leaf, db_descriptor *db_desc, void *key,
					    uint32_t key_size, int level_id)
{
	bt_insert_req req;
	char buf[MAX_KEY_SIZE + sizeof(struct kv_splice)];
	struct dl_bsearch_result result = { .middle = 0, .status = INSERT, .op = DYNAMIC_LEAF_FIND };
	struct find_result ret_result = { .kv = NULL, .key_type = KV_INPLACE, .kv_category = BIG_INLOG, .tombstone = 0 };
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	db_handle handle = { .db_desc = db_desc, .volume_desc = NULL };
	uint32_t leaf_size = db_desc->levels[level_id].leaf_size;

	assert(buf != NULL);
	serialize_key(buf, key, key_size);

	memset(&req, 0x00, sizeof(req));
	req.key_value_buf = buf;
	req.metadata.key_format = KV_FORMAT;
	req.metadata.level_id = level_id;
	req.metadata.handle = &handle;
	//validate_dynamic_leaf((void *) leaf, NULL, 0, 0);
	binary_search_dynamic_leaf(leaf, leaf_size, &req, &result);

	ret_result.tombstone = result.tombstone;

	switch (result.status) {
	case FOUND:
		switch (get_kv_format(slot_array[result.middle].key_category)) {
		case KV_INPLACE:
			ret_result.kv = (void *)ABSOLUTE_ADDRESS(
				get_kv_offset(leaf, leaf_size, slot_array[result.middle].index));
			ret_result.key_type = KV_INPLACE;
			ret_result.kv_category = slot_array[result.middle].key_category;
			break;
		case KV_INLOG:
			ret_result.kv = (char *)&((struct kv_seperation_splice *)get_kv_offset(
							  leaf, leaf_size, slot_array[result.middle].index))
						->dev_offt;
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
	char *leaf_key_buf = NULL;
	int32_t start = 0, end = leaf->header.num_entries - 1;
	const int32_t numberOfEntriesInNode = leaf->header.num_entries;
	uint32_t offset_in_leaf;
	int ret, ret_case;
	struct key_compare key1_cmp, key2_cmp;

	while (numberOfEntriesInNode > 0) {
		int32_t middle = (start + end) / 2;
		if (middle < 0 || middle >= numberOfEntriesInNode) {
			result->status = ERROR;
			BUG_ON();
			return;
		}

		offset_in_leaf = slot_array[middle].index;
		assert(offset_in_leaf < leaf_size);

		/*This buffer is usefull in cases where the key is stored in place and its size is
		 * smaller than PREFIX_SIZE */
		char padded_leaf_prefix[PREFIX_SIZE];

		/*Initialized leaf key prefix either inside the index or the padded_prefix case*/
		struct kv_splice *key_buf = (struct kv_splice *)get_kv_offset(leaf, leaf_size, offset_in_leaf);
		if (get_kv_format(slot_array[middle].key_category) == KV_INPLACE && key_buf->key_size < PREFIX_SIZE) {
			memset(padded_leaf_prefix, 0x00, PREFIX_SIZE);
			memcpy(padded_leaf_prefix, key_buf->data, key_buf->key_size);
			leaf_key_prefix.prefix = padded_leaf_prefix;
			leaf_key_prefix.len = PREFIX_SIZE;
		} else
			fill_prefix(&leaf_key_prefix, get_kv_offset(leaf, leaf_size, offset_in_leaf),
				    get_kv_format(slot_array[middle].key_category));

		/* Next we check the look up key*/
		if (req->metadata.key_format == KV_PREFIX) {
			ret = prefix_compare(leaf_key_prefix.prefix, req->key_value_buf, PREFIX_SIZE);
			goto check_comparison;
		}
		struct kv_splice *kv_inplace = (struct kv_splice *)req->key_value_buf;
		if (get_key_size(kv_inplace) >= PREFIX_SIZE) {
			ret = prefix_compare(leaf_key_prefix.prefix, get_key_offset_in_kv(kv_inplace), PREFIX_SIZE);
			goto check_comparison;
		}

		/*Case we have a key in KV_FORMAT encoding that IS smaller than PREFIX_SIZE*/
		char padded_lookupkey_prefix[PREFIX_SIZE] = { 0 };
		memcpy(padded_lookupkey_prefix, get_key_offset_in_kv(kv_inplace), get_key_size(kv_inplace));
		ret = prefix_compare(leaf_key_prefix.prefix, padded_lookupkey_prefix, PREFIX_SIZE);

	check_comparison:
		ret_case = ret < 0 ? LESS_THAN_ZERO : ret > 0 ? GREATER_THAN_ZERO : EQUAL_TO_ZERO;
		struct bt_kv_log_address L = { .addr = NULL, .in_tail = 0, .tail_id = UINT8_MAX };

		if (ret_case == EQUAL_TO_ZERO) {
			char *kv_offset = get_kv_offset(leaf, leaf_size, offset_in_leaf);

			leaf_key_buf = fill_keybuf(kv_offset, get_kv_format(slot_array[middle].key_category));
			switch (slot_array[middle].key_category) {
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
				struct kv_seperation_splice *kv_entry =
					(struct kv_seperation_splice *)req->key_value_buf;
				/*key1 and key2 are KV_FORMATed*/
				init_key_cmp(&key1_cmp, L.addr, KV_FORMAT);
				init_key_cmp(&key2_cmp, (void *)kv_entry->dev_offt, KV_FORMAT);
				ret = key_cmp(&key1_cmp, &key2_cmp);
				break;
			}
			case KV_FORMAT:

				/*key1 and key2 are KV_FORMATed*/
				init_key_cmp(&key1_cmp, L.addr, KV_FORMAT);
				init_key_cmp(&key2_cmp, req->key_value_buf, KV_FORMAT);
				ret = key_cmp(&key1_cmp, &key2_cmp);
				break;
			default:
				log_fatal("Corrupted key type");
				BUG_ON();
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
		char *key = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[i].index),
					get_kv_format(slot_array[i].key_category));

		assert(get_key_size(key) < MAX_KEY_SPLICE_SIZE);
		log_debug("Key %*s", get_key_size(key), key + get_lsn_size());
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
	for (int32_t i = 0; i < leaf->header.num_entries; ++i) {
		struct kv_splice *key = (struct kv_splice *)fill_keybuf(
			get_kv_offset(leaf, leaf_size, slot_array[i].index), get_kv_format(slot_array[i].key_category));
		log_info("offset in leaf %d ADDR %p Size%d key %s\n", slot_array[i].index,
			 (void *)get_kv_offset(leaf, leaf_size, slot_array[i].index), get_key_size(key),
			 get_key_offset_in_kv(key));
	}
	log_info("2--------------------------------------------");
}

#ifdef DEBUG_DYNAMIC_LEAF
void check_sorted_dynamic_leaf(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size)
{
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	struct key_compare key1_cmp, key2_cmp;
	/* log_info("number of entries %d", leaf->header.num_entries); */
	for (unsigned i = 0; i < leaf->header.num_entries - 1; ++i) {
		char *key = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[i].index), slot_array[i].bitmap);
		char *key2 =
			fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[i + 1].index), slot_array[i + 1].bitmap);
		/*key1 and key2 are KV_FORMATed*/
		init_key_cmp(&key1_cmp, key, KV_FORMAT);
		init_key_cmp(&key2_cmp, key2, KV_FORMAT);
		if (key_cmp(&key1_cmp, &key2_cmp) > 0) {
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
		leaf_log_size += get_kv_seperated_splice_size();
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
	struct bt_dynamic_leaf_node *left_leaf = NULL;
	struct bt_dynamic_leaf_node *right_leaf = NULL;
	struct bt_dynamic_leaf_node *old_leaf = leaf;
	struct bt_dynamic_leaf_slot_array *slot_array = NULL;
	struct bt_dynamic_leaf_slot_array *right_leaf_slot_array = NULL;
	struct bt_dynamic_leaf_slot_array *left_leaf_slot_array = NULL;
	int level_id = req->metadata.level_id;
	char *split_buffer = malloc(leaf_size);
	char *key_buf = NULL;
	char *leaf_log_tail = NULL;
	char *middle_key_buf = NULL;
	level_descriptor *level = &req->metadata.handle->db_desc->levels[level_id];
	struct db_descriptor *db_desc = req->metadata.handle->db_desc;
	int32_t i = 0, j = 0;
	uint32_t key_buf_size = 0;
	/*cow check*/
#ifdef DEBUG_DYNAMIC_LEAF
	validate_dynamic_leaf(leaf, level, 0, 0);
	check_sorted_dynamic_leaf(leaf, leaf_size);
#endif

	memcpy(split_buffer, leaf, leaf_size);
	slot_array = get_slot_array_offset((struct bt_dynamic_leaf_node *)split_buffer);
	left_leaf = rep.left_leaf_child = leaf;
	leaf = (struct bt_dynamic_leaf_node *)split_buffer;
	/*Fix left leaf metadata*/
	left_leaf->header.type = leafNode;
	left_leaf->header.num_entries = 0;
	left_leaf->header.fragmentation = 0;
	left_leaf->header.leaf_log_size = 0;
	left_leaf->header.height = 0;

	leaf_log_tail = get_leaf_log_offset(left_leaf, level->leaf_size);
	left_leaf_slot_array = get_slot_array_offset(left_leaf);
	for (i = 0, j = 0; i < leaf->header.num_entries / 2; ++i, ++j) {
		key_buf = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[i].index),
				      get_kv_format(slot_array[i].key_category));
		if (get_kv_format(slot_array[i].key_category) == KV_INPLACE) {
			key_buf_size = get_kv_size((struct kv_splice *)key_buf);
			left_leaf->header.leaf_log_size += key_buf_size;
			leaf_log_tail -= key_buf_size;
			memcpy(leaf_log_tail, key_buf, key_buf_size);
		} else if (get_kv_format(slot_array[i].key_category) == KV_INLOG) {
			left_leaf->header.leaf_log_size += get_kv_seperated_splice_size();
			leaf_log_tail -= get_kv_seperated_splice_size();
			memcpy(leaf_log_tail, get_kv_offset(leaf, leaf_size, slot_array[i].index),
			       get_kv_seperated_splice_size());
		}

		left_leaf_slot_array[j].index = left_leaf->header.leaf_log_size;
		left_leaf_slot_array[j].key_category = slot_array[i].key_category;
		left_leaf_slot_array[j].tombstone = slot_array[i].tombstone;
	}

	/*Fix Right leaf metadata*/
	rep.right_leaf_child = seg_get_dynamic_leaf_node(db_desc, level_id, req->metadata.tree_id);
	middle_key_buf = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[leaf->header.num_entries / 2].index),
				     get_kv_format(slot_array[leaf->header.num_entries / 2].key_category));

	//Stub for big log direct IO, this function is called na/now
	//only in L0
	struct bt_kv_log_address L = { .addr = NULL, .in_tail = 0, .tail_id = UINT8_MAX };
	switch (slot_array[leaf->header.num_entries / 2].key_category) {
	case BIG_INLOG:
		L = bt_get_kv_log_address(&req->metadata.handle->db_desc->big_log, ABSOLUTE_ADDRESS(middle_key_buf));
		break;
	default:
		L.addr = middle_key_buf;
		break;
	}

	struct kv_splice *kv_splice = (struct kv_splice *)L.addr;

	serialize_kv_splice_to_key_splice(rep.middle_key, kv_splice);

	if (L.in_tail) {
		struct log_descriptor *log_desc = NULL;
		switch (slot_array[leaf->header.num_entries / 2].key_category) {
		case BIG_INLOG:
			log_desc = &req->metadata.handle->db_desc->big_log;
			break;
		case MEDIUM_INLOG:
			log_desc = &req->metadata.handle->db_desc->medium_log;
			break;
		default:
			log_fatal("Unhandled case");
			BUG_ON();
			//#endif
		}
		bt_done_with_value_log_address(log_desc, &L);
	}
	//Stub end

	right_leaf = rep.right_leaf_child;
	/*Copy pointers + prefixes*/
	leaf_log_tail = get_leaf_log_offset(right_leaf, leaf_size);
	right_leaf_slot_array = get_slot_array_offset(right_leaf);
	for (i = leaf->header.num_entries / 2, j = 0; i < leaf->header.num_entries; ++i, ++j) {
		key_buf = fill_keybuf(get_kv_offset(leaf, leaf_size, slot_array[i].index),
				      get_kv_format(slot_array[i].key_category));
		if (get_kv_format(slot_array[i].key_category) == KV_INPLACE) {
			key_buf_size = get_kv_size((struct kv_splice *)key_buf);
			leaf_log_tail -= key_buf_size;
			right_leaf->header.leaf_log_size += key_buf_size;
			memcpy(leaf_log_tail, key_buf, key_buf_size);
		} else if (get_kv_format(slot_array[i].key_category) == KV_INLOG) {
			right_leaf->header.leaf_log_size += get_kv_seperated_splice_size();
			leaf_log_tail -= get_kv_seperated_splice_size();
			memcpy(leaf_log_tail, get_kv_offset(leaf, leaf_size, slot_array[i].index),
			       get_kv_seperated_splice_size());
		}

		right_leaf_slot_array[j].index = right_leaf->header.leaf_log_size;
		right_leaf_slot_array[j].key_category = slot_array[i].key_category;
		right_leaf_slot_array[j].tombstone = slot_array[i].tombstone;
	}

	rep.left_leaf_child->header.height = leaf->header.height;
	rep.left_leaf_child->header.num_entries = leaf->header.num_entries / 2;

	rep.right_leaf_child->header.num_entries = leaf->header.num_entries - (leaf->header.num_entries / 2);
	rep.right_leaf_child->header.type = leafNode;

#ifdef DEBUG_DYNAMIC_LEAF
	validate_dynamic_leaf(left_leaf, level, 0, 0);
	validate_dynamic_leaf(right_leaf, level, 0, 0);
	check_sorted_dynamic_leaf(left_leaf, leaf_size);
	check_sorted_dynamic_leaf(right_leaf, leaf_size);
#endif

	if (leaf->header.type == leafRootNode) {
		rep.left_leaf_child->header.type = leafNode;
		rep.stat = LEAF_ROOT_NODE_SPLITTED;
	} else
		rep.stat = LEAF_NODE_SPLITTED;
#ifdef DEBUG_DYNAMIC_LEAF
	log_debug("left leaf");
	print_all_keys(left_leaf, leaf_size);
	log_debug("right leaf");
	print_all_keys(right_leaf, leaf_size);
#endif

	seg_free_leaf_node(db_desc, level_id, req->metadata.tree_id, (struct bt_dynamic_leaf_node *)old_leaf);
	free(split_buffer);

	//log_debug("middle key propoted is : %u, %s", *(uint32_t *)rep.middle_key, rep.middle_key + sizeof(uint32_t));

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

	if (args->cat == BIG_INLOG || args->cat == MEDIUM_INLOG)
		status = KV_INLOG;
	else
		status = KV_INPLACE;

	if (status == KV_INPLACE) {
		assert(kv_format != KV_PREFIX);
		leaf->header.leaf_log_size += append_kv_inplace(dest, key_value_buf, key_value_size);
	} else if (status == KV_INLOG) {
		struct kv_seperation_splice *serialized = (struct kv_seperation_splice *)key_value_buf;
		if (args->level_id == 0 && args->cat == BIG_INLOG && kv_format == KV_FORMAT) {
			struct kv_splice *key = (struct kv_splice *)key_value_buf;
			assert(args->kv_dev_offt != 0);
			leaf->header.leaf_log_size += append_bt_leaf_entry_inplace(dest, args->kv_dev_offt, key->data,
										   MIN(key->key_size, PREFIX_SIZE));
		} else {
			if (kv_format == KV_FORMAT) {
				struct kv_splice *key = (struct kv_splice *)key_value_buf;
				leaf->header.leaf_log_size +=
					append_bt_leaf_entry_inplace(dest, ABSOLUTE_ADDRESS(key_value_buf), key->data,
								     MIN(key->key_size, PREFIX_SIZE));
			} else {
				leaf->header.leaf_log_size += append_bt_leaf_entry_inplace(
					dest, ABSOLUTE_ADDRESS(serialized->dev_offt), serialized->prefix, PREFIX_SIZE);
			}
		}
	} else
		BUG_ON();

	slot.index = leaf->header.leaf_log_size;
	slot.key_category = args->cat;
	slot.tombstone = args->tombstone;
	slot_array[middle] = slot;
}

int reorganize_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size, bt_insert_req *req)
{
	enum kv_category cat = req->metadata.cat;
	uint32_t kv_size = (cat == BIG_INLOG || cat == MEDIUM_INLOG) ?
				   get_kv_seperated_splice_size() :
				   get_kv_size((struct kv_splice *)req->key_value_buf);

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

	char *leaf_log_tail = get_leaf_log_offset(leaf, leaf_size);
	struct bt_dynamic_leaf_slot_array *leaf_slot_array = get_slot_array_offset(leaf);

	for (int32_t i = 0; i < reorganize_buffer->header.num_entries; ++i) {
		char *key_buf = fill_keybuf(get_kv_offset(reorganize_buffer, leaf_size, slot_array[i].index),
					    get_kv_format(slot_array[i].key_category));

		if (get_kv_format(slot_array[i].key_category) == KV_INPLACE) {
			uint32_t key_buf_size = get_kv_size((struct kv_splice *)key_buf);
			assert(slot_array[i].key_category == SMALL_INPLACE ||
			       slot_array[i].key_category == MEDIUM_INPLACE);
			leaf->header.leaf_log_size += key_buf_size;
			leaf_log_tail -= key_buf_size;
			memcpy(leaf_log_tail, key_buf, key_buf_size);
		} else if (get_kv_format(slot_array[i].key_category) == KV_INLOG) {
			leaf->header.leaf_log_size += get_kv_seperated_splice_size();
			leaf_log_tail -= get_kv_seperated_splice_size();
			assert(slot_array[i].key_category != SMALL_INPLACE &&
			       slot_array[i].key_category != MEDIUM_INPLACE);
			memcpy(leaf_log_tail, get_kv_offset(reorganize_buffer, leaf_size, slot_array[i].index),
			       get_kv_seperated_splice_size());
		}

		leaf_slot_array[i].index = leaf->header.leaf_log_size;
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
	struct write_dynamic_leaf_args write_leaf_args = {
		.leaf = leaf,
		.key_value_buf = req->key_value_buf,
		.kv_dev_offt = req->kv_dev_offt,
		.key_value_size = get_kv_size((struct kv_splice *)req->key_value_buf),
		.level_id = level->level_id,
		.kv_format = req->metadata.key_format,
		.level_medium_inplace = req->metadata.handle->db_desc->level_medium_inplace,
		.cat = req->metadata.cat,
		.tombstone = req->metadata.tombstone
	};
	struct dl_bsearch_result bsearch = { .middle = 0, .status = INSERT, .op = DYNAMIC_LEAF_INSERT };
	char *leaf_log_tail = get_leaf_log_offset(leaf, level->leaf_size);

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
		    slot_array[bsearch.middle].key_category == MEDIUM_INLOG)
			leaf->header.fragmentation += get_kv_seperated_splice_size();
		else {
			char *kv = fill_keybuf(get_kv_offset(leaf, level->leaf_size, slot_array[bsearch.middle].index),
					       get_kv_format(slot_array[bsearch.middle].key_category));
			if (kv == NULL) {
				log_fatal("Encountered NULL kv in leaf");
				assert(0);
				BUG_ON();
			}

			uint32_t kv_size = get_kv_size((struct kv_splice *)kv);
			leaf->header.fragmentation += kv_size;
		}
		write_data_in_dynamic_leaf(&write_leaf_args);
		break;
	default:
		log_fatal("ERROR in insert path%d", bsearch.middle);
		BUG_ON();
	}

#ifdef DEBUG_DYNAMIC_LEAF
	validate_dynamic_leaf(leaf, level, 0, 1);
	check_sorted_dynamic_leaf(leaf, level->leaf_size);
#endif
	assert(leaf->header.leaf_log_size < LEVEL0_LEAF_SIZE);
	//validate_dynamic_leaf(leaf, level, 0, 1);

	return bsearch.status;
}
/*gesalous*/
struct kv_general_splice dl_get_general_splice(struct bt_dynamic_leaf_node *leaf, int32_t position)
{
	struct kv_general_splice general_splice = { 0 };
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	general_splice.cat = slot_array[position].key_category;
	general_splice.is_tombstone = slot_array[position].tombstone;
	uint8_t *kv_addr = (uint8_t *)leaf + slot_array[position].index;
	if (general_splice.cat == SMALL_INPLACE || general_splice.cat == MEDIUM_INPLACE)
		general_splice.kv_splice = (struct kv_splice *)kv_addr;
	else if (general_splice.cat == MEDIUM_INLOG || general_splice.cat == BIG_INLOG) {
		general_splice.kv_sep2 = (struct kv_seperation_splice2 *)kv_addr;
	} else {
		log_fatal("Unknown kv category");
		BUG_ON();
	}
	return general_splice;
}

static void dl_fill_key_from_general_splice(struct kv_general_splice *general_splice, char **key, int32_t *key_size)
{
	if (general_splice->cat == SMALL_INPLACE || general_splice->cat == MEDIUM_INPLACE) {
		*key = get_key_offset_in_kv(general_splice->kv_splice);
		*key_size = get_key_size(general_splice->kv_splice);
	} else if (general_splice->cat == MEDIUM_INLOG || general_splice->cat == BIG_INLOG) {
		*key = kv_sep2_get_key(general_splice->kv_sep2);
		*key_size = kv_sep2_get_key_size(general_splice->kv_sep2);
	} else {
		log_fatal("Unknown kv category");
		BUG_ON();
	}
}

int32_t dl_search_get_pos(struct bt_dynamic_leaf_node *leaf, char *key, int32_t key_size, bool *exact_match)
{
	*exact_match = false;

	if (leaf->header.num_entries == 0)
		return -1;

	int32_t cmp_return_value = 0;
	int32_t start = 0;
	int32_t end = leaf->header.num_entries - 1;

	int32_t middle = 0;

	while (start <= end) {
		middle = (start + end) / 2;

		struct kv_general_splice leaf_splice = dl_get_general_splice(leaf, middle);

		/*At zero position we have a guard or -oo*/
		char *leaf_key = NULL;
		int32_t leaf_key_size = 0;
		dl_fill_key_from_general_splice(&leaf_splice, &leaf_key, &leaf_key_size);
		// log_debug(
		// 	"Comparing leaf key size: %d leaf key data %.*s  pos is %d with look up key size: %d key data %.*s",
		// 	leaf_key_size, leaf_key_size, leaf_key, middle, key_size, key_size, key);
		assert(leaf_key_size > 0);

		cmp_return_value = memcmp(leaf_key, key, key_size <= leaf_key_size ? key_size : leaf_key_size);

		if (0 == cmp_return_value && leaf_key_size == key_size) {
			*exact_match = true;
			return middle;
		}

		if (0 == cmp_return_value)
			cmp_return_value = leaf_key_size - key_size;

		if (cmp_return_value > 0)
			end = middle - 1;
		else
			start = middle + 1;
	}

	return cmp_return_value > 0 ? middle - 1 : middle;
}

struct kv_general_splice dl_find_kv_in_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, char *key, int32_t key_size,
						    const char **error)
{
	struct find_result result = { 0 };
	struct kv_general_splice kv_not_found = { 0 };
	bool exact_match = false;
	int32_t pos = dl_search_get_pos(leaf, key, key_size, &exact_match);

	if (exact_match)
		return dl_get_general_splice(leaf, pos);
	*error = "KV pair not found";
	return kv_not_found;
}

bool dl_is_leaf_full(struct bt_dynamic_leaf_node *leaf, int32_t kv_size)
{
	uint8_t *left_border = (uint8_t *)leaf + sizeof(struct node_header) +
			       ((leaf->header.num_entries + 1) * sizeof(struct bt_dynamic_leaf_slot_array));

	uint8_t *right_border = (uint8_t *)leaf + leaf->header.leaf_log_size;
	right_border -= kv_size;
	// log_debug("kv_size %d right_border %lu left border %lu", kv_size, right_border, left_border);
	return right_border > left_border ? false : true;
}

static uint16_t dl_append_data_splice_in_dynamic_leaf(struct bt_dynamic_leaf_node *leaf,
						      struct kv_general_splice *general_splice)
{
	int32_t kv_size = kv_general_splice_calculate_size(general_splice);
	if (dl_is_leaf_full(leaf, kv_size)) {
		log_warn("Leaf is full cannot serve request");
		return 0;
	}
	assert(leaf->header.leaf_log_size > kv_size);
	leaf->header.leaf_log_size -= kv_size;
	char *src = (char *)leaf;
	char *dest = &src[leaf->header.leaf_log_size];
	if (general_splice->cat == SMALL_INPLACE || general_splice->cat == MEDIUM_INPLACE)
		kv_splice_serialize(general_splice->kv_splice, dest);
	if (general_splice->cat == BIG_INLOG || general_splice->cat == MEDIUM_INLOG)
		kv_sep2_serialize(general_splice->kv_sep2, dest, kv_size);

	return leaf->header.leaf_log_size;
}

bool dl_append_splice_in_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, struct kv_general_splice *general_splice,
				      bool is_tombstone)
{
	uint16_t offt = dl_append_data_splice_in_dynamic_leaf(leaf, general_splice);
	if (!offt) {
		log_fatal("Leaf is full cannot serve request to avoid overflow (it shouldn't at this point)");
		_exit(EXIT_FAILURE);
	}
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	slot_array[leaf->header.num_entries].index = offt;
	slot_array[leaf->header.num_entries].tombstone = 0;
	if (is_tombstone)
		slot_array[leaf->header.num_entries].tombstone = 1;
	slot_array[leaf->header.num_entries++].key_category = general_splice->cat;
	return true;
}

bool dl_insert_in_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, struct kv_general_splice *splice, bool is_tombstone,
			       bool *exact_match)
{
	if (dl_is_leaf_full(leaf, kv_general_splice_calculate_size(splice))) {
		log_fatal("Cannot server request leaf will overflow");
		_exit(EXIT_FAILURE);
	}
	// if (!dl_check_leaf(leaf)) {
	// 	log_debug("Faulting splice is %d %s leaf entries = %d", kv_general_splice_get_key_size(splice),
	// 		  kv_general_splice_get_key_buf(splice), leaf->header.num_entries);
	// 	assert(0);
	// }
	int32_t kv_size = kv_general_splice_calculate_size(splice);
	if (dl_is_leaf_full(leaf, kv_size))
		return false;

	char *key = NULL;
	int32_t key_size = 0;

	dl_fill_key_from_general_splice(splice, &key, &key_size);

	int32_t pos = dl_search_get_pos(leaf, key, key_size, exact_match);
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	if (*exact_match) {
		struct kv_general_splice updated_kv = dl_get_general_splice(leaf, pos);
		leaf->header.fragmentation += kv_general_splice_get_size(&updated_kv);
	} else {
		size_t bytes_to_move =
			(leaf->header.num_entries - (pos + 1)) * sizeof(struct bt_dynamic_leaf_slot_array);
		// log_debug("Moving slot array from pos %d to pos %d gona move %lu bytes entris in leaf %d", pos + 1,
		// 	  pos + 2, bytes_to_move, leaf->header.num_entries);
		if (bytes_to_move)
			memmove(&slot_array[pos + 2], &slot_array[pos + 1], bytes_to_move);
	}
	uint16_t offt = dl_append_data_splice_in_dynamic_leaf(leaf, splice);
	if (!offt) {
		log_fatal("Leaf is full cannot fullfill the request (it shouldn't at this point)");
		_exit(EXIT_FAILURE);
	}

	if (!*exact_match) {
		pos = pos + 1;
		++leaf->header.num_entries;
	}
	slot_array[pos].index = offt;
	slot_array[pos].tombstone = is_tombstone ? 1 : 0;
	slot_array[pos].key_category = splice->cat;
	// if (!dl_check_leaf(leaf)) {
	// 	log_debug(
	// 		"Faulting splice is %d %s leaf entries = %d key was %.*s pos is %d num entries %d offt was %u",
	// 		kv_general_splice_get_key_size(splice), kv_general_splice_get_key_buf(splice),
	// 		leaf->header.num_entries, key_size, key, pos, leaf->header.num_entries, offt);
	// 	assert(0);
	// }
	return true;
}

struct dl_leaf_iterator {
	struct kv_general_splice splice;
	struct bt_dynamic_leaf_node *leaf;
	int pos;
};

static void dl_init_leaf_iterator(struct bt_dynamic_leaf_node *leaf, struct dl_leaf_iterator *iter, char *key,
				  int32_t key_size)
{
	iter->leaf = leaf;
	if (iter->leaf->header.num_entries <= 0) {
		iter->pos = -1;
		return;
	}
	iter->pos = 0;
	if (NULL != key) {
		bool exact_match = false;
		iter->pos = dl_search_get_pos(leaf, key, key_size, &exact_match);
	}
	iter->splice = dl_get_general_splice(leaf, iter->pos);
}

static bool dl_is_leaf_iterator_valid(struct dl_leaf_iterator *iter)
{
	return iter->leaf->header.num_entries > 0 && iter->pos < iter->leaf->header.num_entries;
}

static void dl_leaf_iterator_next(struct dl_leaf_iterator *iter)
{
	++iter->pos;
}

static struct kv_general_splice dl_leaf_iterator_curr(struct dl_leaf_iterator *iter)
{
	if (!dl_is_leaf_iterator_valid(iter)) {
		struct kv_general_splice splice = { 0 };
		return splice;
	}

	return dl_get_general_splice(iter->leaf, iter->pos);
}

// static bool dl_check_leaf(struct bt_dynamic_leaf_node *leaf)
// {
// 	struct dl_leaf_iterator iter = { 0 };
// 	dl_init_leaf_iterator(leaf, &iter, NULL, -1);
// 	while (dl_is_leaf_iterator_valid(&iter)) {
// 		struct kv_general_splice splice = dl_leaf_iterator_curr(&iter);
// 		if (kv_general_splice_get_key_size(&splice) <= 0) {
// 			log_debug("Assertion failed iterator pos %d  leaf entries: %d cat = %d", iter.pos,
// 				  iter.leaf->header.num_entries, splice.cat);
// 			return false;
// 		}
// 		if (kv_general_splice_get_key_size(&splice) > MAX_KEY_SIZE) {
// 			log_debug("Assertion failed iterator pos %d", iter.pos);
// 			assert(0);
// 		}
// 		dl_leaf_iterator_next(&iter);
// 	}
// 	return true;
// }

struct kv_general_splice dl_split_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, struct bt_dynamic_leaf_node *left,
					       struct bt_dynamic_leaf_node *right)
{
	struct dl_leaf_iterator iter = { 0 };
	dl_init_leaf_iterator(leaf, &iter, NULL, -1);
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	int32_t idx = 0;
	for (; idx < leaf->header.num_entries / 2; idx++) {
		if (!dl_is_leaf_iterator_valid(&iter)) {
			log_fatal("This should not happen, probably corruption?");
			assert(0);
			_exit(EXIT_FAILURE);
		}
		struct kv_general_splice splice = dl_leaf_iterator_curr(&iter);
		dl_append_splice_in_dynamic_leaf(left, &splice, slot_array[iter.pos].tombstone);
		dl_leaf_iterator_next(&iter);
	}
	struct kv_general_splice pivot_splice = dl_get_general_splice(leaf, idx);
	for (; idx < leaf->header.num_entries; idx++) {
		if (!dl_is_leaf_iterator_valid(&iter)) {
			log_fatal("This should not happen, probably corruption?");
			_exit(EXIT_FAILURE);
		}
		struct kv_general_splice splice = dl_leaf_iterator_curr(&iter);

		dl_append_splice_in_dynamic_leaf(right, &splice, slot_array[iter.pos].tombstone);
		dl_leaf_iterator_next(&iter);
	}
	return pivot_splice;
}

bool dl_is_reorganize_possible(struct bt_dynamic_leaf_node *leaf, int32_t kv_size)
{
	return leaf->header.fragmentation <= kv_size ? false : true;
}

void dl_reorganize_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, struct bt_dynamic_leaf_node *target)
{
	struct dl_leaf_iterator iter = { 0 };
	dl_init_leaf_iterator(leaf, &iter, NULL, -1);
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(leaf);
	for (int32_t i = 0; i < leaf->header.num_entries; i++) {
		if (!dl_is_leaf_iterator_valid(&iter)) {
			log_fatal("This should not happen, probably corruption?");
			_exit(EXIT_FAILURE);
		}
		struct kv_general_splice splice = dl_leaf_iterator_curr(&iter);
		dl_append_splice_in_dynamic_leaf(target, &splice, slot_array[iter.pos].tombstone);
		dl_leaf_iterator_next(&iter);
	}
}

void dl_init_leaf_node(struct bt_dynamic_leaf_node *node, uint32_t leaf_size)
{
	memset(node, 0x00, leaf_size);
	node->header.leaf_log_size = leaf_size;
}

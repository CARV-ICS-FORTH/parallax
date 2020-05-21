#include <assert.h>
#include <stdint.h>
#include <limits.h>
#include <mba/bitset.h>
#include <log.h>
#include "static_leaf.h"
#include "conf.h"

extern uint32_t leaf_size_per_level[MAX_LEVELS];
extern level_offsets_todata leaf_node_offsets[MAX_LEVELS];

static void retrieve_static_leaf_structures(struct bt_static_leaf_node const *leaf, struct bt_static_leaf_structs *src)
{
	char *leaf_base_address = (char *)leaf;
	uint8_t level_id = leaf->header.level_id;
	src->bitmap = (bt_leaf_bitmap *)(leaf_base_address + leaf_node_offsets[level_id].bitmap_offset);
	src->slot_array = (bt_leaf_slot_array *)(leaf_base_address + leaf_node_offsets[level_id].slot_array_offset);
	src->kv_entries = (bt_leaf_entry *)(leaf_base_address + leaf_node_offsets[level_id].kv_entries_offset);
}

static uint32_t get_bitmap_size(uint8_t level_id)
{
	return sizeof(bt_leaf_bitmap) * leaf_node_offsets[level_id].bitmap_entries;
}

static uint32_t get_slot_array_size(uint8_t level_id)
{
	return sizeof(bt_leaf_slot_array) * leaf_node_offsets[level_id].slot_array_entries;
}

static uint32_t get_kv_entries_size(uint8_t level_id)
{
	return sizeof(bt_leaf_entry) * leaf_node_offsets[level_id].kv_entries;
}

void init_static_leaf_metadata(struct bt_static_leaf_node *leaf)
{
	struct bt_static_leaf_structs src;
	uint8_t level_id = leaf->header.level_id;
	retrieve_static_leaf_structures(leaf, &src);
	/* If the bt_leaf_bitmap struct becomes a different type than an unsigned char,
	   the UCHAR_MAX should be replaced with the maximum value the type can hold.  */
	memset(src.bitmap, 0, get_bitmap_size(level_id));
	memset(src.slot_array, 0, get_slot_array_size(level_id));
	memset(src.kv_entries, 0, get_kv_entries_size(level_id));
}

struct bsearch_result binary_search_static_leaf(struct bt_static_leaf_node const *leaf, struct splice *key_buf)
{
	struct bt_static_leaf_structs src;
	char *leaf_key_prefix, *leaf_key_buf;
	struct bsearch_result result = { 0, INSERT };
	int32_t start = 0, middle = 0, end = leaf->header.numberOfEntriesInNode - 1;
	const int32_t numberOfEntriesInNode = leaf->header.numberOfEntriesInNode;
	const int32_t kv_entries = leaf_node_offsets[leaf->header.level_id].kv_entries;
	uint32_t pos;
	int ret, ret_case;
	retrieve_static_leaf_structures(leaf, &src);

	while (numberOfEntriesInNode > 0) {
		middle = (start + end) / 2;

		if (numberOfEntriesInNode > kv_entries || middle < 0 || middle >= numberOfEntriesInNode) {
			result.status = ERROR;
			return result;
		}

		pos = src.slot_array[middle].index;
		leaf_key_prefix = src.kv_entries[pos].prefix;
		ret = prefix_compare(leaf_key_prefix, key_buf->data, PREFIX_SIZE);
		ret_case = ret < 0 ? LESS_THAN_ZERO : ret > 0 ? GREATER_THAN_ZERO : EQUAL_TO_ZERO;

		if (ret_case == EQUAL_TO_ZERO) {
			leaf_key_buf = (void *)(MAPPED + src.kv_entries[pos].pointer);
			ret = _tucana_key_cmp(leaf_key_buf, key_buf, KV_FORMAT, KV_FORMAT);

			if (ret == 0) {
				result.middle = middle;
				result.status = UPDATE;
				return result;
			}

			ret_case = ret < 0 ? LESS_THAN_ZERO : GREATER_THAN_ZERO;
		}

		switch (ret_case) {
		case LESS_THAN_ZERO:
			start = middle + 1;
			if (start > end) {
				middle++;
				result.middle = middle;
				result.status = INSERT;
				return result;
			}
			continue;
		case GREATER_THAN_ZERO:
			end = middle - 1;
			if (start > end) {
				result.middle = middle;
				result.status = INSERT;
				return result;
			}
			continue;
		}
	}

	return result;
}

void shift_slot_array(struct bt_static_leaf_node *leaf, uint32_t middle)
{
	struct bt_static_leaf_structs src;
	const size_t num_items = leaf->header.numberOfEntriesInNode - middle;
	retrieve_static_leaf_structures(leaf, &src);

	if (num_items == 0)
		return;

	memmove(&src.slot_array[middle + 1], &src.slot_array[middle], num_items * sizeof(bt_leaf_slot_array));
}

void validate_static_leaf(uint64_t num_entries, bt_leaf_bitmap *bitmap_base, bt_leaf_bitmap *bitmap_end)
{
	iter_t iter;
	uint64_t count_set_bits = 0;
	bitset_iterate(&iter);

	while (1) {
		switch (bitset_next(bitmap_base, bitmap_end, &iter)) {
		case 1:
			++count_set_bits;
			continue;
		case 0:
			continue;
		case -1:
			break;
		}
	}
	assert(num_entries == count_set_bits);
}

int8_t insert_in_static_leaf(struct bt_static_leaf_node *leaf, bt_insert_req *req)
{
	struct bt_static_leaf_structs src;
	struct splice *key = req->key_value_buf;
	bt_leaf_bitmap *bitmap_end;
	struct bsearch_result bsearch = binary_search_static_leaf(leaf, key);
	int kventry_slot = -1;

	retrieve_static_leaf_structures(leaf, &src);
	bitmap_end = src.bitmap + leaf_node_offsets[leaf->header.level_id].kv_entries;

	++leaf->header.v1;
	switch (bsearch.status) {
	case INSERT:
		shift_slot_array(leaf, bsearch.middle);
		kventry_slot = bitset_find_first(&src.bitmap, bitmap_end, 0);
		bitset_set(src.bitmap, kventry_slot);
		src.slot_array[bsearch.middle].index = kventry_slot;
		src.kv_entries[kventry_slot].pointer = (uint64_t)(req->key_value_buf - MAPPED);
		memcpy(src.kv_entries[kventry_slot].prefix, key->data, MIN(key->size, PREFIX_SIZE));
		leaf->header.numberOfEntriesInNode++;
		break;
	case UPDATE:
		src.kv_entries[src.slot_array[bsearch.middle].index].pointer = (uint64_t)(req->key_value_buf - MAPPED);
		memcpy(src.kv_entries[src.slot_array[bsearch.middle].index].prefix, key->data,
		       MIN(key->size, PREFIX_SIZE));

		break;
	default:
		log_info("ERROR");
		exit(EXIT_FAILURE);
	}
	++leaf->header.v2;
	validate_static_leaf(leaf->header.numberOfEntriesInNode, src.bitmap, bitmap_end);
	return 1;
}

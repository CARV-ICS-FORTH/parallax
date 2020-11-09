#include <assert.h>
#include <stdint.h>
#include <limits.h>
#include <mba/bitset.h>
#include <log.h>
#include "static_leaf.h"
#include "conf.h"

static void retrieve_static_leaf_structures(const struct bt_static_leaf_node *leaf, struct bt_static_leaf_structs *src,
					    level_descriptor *level)
{
	char *leaf_base_address = (char *)leaf;
	src->bitmap = (struct bt_leaf_entry_bitmap *)(leaf_base_address + level->leaf_offsets.bitmap_offset);
	src->slot_array = (bt_leaf_slot_array *)(leaf_base_address + level->leaf_offsets.slot_array_offset);
	src->kv_entries = (bt_leaf_entry *)(leaf_base_address + level->leaf_offsets.kv_entries_offset);
}

static uint32_t get_bitmap_size(level_descriptor *level)
{
	return sizeof(struct bt_leaf_entry_bitmap) * level->leaf_offsets.bitmap_entries;
}

static uint32_t get_slot_array_size(level_descriptor *level)
{
	return sizeof(bt_leaf_slot_array) * level->leaf_offsets.slot_array_entries;
}

static uint32_t get_kv_entries_size(level_descriptor *level)
{
	return sizeof(bt_leaf_entry) * level->leaf_offsets.kv_entries_offset;
}

void init_static_leaf_metadata(struct bt_static_leaf_node *leaf, level_descriptor *level)
{
	struct bt_static_leaf_structs src;
	retrieve_static_leaf_structures(leaf, &src, level);
	memset(src.bitmap, 0, get_bitmap_size(level));
	memset(src.slot_array, 0, get_slot_array_size(level));
	memset(src.kv_entries, 0, get_kv_entries_size(level));
}

struct bsearch_result binary_search_static_leaf(struct bt_static_leaf_node const *leaf, level_descriptor *level,
						struct splice *key_buf)
{
	struct bt_static_leaf_structs src;
	char *leaf_key_prefix, *leaf_key_buf;
	struct bsearch_result result = { 0, INSERT };
	int32_t start = 0, middle = 0, end = leaf->header.numberOfEntriesInNode - 1;
	const int32_t numberOfEntriesInNode = leaf->header.numberOfEntriesInNode;
	const int32_t kv_entries = level->leaf_offsets.kv_entries;
	uint32_t pos;
	int ret, ret_case;
	retrieve_static_leaf_structures(leaf, &src, level);

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
				result.status = FOUND;
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

void *find_key_in_static_leaf(const struct bt_static_leaf_node *leaf, level_descriptor *level, void *key,
			      uint32_t key_size)
{
	bt_leaf_entry kv_entry;
	struct bt_static_leaf_structs src;
	struct bsearch_result result;
	void *ret = NULL;
	char buf[128];
	struct splice *key_buf = (struct splice *)buf;

	assert(buf != NULL);
	assert((key_size + sizeof(uint32_t)) <= 128);
	SERIALIZE_KEY(buf, key, key_size);
	retrieve_static_leaf_structures(leaf, &src, level);

	result = binary_search_static_leaf(leaf, level, key_buf);
	switch (result.status) {
	case FOUND:
		return (void *)src.kv_entries[src.slot_array[result.middle].index].pointer;
	default:
		log_info("Key not found %s", key_buf->data);
	}

	return ret;
}

void shift_slot_array(struct bt_static_leaf_node *leaf, uint32_t middle, level_descriptor *level)
{
	struct bt_static_leaf_structs src;
	const size_t num_items = leaf->header.numberOfEntriesInNode - middle;
	retrieve_static_leaf_structures(leaf, &src, level);

	if (num_items == 0)
		return;

	memmove(&src.slot_array[middle + 1], &src.slot_array[middle], num_items * sizeof(bt_leaf_slot_array));
}

void validate_static_leaf(uint64_t num_entries, struct bt_leaf_entry_bitmap *bitmap_base,
			  struct bt_leaf_entry_bitmap *bitmap_end)
{
	iter_t iter;
	uint64_t count_set_bits = 0;
	bitset_iterate(&iter);

	while (1)
		switch (bitset_next(bitmap_base, bitmap_end, &iter)) {
		case 1:
			++count_set_bits;
			continue;
		case 0:
			continue;
		case -1:
			return;
		}

	assert(num_entries == count_set_bits);
}

int8_t insert_in_static_leaf(struct bt_static_leaf_node *leaf, bt_insert_req *req, level_descriptor *level)
{
	struct bt_static_leaf_structs src;
	struct splice *key = req->key_value_buf;
	struct bt_leaf_entry_bitmap *bitmap_end;
	struct bsearch_result bsearch;
	int kventry_slot = -1;

	if (unlikely(leaf->header.numberOfEntriesInNode == 0)) {
		init_static_leaf_metadata(leaf, level);
	}

	retrieve_static_leaf_structures(leaf, &src, level);
	bitmap_end = src.bitmap + level->leaf_offsets.bitmap_entries;
	bsearch = binary_search_static_leaf(leaf, level, key);

	switch (bsearch.status) {
	case INSERT:
		shift_slot_array(leaf, bsearch.middle, level);
		kventry_slot = bitset_find_first(src.bitmap, bitmap_end, 0);
		assert(kventry_slot >= 0);
		bitset_set(src.bitmap, kventry_slot);
		src.slot_array[bsearch.middle].index = kventry_slot;
		src.kv_entries[kventry_slot].pointer = (uint64_t)req->key_value_buf - MAPPED;
		memcpy(src.kv_entries[kventry_slot].prefix, key->data, MIN(key->size, PREFIX_SIZE));
		++leaf->header.numberOfEntriesInNode;
		break;
	case FOUND:
		src.kv_entries[src.slot_array[bsearch.middle].index].pointer = (uint64_t)(req->key_value_buf - MAPPED);
		memcpy(src.kv_entries[src.slot_array[bsearch.middle].index].prefix, key->data,
		       MIN(key->size, PREFIX_SIZE));
		++leaf->header.fragmentation;
		break;
	default:
		log_info("ERROR");
		exit(EXIT_FAILURE);
	}
	validate_static_leaf(leaf->header.numberOfEntriesInNode, src.bitmap, bitmap_end);
	return 1;
}

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
#include "index_node.h"
#include "../btree/key_splice.h"
#include "../btree/kv_pairs.h"
#include "../common/common.h"
#include <assert.h>
#include <log.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct key_splice;

#define INDEX_NODE_SIZE (8192)

struct index_node {
	struct node_header header;
	struct {
		char rest_space[INDEX_NODE_SIZE - sizeof(struct node_header)];
	};
} __attribute__((packed));

struct node_header *index_node_get_header(struct index_node *node)
{
	return &node->header;
}

uint64_t index_node_get_size(void)
{
	_Static_assert(sizeof(struct index_node) == INDEX_NODE_SIZE, "Index node is not page aligned");
	return sizeof(struct index_node);
}

struct pivot_pointer *index_get_pivot_pointer(struct key_splice *key_splice)
{
	uint32_t key_size = key_splice_get_key_size(key_splice) + key_splice_get_metadata_size();
	return (struct pivot_pointer *)((char *)key_splice + key_size);
}

static struct index_slot_array_entry *index_get_slot_array(struct index_node *node)
{
	char *node_array = (char *)node;
	return (struct index_slot_array_entry *)&node_array[sizeof(struct node_header)];
}

static inline size_t index_get_pivot_size(struct key_splice *pivot_splice)
{
	return sizeof(struct pivot_pointer) + key_splice_get_key_size(pivot_splice) + key_splice_get_metadata_size();
}

void index_add_guard(struct index_node *node, uint64_t child_node_dev_offt)
{
	char guard_buf[SMALLEST_KEY_SPLICE_SIZE + sizeof(struct pivot_pointer)] = { 0 };
	bool malloced = false;
	struct key_splice *guard_splice = key_splice_create_smallest(guard_buf, SMALLEST_KEY_SPLICE_SIZE, &malloced);
	if (malloced) {
		log_fatal("Guard buffer for index node is not enough");
		_exit(EXIT_FAILURE);
	}
	struct pivot_pointer *guard_pointer = index_get_pivot_pointer(guard_splice);
	guard_pointer->child_offt = child_node_dev_offt;
	size_t pivot_size = index_get_pivot_size(guard_splice);
	char *pivot_addr = &((char *)node)[INDEX_NODE_SIZE - pivot_size];
	memcpy(pivot_addr, guard_splice, pivot_size);
	assert(node->header.log_size == INDEX_NODE_SIZE);
	node->header.log_size -= pivot_size;
	node->header.num_entries = 1;
	struct index_slot_array_entry *slot_array = index_get_slot_array(node);
	slot_array[0].pivot = node->header.log_size;
}

bool index_is_empty(struct index_node *node)
{
	return node->header.num_entries == 0;
}

void index_init_node(enum add_guard_option option, struct index_node *node, nodeType_t type)
{
	if (option != ADD_GUARD && option != DO_NOT_ADD_GUARD) {
		log_fatal("Unknown guard option");
		BUG_ON();
	}

	node->header.type = type;
	node->header.num_entries = 0;

	node->header.height = -1;
	node->header.fragmentation = 0;

	/*private key log for index nodes, these are unnecessary now will be deleted*/
	node->header.log_size = INDEX_NODE_SIZE;
	if (ADD_GUARD == option)
		index_add_guard(node, UINT64_MAX);
}

static uint32_t index_get_remaining_space(struct index_node *node)
{
	/*Is there enough space?*/
	uint64_t left_border_dev_offt =
		sizeof(struct node_header) + (node->header.num_entries * sizeof(struct index_slot_array_entry));
	/*What is the value of the right border if we append the pivot?*/
	uint64_t right_border_dev_offt = node->header.log_size;
	assert(right_border_dev_offt >= left_border_dev_offt);

	return right_border_dev_offt - left_border_dev_offt;
}

static uint32_t index_get_next_pivot_offt_in_node(struct index_node *node, struct key_splice *key_splice)
{
	uint32_t remaining_space = index_get_remaining_space(node);
	uint32_t pivot_size = index_get_pivot_size(key_splice);
	uint32_t size_needed = pivot_size + sizeof(struct index_slot_array_entry);
	//log_debug("Remaining space %u pivot_size: %lu", remaining_space, PIVOT_SIZE(key));
	return remaining_space <= size_needed ? 0 : node->header.log_size - pivot_size;
}

bool index_is_split_needed(struct index_node *node, uint32_t max_pivot_size)
{
	max_pivot_size +=
		key_splice_get_metadata_size() + sizeof(struct pivot_pointer) + sizeof(struct index_slot_array_entry);

	return index_get_remaining_space(node) < max_pivot_size;
}

static inline struct key_splice *index_get_key_splice(struct index_node *node, uint16_t offset)
{
	return (struct key_splice *)((uint64_t)node + offset);
}

/**
 * Returns the position in the node header children offt array which we need to follow based on the lookup_key.
 * The actual offset is at node->children_offt[position]
 */
static int32_t index_search_get_pos(struct index_node *node, char *lookup_key, int32_t lookup_key_size,
				    bool *exact_match)
{
	assert(lookup_key_size >= 0);
	assert(lookup_key_size <= MAX_KEY_SIZE);
	*exact_match = false;

	int comparison_return_value = 0;
	int32_t start = 0;
	int32_t end = node->header.num_entries - 1;

	int32_t middle = 0;
	struct index_slot_array_entry *slot_array = index_get_slot_array(node);

	while (start <= end) {
		middle = (start + end) / 2;

		struct key_splice *index_splice = index_get_key_splice(node, slot_array[middle].pivot);

		/*At zero position we have a guard or -oo*/

		int32_t index_key_size = key_splice_get_key_size(index_splice);
		assert(index_key_size > 0);
		assert(index_key_size <= MAX_KEY_SIZE);
		comparison_return_value = memcmp(key_splice_get_key_offset(index_splice), lookup_key,
						 index_key_size < lookup_key_size ? index_key_size : lookup_key_size);
		// log_debug("Comparing index key size %u -- %s with look up key size: %d data: %s ret value is %d",
		// 	  key_splice_get_key_size(index_splice), key_splice_get_key_offset(index_splice),
		// 	  lookup_key_size, lookup_key, comparison_return_value);
		if (0 == comparison_return_value && index_key_size == lookup_key_size) {
			*exact_match = true;
			return middle;
		}
		if (0 == comparison_return_value)
			comparison_return_value = index_key_size - lookup_key_size;

		if (comparison_return_value > 0)
			end = middle - 1;
		else
			start = middle + 1;
	}

	return comparison_return_value > 0 ? middle - 1 : middle;
}

bool index_set_type(struct index_node *node, const nodeType_t node_type)
{
	if (!node)
		return false;

	if (node_type != internalNode && node_type != rootNode)
		return false;
	node->header.type = node_type;
	return true;
}

void index_set_height(struct index_node *node, int32_t height)
{
	if (!node)
		BUG_ON();
	node->header.height = height;
}

struct key_splice *index_remove_last_pivot_key(struct index_node *node)
{
	if (!node)
		return NULL;
	if (0 == node->header.num_entries)
		return NULL;
	int32_t position = node->header.num_entries - 1;
	struct index_slot_array_entry *slot_array = index_get_slot_array(node);
	struct key_splice *index_splice = index_get_key_splice(node, slot_array[position].pivot);
	size_t pivot_size = index_get_pivot_size(index_splice);
	struct key_splice *pivot_copy = calloc(1UL, pivot_size);
	memcpy(pivot_copy, index_splice, pivot_size);
	--node->header.num_entries;
	return pivot_copy;
}

static struct key_splice *index_search_get_full_pivot(struct index_node *node, char *lookup_key,
						      int32_t lookup_key_size)
{
	assert(lookup_key_size > 0);
	assert(lookup_key_size <= MAX_KEY_SIZE);
	bool unused = false; // Created here to call the function
	int32_t position = index_search_get_pos(node, lookup_key, lookup_key_size, &unused);

	struct index_slot_array_entry *slot_array = index_get_slot_array(node);
	struct key_splice *pivot_splice = index_get_key_splice(node, slot_array[position].pivot);

	return pivot_splice;
}

struct pivot_pointer *index_search_get_pivot(struct index_node *node, char *lookup_key, int32_t lookup_key_size)
{
	assert(lookup_key_size > 0);
	assert(lookup_key_size <= MAX_KEY_SIZE);
	struct key_splice *pivot_splice = index_search_get_full_pivot(node, lookup_key, lookup_key_size);
	return index_get_pivot_pointer(pivot_splice);
}

uint64_t index_binary_search(struct index_node *node, char *lookup_key, int32_t lookup_key_size)
{
	assert(lookup_key_size > 0);
	assert(lookup_key_size <= MAX_KEY_SIZE);
	struct key_splice *index_key_splice = index_search_get_full_pivot(node, lookup_key, lookup_key_size);
	struct pivot_pointer *piv_pointer = index_get_pivot_pointer(index_key_splice);
	return piv_pointer->child_offt;
}

static bool index_internal_insert_pivot(struct insert_pivot_req *ins_pivot_req, bool is_append)
{
	uint64_t pivot_offt_in_node = index_get_next_pivot_offt_in_node(ins_pivot_req->node, ins_pivot_req->key_splice);

	if (!pivot_offt_in_node)
		return false;
	int32_t position = ins_pivot_req->node->header.num_entries - 1;

	struct index_slot_array_entry *slot_array = index_get_slot_array(ins_pivot_req->node);
	if (!is_append) {
		bool exact_match = false;
		position = index_search_get_pos(ins_pivot_req->node,
						key_splice_get_key_offset(ins_pivot_req->key_splice),
						key_splice_get_key_size(ins_pivot_req->key_splice), &exact_match);
		assert(position >= 0);

		//TODO refactor this and move it inside index_search_get_pos
		//On the other call sites of index_search_get_pos exact match is not an error.
		//so we should move the error reporting inside the function.
		if (exact_match) {
			log_fatal("Key  %.*s already present in index node",
				  key_splice_get_key_size(ins_pivot_req->key_splice),
				  key_splice_get_key_offset(ins_pivot_req->key_splice));
			BUG_ON();
		}

		/*Create room for the now entry in the slot array*/
		memmove(&slot_array[position + 2], &slot_array[position + 1],
			(ins_pivot_req->node->header.num_entries - (position + 1)) *
				sizeof(struct index_slot_array_entry));

		/*Update in-place the left_child. This is ok because we call this function for L0 which is in memory*/
		struct key_splice *left_pivot_key_splice =
			index_get_key_splice(ins_pivot_req->node, slot_array[position].pivot);

		struct pivot_pointer *left = index_get_pivot_pointer(left_pivot_key_splice);
		*left = *ins_pivot_req->left_child;
	}

	/*append the actual pivot --> <key_size><key><pivot>*/
	char *pivot_address = (char *)ins_pivot_req->node;
	size_t pivot_key_size = key_splice_get_key_size(ins_pivot_req->key_splice) + key_splice_get_metadata_size();
	memcpy(&pivot_address[pivot_offt_in_node], ins_pivot_req->key_splice, pivot_key_size);
	memcpy(pivot_address + pivot_offt_in_node + pivot_key_size, ins_pivot_req->right_child,
	       sizeof(*ins_pivot_req->right_child));
	ins_pivot_req->node->header.log_size -= pivot_key_size + sizeof(*ins_pivot_req->right_child);

	slot_array[position + 1].pivot = ins_pivot_req->node->header.log_size;

	++ins_pivot_req->node->header.num_entries;

	return true;
}

bool index_append_pivot(struct insert_pivot_req *ins_pivot_req)
{
	ins_pivot_req->left_child = NULL;
	return index_internal_insert_pivot(ins_pivot_req, 1);
}

bool index_insert_pivot(struct insert_pivot_req *ins_pivot_req)
{
	// log_debug("New pivot is %u %.*s", key_splice_get_key_size(ins_pivot_req->key_splice),
	// 	  key_splice_get_key_size(ins_pivot_req->key_splice),
	// 	  key_splice_get_key_offset(ins_pivot_req->key_splice));
	return index_internal_insert_pivot(ins_pivot_req, 0);
}

static void index_internal_iterator_init(struct index_node *node, struct index_node_iterator *iterator,
					 struct key_splice *key_splice)
{
	iterator->node = node;

	iterator->num_entries = node->header.num_entries;

	if (node->header.num_entries <= 0) {
		iterator->key_splice = NULL;
		return;
	}

	iterator->key_splice = NULL;

	iterator->position = 0;
	if (!key_splice)
		return;

	bool unused_match = false;
	// TODO: (@geostyl) @gesalous you should definetly review this
	// We take a pivot_key as key so we should compare it like an index_key_type (?)
	iterator->position = index_search_get_pos(node, key_splice_get_key_offset(key_splice),
						  key_splice_get_key_size(key_splice), &unused_match);
}

void index_iterator_init_with_key(struct index_node *node, struct index_node_iterator *iterator,
				  struct key_splice *key_splice)
{
	index_internal_iterator_init(node, iterator, key_splice);
}

void index_iterator_init(struct index_node *node, struct index_node_iterator *iterator)
{
	index_internal_iterator_init(node, iterator, NULL);
}

uint8_t index_iterator_is_valid(struct index_node_iterator *iterator)
{
	return iterator->position < iterator->num_entries;
}

struct pivot_pointer *index_iterator_get_pivot_pointer(struct index_node_iterator *iterator)
{
	struct key_splice *piv_key_splice = index_iterator_get_pivot_key(iterator);
	struct pivot_pointer *piv_pointer = index_get_pivot_pointer(piv_key_splice);
	return piv_pointer;
}

struct key_splice *index_iterator_get_pivot_key(struct index_node_iterator *iterator)
{
	if (!iterator)
		BUG_ON();

	if (!index_iterator_is_valid(iterator))
		return NULL;

	struct index_slot_array_entry *slot_array = index_get_slot_array(iterator->node);
	iterator->key_splice = index_get_key_splice(iterator->node, slot_array[iterator->position].pivot);
	++iterator->position;

	return iterator->key_splice;
}

void index_split_node(struct index_node_split_request *request, struct index_node_split_reply *reply)
{
	// struct bt_rebalance_result result = { 0 };

	// result.left_child = (struct node_header *)seg_get_index_node(
	// 	ins_req->metadata.handle->db_desc, ins_req->metadata.level_id, ins_req->metadata.tree_id, 0);

	struct index_node_iterator iterator = { 0 };
	index_iterator_init(request->node, &iterator);
	struct key_splice *piv_key_splice = index_iterator_get_pivot_key(&iterator);
	index_init_node(DO_NOT_ADD_GUARD, request->left_child, internalNode);

	int32_t curr_entry = 0;

	while (index_iterator_is_valid(&iterator) && curr_entry < request->node->header.num_entries / 2) {
		struct insert_pivot_req ins_pivot_req = { .node = request->left_child,
							  .key_splice = piv_key_splice,
							  .right_child = index_get_pivot_pointer(piv_key_splice) };

		if (!index_append_pivot(&ins_pivot_req)) {
			log_fatal("Could not append to index node");
			BUG_ON();
		}
		++curr_entry;
		piv_key_splice = index_iterator_get_pivot_key(&iterator);
	}

	struct index_slot_array_entry *slot_array = index_get_slot_array(request->node);
	struct key_splice *middle_key_splice = index_get_key_splice(request->node, slot_array[curr_entry].pivot);
	// memcpy(&middle_key, middle_key, PIVOT_KEY_SIZE(middle_key));
	if (reply->pivot_buf_size < index_get_pivot_size(middle_key_splice)) {
		log_fatal("Buffer overflow in split index node provided buffer size is %u pivot size is %lu",
			  reply->pivot_buf_size, index_get_pivot_size(middle_key_splice));
		log_fatal("Middle key is size:%u key-data:%.*s", key_splice_get_key_size(middle_key_splice),
			  key_splice_get_key_size(middle_key_splice), key_splice_get_key_offset(middle_key_splice));
		assert(0);
		_exit(EXIT_FAILURE);
	}
	memcpy(reply->pivot_buf, middle_key_splice, index_get_pivot_size(middle_key_splice));

	// result.right_child = (node_header *)seg_get_index_node(
	// 	ins_req->metadata.handle->db_desc, ins_req->metadata.level_id, ins_req->metadata.tree_id, 0);

	index_init_node(DO_NOT_ADD_GUARD, (struct index_node *)request->right_child, internalNode);
	struct pivot_pointer *pivotp = index_get_pivot_pointer(middle_key_splice);
	index_add_guard(request->right_child, pivotp->child_offt);

	++curr_entry;
	while (index_iterator_is_valid(&iterator) && curr_entry < request->node->header.num_entries) {
		piv_key_splice = index_iterator_get_pivot_key(&iterator);

		struct insert_pivot_req ins_pivot_req = { .node = (struct index_node *)request->right_child,
							  .key_splice = piv_key_splice,
							  .right_child = index_get_pivot_pointer(piv_key_splice) };

		if (!index_append_pivot(&ins_pivot_req)) {
			log_fatal("Could not append to index node");
			BUG_ON();
		}
		++curr_entry;
	}
	assert(curr_entry == request->node->header.num_entries);

	/*set node heights*/
	request->left_child->header.height = request->node->header.height;
	request->right_child->header.height = request->node->header.height;
}

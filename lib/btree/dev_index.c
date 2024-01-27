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
#include "../btree/conf.h"
#include "../btree/key_splice.h"
#include "../common/common.h"
#include "btree_node.h"
#include "device_level.h"
#include "index_node.h"
#include <assert.h>
#include <log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct key_splice;

struct index_node {
	struct node_header header;
	struct {
		char rest_space[INDEX_NODE_SIZE - sizeof(struct node_header)];
	};
} __attribute__((packed));

struct dev_idx_slot_array_entry {
	uint16_t pivot;
} __attribute__((packed));

static struct pivot_pointer *dev_idx_get_pivot_pointer(struct key_splice *key_splice)
{
	uint32_t key_size = key_splice_get_key_size(key_splice) + key_splice_get_metadata_size();
	return (struct pivot_pointer *)((char *)key_splice + key_size);
}

static struct dev_idx_slot_array_entry *dev_idx_get_slot_array(struct index_node *node)
{
	char *node_array = (char *)node;
	return (struct dev_idx_slot_array_entry *)&node_array[sizeof(struct node_header)];
}

static inline size_t dev_idx_get_pivot_size(struct key_splice *pivot_splice)
{
	return sizeof(struct pivot_pointer) + key_splice_get_key_size(pivot_splice) + key_splice_get_metadata_size();
}

static void dev_idx_add_guard(struct index_node *node, uint64_t child_node_dev_offt)
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
	size_t pivot_size = dev_idx_get_pivot_size(guard_splice);
	char *pivot_addr = &((char *)node)[INDEX_NODE_SIZE - pivot_size];
	memcpy(pivot_addr, guard_splice, pivot_size);
	assert(node->header.log_size == INDEX_NODE_SIZE);
	node->header.log_size -= pivot_size;
	node->header.num_entries = 1;
	struct dev_idx_slot_array_entry *slot_array = dev_idx_get_slot_array(node);
	slot_array[0].pivot = node->header.log_size;
}

static bool dev_idx_is_empty(struct index_node *node)
{
	return node->header.num_entries == 0;
}

static void dev_idx_init_node(enum add_guard_option option, struct index_node *node, nodeType_t type)
{
	if (option != ADD_GUARD && option != DO_NOT_ADD_GUARD) {
		log_fatal("Unknown guard option");
		BUG_ON();
	}
	if (!node) {
		log_warn("Canno init a null node");
		return;
	}

	node->header.type = type;
	node->header.num_entries = 0;

	node->header.height = -1;
	node->header.fragmentation = 0;
	node->header.node_size = sizeof(struct index_node);

	/*private key log for index nodes, these are unnecessary now will be deleted*/
	node->header.log_size = INDEX_NODE_SIZE;
	if (ADD_GUARD == option)
		index_add_guard(node, UINT64_MAX);
}

static uint32_t dev_idx_get_remaining_space(struct index_node *node)
{
	/*Is there enough space?*/
	uint64_t left_border_dev_offt =
		sizeof(struct node_header) + (node->header.num_entries * sizeof(struct index_slot_array_entry));
	/*What is the value of the right border if we append the pivot?*/
	uint64_t right_border_dev_offt = node->header.log_size;
	assert(right_border_dev_offt >= left_border_dev_offt);

	return right_border_dev_offt - left_border_dev_offt;
}

static uint32_t dev_idx_get_next_pivot_offt_in_node(struct index_node *node, struct key_splice *key_splice)
{
	uint32_t remaining_space = dev_idx_get_remaining_space(node);
	uint32_t pivot_size = dev_idx_get_pivot_size(key_splice);
	uint32_t size_needed = pivot_size + sizeof(struct index_slot_array_entry);
	//log_debug("Remaining space %u pivot_size: %lu", remaining_space, PIVOT_SIZE(key));
	return remaining_space <= size_needed ? 0 : node->header.log_size - pivot_size;
}

static inline struct key_splice *dev_idx_get_key_splice(struct index_node *node, uint16_t offset)
{
	return (struct key_splice *)((uintptr_t)node + offset);
}

/**
 * Returns the position in the node header children offt array which we need to follow based on the lookup_key.
 * The actual offset is at node->children_offt[position]
 */
static int32_t dev_idx_search_get_pos(struct index_node *node, char *lookup_key, int32_t lookup_key_size,
				      bool *exact_match)
{
	assert(lookup_key_size >= 0);
	assert(lookup_key_size <= MAX_KEY_SIZE);
	*exact_match = false;

	int comparison_return_value = 0;
	int32_t start = 0;
	int32_t end = node->header.num_entries - 1;

	int32_t middle = 0;
	struct dev_idx_slot_array_entry *slot_array = dev_idx_get_slot_array(node);

	while (start <= end) {
		middle = (start + end) / 2;

		struct key_splice *index_splice = dev_idx_get_key_splice(node, slot_array[middle].pivot);

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

bool dev_idx_set_type(struct index_node *node, const nodeType_t node_type)
{
	if (!node)
		return false;

	if (node_type != internalNode && node_type != rootNode)
		return false;
	node->header.type = node_type;
	return true;
}

void dev_idx_set_height(struct index_node *node, int32_t height)
{
	if (!node)
		BUG_ON();
	node->header.height = height;
}

struct key_splice *dev_idx_remove_last_pivot_key(struct index_node *node)
{
	if (!node)
		return NULL;
	if (0 == node->header.num_entries)
		return NULL;
	int32_t position = node->header.num_entries - 1;
	struct dev_idx_slot_array_entry *slot_array = dev_idx_get_slot_array(node);
	struct key_splice *index_splice = dev_idx_get_key_splice(node, slot_array[position].pivot);
	size_t pivot_size = dev_idx_get_pivot_size(index_splice);
	struct key_splice *pivot_copy = calloc(1UL, pivot_size);
	memcpy(pivot_copy, index_splice, pivot_size);
	--node->header.num_entries;
	return pivot_copy;
}

static bool dev_idx_internal_insert_pivot(struct insert_pivot_req *ins_pivot_req, bool is_append)
{
	if (!is_append) {
		log_fatal("Only appends supported in device levels!");
		_exit(EXIT_FAILURE);
	}
	uint64_t pivot_offt_in_node =
		dev_idx_get_next_pivot_offt_in_node(ins_pivot_req->node, ins_pivot_req->key_splice);

	if (!pivot_offt_in_node)
		return false;
	int32_t position = ins_pivot_req->node->header.num_entries - 1;

	struct dev_idx_slot_array_entry *slot_array = dev_idx_get_slot_array(ins_pivot_req->node);

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

static bool dev_idx_append_pivot(struct insert_pivot_req *ins_pivot_req)
{
	ins_pivot_req->left_child = NULL;
	return dev_idx_internal_insert_pivot(ins_pivot_req, 1);
}

// static void dev_idx_internal_iterator_init(struct index_node *node, struct index_node_iterator *iterator,
// 					   struct key_splice *key_splice)
// {
// 	iterator->node = node;

// 	iterator->num_entries = node->header.num_entries;

// 	if (node->header.num_entries <= 0) {
// 		iterator->key_splice = NULL;
// 		return;
// 	}

// 	iterator->key_splice = NULL;

// 	iterator->position = 0;
// 	if (!key_splice)
// 		return;

// 	bool unused_match = false;
// 	// TODO: (@geostyl) @gesalous you should definetly review this
// 	// We take a pivot_key as key so we should compare it like an index_key_type (?)
// 	iterator->position = dev_idx_search_get_pos(node, key_splice_get_key_offset(key_splice),
// 						    key_splice_get_key_size(key_splice), &unused_match);
// }

// static void dev_idx_iterator_init_with_key(struct index_node *node, struct index_node_iterator *iterator,
// 					   struct key_splice *key_splice)
// {
// 	dev_idx_internal_iterator_init(node, iterator, key_splice);
// }

static struct key_splice *dev_idx_search_get_full_pivot(struct index_node *node, char *lookup_key,
							int32_t lookup_key_size)
{
	assert(lookup_key_size > 0);
	assert(lookup_key_size <= MAX_KEY_SIZE);
	bool unused = false; // Created here to call the function
	int32_t position = dev_idx_search_get_pos(node, lookup_key, lookup_key_size, &unused);

	struct dev_idx_slot_array_entry *slot_array = dev_idx_get_slot_array(node);
	struct key_splice *pivot_splice = dev_idx_get_key_splice(node, slot_array[position].pivot);

	return pivot_splice;
}

uint64_t dev_idx_binary_search(struct index_node *node, char *lookup_key, int32_t lookup_key_size)
{
	assert(lookup_key_size > 0);
	assert(lookup_key_size <= MAX_KEY_SIZE);
	struct key_splice *index_key_splice = dev_idx_search_get_full_pivot(node, lookup_key, lookup_key_size);
	struct pivot_pointer *piv_pointer = index_get_pivot_pointer(index_key_splice);
	return piv_pointer->child_offt;
}
// cppcheck-suppress unusedFunction
void dex_idx_node_print(struct index_node *node)
{
	(void)node;
	log_info("Node num entries %u fragmentation: %d height: %d", node->header.num_entries,
		 node->header.fragmentation, node->header.height);
}

bool dev_idx_register(struct level_index_api *index_api)
{
	index_api->index_get_pivot = dev_idx_get_pivot_pointer;

	index_api->index_init_node = dev_idx_init_node;

	index_api->index_set_height = dev_idx_set_height;

	index_api->index_set_type = dev_idx_set_type;

	index_api->index_is_empty = dev_idx_is_empty;

	index_api->index_add_guard = dev_idx_add_guard;

	index_api->index_append_pivot = dev_idx_append_pivot;

	index_api->index_remove_last_key = dev_idx_remove_last_pivot_key;

	index_api->index_search = dev_idx_binary_search;

	// index_api->index_init_iter_key = dev_idx_iterator_init_with_key;

	index_api->index_set_pivot_key = NULL;

	index_api->index_get_header = index_node_get_header;

	index_api->index_get_node_size = index_node_get_size;
	return true;
}

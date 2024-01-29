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

#define FRAC_IDX_BLOCK_SIZE 256UL

typedef enum {
	FRAC_IDX_TAIL_OFFT = 0,
	FRAC_IDX_FIRST_PIVOT_OFFT,
	FRAC_IDX_PIVOT_TAIL_OFFT,
	FRAC_IDX_FULL,
	FRAC_IDX_BLOCK_ID,
	FRAC_IDX_NUM_GUARDS,
	FRAC_IDX_SIZE
} frac_idx_counter_e;

struct index_node {
	struct node_header header;
	uint16_t counters[FRAC_IDX_SIZE];
} __attribute__((packed));

struct index_guard {
	uint16_t pivot_idx;
	uint8_t size;
	unsigned char key[];
} __attribute__((packed));

struct index_pivot {
	struct pivot_pointer pivot_pointer;
	uint16_t prev_size;
} __attribute__((packed));

static int frac_idx_comparator(void *key1, void *key2, int32_t key1_size, int32_t key2_size)
{
	int ret = memcmp(key1, key2, key1_size <= key2_size ? key1_size : key2_size);
	return ret ? ret : key1_size - key2_size;
}

static inline size_t frac_idx_calculate_splice_size(struct key_splice *pivot_splice)
{
	return key_splice_get_key_size(pivot_splice) + key_splice_get_metadata_size();
}

static struct pivot_pointer *frac_idx_get_pivot_pointer(struct key_splice *key_splice)
{
	char *buf = (char *)key_splice;
	struct index_pivot *pivot = (struct index_pivot *)&buf[frac_idx_calculate_splice_size(key_splice)];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
	return &pivot->pivot_pointer;
#pragma GCC diagnostic pop
}

static bool frac_idx_is_empty(struct index_node *node)
{
	return node->header.num_entries == 0;
}

static void frac_idx_init_node(enum add_guard_option option, struct index_node *node, nodeType_t type)
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
	node->header.node_size = INDEX_NODE_SIZE;

	/*private key log for index nodes, these are unnecessary now will be deleted*/
	node->header.log_size = INDEX_NODE_SIZE;
	node->counters[FRAC_IDX_FULL] = 0;
	node->counters[FRAC_IDX_PIVOT_TAIL_OFFT] = sizeof(struct index_node);
	node->counters[FRAC_IDX_TAIL_OFFT] = LEAF_NODE_SIZE;
	node->counters[FRAC_IDX_BLOCK_ID] = (node->counters[FRAC_IDX_TAIL_OFFT] / FRAC_IDX_BLOCK_SIZE) - 1;
	node->counters[FRAC_IDX_NUM_GUARDS] = 0;
	// log_debug("Initialized index node!");
	if (ADD_GUARD == option) {
		// log_debug("Add a guard also.");
		index_add_guard(node, UINT64_MAX);
	}
}

static uint32_t frac_idx_get_remaining_space(struct index_node *node)
{
	if (node->counters[FRAC_IDX_FULL]) {
		// log_debug("Sorry full pivots fot node: %p",(void *)node);
		return 0;
	}
	// log_debug("FRAC_IDX_TAIL_OFFT = %u FRAC_IDX_PIVOT_TAIL_OFFT = %u for node: %p", node->counters[FRAC_IDX_TAIL_OFFT],
	//    node->counters[FRAC_IDX_PIVOT_TAIL_OFFT], (void *)node);
	return node->counters[FRAC_IDX_TAIL_OFFT] - node->counters[FRAC_IDX_PIVOT_TAIL_OFFT];
}

static bool frac_idx_is_full(struct index_node *node, uint32_t key_splice_size)
{
	return frac_idx_get_remaining_space(node) < key_splice_size;
}

bool frac_idx_set_type(struct index_node *node, const nodeType_t node_type)
{
	if (!node)
		return false;

	if (node_type != internalNode && node_type != rootNode)
		return false;
	node->header.type = node_type;
	return true;
}

void frac_idx_set_height(struct index_node *node, int32_t height)
{
	if (!node)
		BUG_ON();
	node->header.height = height;
}

static inline bool frac_idx_get_pivot(struct index_node *node, struct index_pivot **pivot, uint16_t offt)
{
	if (offt < node->counters[FRAC_IDX_TAIL_OFFT]) {
		log_debug("End of entries in node: %p that has num pivot entries: %u offt: %u tail is at: %u",
			  (void *)node, node->header.num_entries, offt, node->counters[FRAC_IDX_TAIL_OFFT]);
		assert(0);
		return false;
	}

	char *node_buf = (char *)node;
	struct key_splice *splice = (struct key_splice *)&node_buf[offt];
	assert(key_splice_get_key_size(splice) <= MAX_KEY_SIZE);
	*pivot = (struct index_pivot *)&node_buf[offt + frac_idx_calculate_splice_size(splice)];
	return true;
}

struct key_splice *frac_idx_remove_last_pivot_key(struct index_node *node)
{
	if (!node)
		return NULL;
	if (0 == node->header.num_entries)
		return NULL;
	//two steps 1) nullify last pivot and 2) nullify if any guard points at it
	//locate last key splice
	char *node_buf = (char *)node;
	struct key_splice *last_key_splice = (struct key_splice *)&node_buf[node->counters[FRAC_IDX_TAIL_OFFT]];
	assert(key_splice_get_key_size(last_key_splice) <= MAX_KEY_SIZE);
	//create a copy
	size_t pivot_size = frac_idx_calculate_splice_size(last_key_splice) + sizeof(struct index_pivot);
	struct key_splice *pivot1_copy = calloc(1UL, pivot_size);
	memcpy(pivot1_copy, &node_buf[node->counters[FRAC_IDX_TAIL_OFFT]], pivot_size);
	//Forward tail and set curr tail prev size to 0
	uint16_t last_pivot_idx = node->counters[FRAC_IDX_TAIL_OFFT] + frac_idx_calculate_splice_size(last_key_splice);
	node->counters[FRAC_IDX_TAIL_OFFT] += pivot_size;
	last_key_splice = (struct key_splice *)&node_buf[node->counters[FRAC_IDX_TAIL_OFFT]];
	struct index_pivot *last_pivot =
		(struct index_pivot *)&node_buf[node->counters[FRAC_IDX_TAIL_OFFT] +
						frac_idx_calculate_splice_size(last_key_splice)];
	log_debug("Setting prev size from %u t 0", last_pivot->prev_size);
	last_pivot->prev_size = 0;
	--node->header.num_entries;

	//Now find the last guard
	if (0 == node->counters[FRAC_IDX_NUM_GUARDS])
		return (struct key_splice *)pivot1_copy;
	uint16_t last_offt = 0;
	for (uint16_t offt = sizeof(struct index_node); offt < node->counters[FRAC_IDX_PIVOT_TAIL_OFFT];) {
		struct index_guard *guard = (struct index_guard *)&node_buf[offt];
		offt += sizeof(struct index_guard) + guard->size;
		if (offt < node->counters[FRAC_IDX_PIVOT_TAIL_OFFT])
			break;
		last_offt = offt;
	}
	struct index_guard *guard = (struct index_guard *)&node_buf[last_offt];
	if (guard->pivot_idx == last_pivot_idx)
		--node->counters[FRAC_IDX_NUM_GUARDS];
	return (struct key_splice *)pivot1_copy;
}

static bool frac_idx_create_index_guard(struct key_splice *last_key_splice, struct key_splice *new_key_splice,
					struct index_guard *new_guard, size_t max_pivot_size)
{
	int32_t key_left_len = key_splice_get_key_size(last_key_splice);
	const char *key_left = key_splice_get_key_offset(last_key_splice);
	int32_t key_right_len = key_splice_get_key_size(new_key_splice);
	const char *key_right = key_splice_get_key_offset(new_key_splice);
	int32_t min_len = key_left_len < key_right_len ? key_left_len : key_right_len;

	// Find the common prefix length
	int32_t idx = 0;
	for (; idx < min_len && key_left[idx] == key_right[idx]; ++idx)
		;

	if (idx == key_left_len || idx == key_right_len) {
		//just use the new_splice as pivot do not bother
		if (max_pivot_size < key_splice_get_key_size(new_key_splice) + sizeof(struct index_guard))
			return false;
		new_guard->size = key_splice_get_key_size(new_key_splice);
		memcpy(new_guard->key, key_splice_get_key_offset(new_key_splice), new_guard->size);
		assert(new_guard->size > 1);
		return new_guard;
	}

	if (max_pivot_size < key_splice_get_key_size(new_key_splice) + 1 + sizeof(struct index_guard))
		return false;

	new_guard->size = idx + 1;
	memcpy(new_guard->key, key_left, idx);

	// Add an extra character
	new_guard->key[idx] = (key_left[idx] + 1 < key_right[idx]) ? key_left[idx] + 1 : key_right[idx];
	assert(key_splice_get_key_size(last_key_splice) <= MAX_KEY_SIZE);
	assert(key_splice_get_key_size(new_key_splice) <= MAX_KEY_SIZE);
	// log_debug("So last_key_splice is: %.*s size: %d new key splice is: %.*s size: %d create guard: %.*s, size: %d",
	// 	  key_splice_get_key_size(last_key_splice), key_splice_get_key_offset(last_key_splice),
	// 	  key_splice_get_key_size(last_key_splice), key_splice_get_key_size(new_key_splice),
	// 	  key_splice_get_key_offset(new_key_splice), key_splice_get_key_size(new_key_splice), new_guard->size,
	// 	  new_guard->key, new_guard->size);
	return true;
}

static bool frac_idx_add_index_guard(struct index_node *node, struct key_splice *new_key_splice,
				     uint16_t max_pivot_size)
{
	char *node_buf = (char *)node;
	struct index_guard *last_guard = (struct index_guard *)&node_buf[node->counters[FRAC_IDX_PIVOT_TAIL_OFFT]];
	struct key_splice *last_key_splice = (struct key_splice *)&node_buf[node->counters[FRAC_IDX_TAIL_OFFT]];

	if (false == frac_idx_create_index_guard(last_key_splice, new_key_splice, last_guard, max_pivot_size))
		return false;
	// log_debug("Created index guard of size: %u content %.*s", last_guard->size, last_guard->size, last_guard->key);

	assert(node->counters[FRAC_IDX_TAIL_OFFT] != INDEX_NODE_SIZE);
	last_guard->pivot_idx = node->counters[FRAC_IDX_TAIL_OFFT];
	node->counters[FRAC_IDX_PIVOT_TAIL_OFFT] += sizeof(*last_guard) + last_guard->size;
	++node->counters[FRAC_IDX_NUM_GUARDS];
	return true;
}

static bool frac_idx_append_pivot(struct insert_pivot_req *ins_pivot_req)
{
	struct index_node *node = ins_pivot_req->node;
	uint32_t key_splice_size = frac_idx_calculate_splice_size(ins_pivot_req->key_splice);
	uint32_t entry_size = sizeof(struct index_pivot) + key_splice_size;

	if (frac_idx_is_full(node, entry_size)) {
		// log_debug("Index node is full cannot serve request %u",entry_size);
		return false;
	}

	char *node_buf = (char *)node;
	uint16_t offt = ins_pivot_req->node->counters[FRAC_IDX_TAIL_OFFT] - entry_size;

	// log_debug("Adding pivot splice: %.*s of size: %d", key_splice_get_key_size(ins_pivot_req->key_splice),
	// 	  key_splice_get_key_offset(ins_pivot_req->key_splice),
	// 	  key_splice_get_key_size(ins_pivot_req->key_splice));
	/*append the actual pivot --> <key_size><key><pivot>*/
	//XXX TODO XXX add a key_splice serialize function
	struct index_pivot idx_pivot = { .prev_size = 0, .pivot_pointer = *ins_pivot_req->right_child };
	memcpy(&node_buf[offt], ins_pivot_req->key_splice, key_splice_size);
	offt += key_splice_size;
	memcpy(&node_buf[offt], &idx_pivot, sizeof(idx_pivot));

	uint32_t block_id = (node->counters[FRAC_IDX_TAIL_OFFT] - entry_size) / FRAC_IDX_BLOCK_SIZE;

	// log_debug("Block id = %u curr_block_id = %u", block_id, ins_pivot_req->node->counters[FRAC_IDX_BLOCK_ID]);
	if (ins_pivot_req->node->header.num_entries == 0 ||
	    block_id == ins_pivot_req->node->counters[FRAC_IDX_BLOCK_ID])
		goto exit_append;

	uint16_t max_pivot_size =
		(node->counters[FRAC_IDX_TAIL_OFFT] - entry_size) - node->counters[FRAC_IDX_PIVOT_TAIL_OFFT];

	struct key_splice *new_key_splice =
		(struct key_splice *)&node_buf[(node->counters[FRAC_IDX_TAIL_OFFT] - entry_size)];

	// log_debug("Going to add an index guard max pivot size = %u new_key_splice: %.*s splice size: %u node: %p",
	// 	  max_pivot_size, key_splice_get_key_size(new_key_splice), key_splice_get_key_offset(new_key_splice),
	// 	  key_splice_get_key_size(new_key_splice), (void *)node);
	assert(key_splice_get_key_size(new_key_splice) <= MAX_KEY_SIZE);
	if (false == frac_idx_add_index_guard(node, new_key_splice, max_pivot_size))
		//failed to add due to space mark as full
		node->counters[FRAC_IDX_FULL] = 1;
	else
		node->counters[FRAC_IDX_BLOCK_ID] = block_id;

exit_append:
	if (node->header.num_entries > 0) {
		struct key_splice *last_splice = (struct key_splice *)&node_buf[node->counters[FRAC_IDX_TAIL_OFFT]];
		assert(key_splice_get_key_size(last_splice) <= MAX_KEY_SIZE);
		struct index_pivot *idx_piv =
			(struct index_pivot *)&node_buf[node->counters[FRAC_IDX_TAIL_OFFT] +
							frac_idx_calculate_splice_size(last_splice)];
		assert(idx_piv->prev_size == 0);
		idx_piv->prev_size = entry_size;
	}

	node->counters[FRAC_IDX_TAIL_OFFT] -= entry_size;

	if (1 == ++node->header.num_entries)
		node->counters[FRAC_IDX_FIRST_PIVOT_OFFT] = node->counters[FRAC_IDX_TAIL_OFFT];

	return true;
}

static void frac_idx_add_pivot_guard(struct index_node *node, uint64_t child_node_frac_offt)
{
	char guard_buf[SMALLEST_KEY_SPLICE_SIZE + sizeof(struct pivot_pointer)] = { 0 };
	bool malloced = false;
	struct key_splice *guard_splice = key_splice_create_smallest(guard_buf, SMALLEST_KEY_SPLICE_SIZE, &malloced);
	if (malloced) {
		log_fatal("Guard buffer for index node is not enough");
		_exit(EXIT_FAILURE);
	}
	struct pivot_pointer pivot = { .child_offt = child_node_frac_offt };
	struct insert_pivot_req ins_req = {
		.node = node, .key_splice = guard_splice, .left_child = NULL, .right_child = &pivot
	};

	if (false == frac_idx_append_pivot(&ins_req)) {
		log_fatal("Failed to add guard");
		_exit(EXIT_FAILURE);
	}
}

static uint16_t frac_idx_seek(struct index_node *node, char *key, int32_t key_size, bool *exact_match)
{
	// log_debug("<SEEK>");
	char *node_buf = (char *)node;

	uint16_t guard_offt_a = sizeof(struct index_node);
	uint16_t guard_offt_b = 0;

	struct index_guard *guard = (struct index_guard *)&node_buf[guard_offt_a];
	int ret = 0;
	// log_debug("Searching node: %p num guards are: %u", (void *)node, node->counters[FRAC_IDX_NUM_GUARDS]);
	for (uint32_t i = 0; i < node->counters[FRAC_IDX_NUM_GUARDS]; i++) {
		ret = frac_idx_comparator(guard->key, key, guard->size, key_size);
		// log_debug("guard key: %.*s guard_key_size: %u key_size: %u ret = %d", guard->size, guard->key,
		// 	  guard->size, key_size, ret);

		if (ret > 0)
			break;

		if (ret == 0) {
			guard_offt_b = guard_offt_a;
			break;
		}

		guard_offt_b = guard_offt_a;
		guard_offt_a += sizeof(struct index_guard) + guard->size;
		guard = (struct index_guard *)&node_buf[guard_offt_a];
	}

	uint16_t pivot_idx = 0 == guard_offt_b ? node->counters[FRAC_IDX_FIRST_PIVOT_OFFT] :
						 ((struct index_guard *)(&node_buf[guard_offt_b]))->pivot_idx;

	assert(pivot_idx < INDEX_NODE_SIZE);

	// uint64_t num_cmp_sp = 0;
	/*now continue in kv section*/
	struct index_pivot *pivot = NULL;
	struct key_splice *key_splice = NULL;
	uint16_t pivot_idx_b = node->counters[FRAC_IDX_FIRST_PIVOT_OFFT];
	for (; frac_idx_get_pivot(node, &pivot, pivot_idx);) {
		key_splice = (struct key_splice *)&node_buf[pivot_idx];
		// log_debug("Found key splice: %.*s of size: %u", key_splice_get_key_size(key_splice),
		// 	  key_splice_get_key_offset(key_splice), key_splice_get_key_size(key_splice));
		ret = frac_idx_comparator(key_splice_get_key_offset(key_splice), key,
					  key_splice_get_key_size(key_splice), key_size);

		if (ret > 0) {
			//follow the previous, we have the guard so no worries
			// log_debug("</SEEK> pivot idx: %u",pivot_idx_b);
			return pivot_idx_b;
		}

		if (ret == 0) {
			*exact_match = true;
			return pivot_idx;
		}
		uint16_t prev_size = pivot->prev_size;
		if (prev_size == 0) {
			// log_debug("Prev size is 0 end of the road node num entries: %u ret: %d loops: %u",
			// 	  node->header.num_entries, ret,loops);
			break;
		}
		pivot_idx_b = pivot_idx;
		pivot_idx -= prev_size;
	}
	return pivot_idx;
}

uint64_t frac_idx_search(struct index_node *node, char *lookup_key, int32_t lookup_key_size)
{
	assert(lookup_key_size > 0);
	assert(lookup_key_size <= MAX_KEY_SIZE);
	bool exact_match = false;
	uint16_t pivot_idx = frac_idx_seek(node, lookup_key, lookup_key_size, &exact_match);
	struct index_pivot *pivot = NULL;
	frac_idx_get_pivot(node, &pivot, pivot_idx);
	return pivot->pivot_pointer.child_offt;
}

// cppcheck-suppress unusedFunction
void dex_idx_node_print(struct index_node *node)
{
	(void)node;
	log_info("Node num entries %u fragmentation: %d height: %d", node->header.num_entries,
		 node->header.fragmentation, node->header.height);
}

bool frac_idx_register(struct level_index_api *index_api)
{
	index_api->index_get_pivot = frac_idx_get_pivot_pointer;

	index_api->index_init_node = frac_idx_init_node;

	index_api->index_set_height = frac_idx_set_height;

	index_api->index_set_type = frac_idx_set_type;

	index_api->index_is_empty = frac_idx_is_empty;

	index_api->index_add_guard = frac_idx_add_pivot_guard;

	index_api->index_append_pivot = frac_idx_append_pivot;

	index_api->index_remove_last_key = frac_idx_remove_last_pivot_key;

	index_api->index_set_pivot_key = NULL;

	index_api->index_get_header = index_node_get_header;

	index_api->index_get_node_size = index_node_get_size;

	index_api->index_search = frac_idx_search;
	return true;
}

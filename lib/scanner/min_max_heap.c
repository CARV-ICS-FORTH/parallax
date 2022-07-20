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
#include "min_max_heap.h"
#include "../../utilities/dups_list.h"
#include "../btree/btree.h"
#include "../btree/conf.h"
#include "../common/common.h"
#include <assert.h>
#include <log.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LCHILD(x) ((2 * x) + 1)
#define RCHILD(x) ((2 * x) + 2)
#define PARENT(x) ((x - 1) / 2)

static void push_back_duplicate_kv(struct sh_heap *heap, struct sh_heap_node *hp_node)
{
	if (hp_node->cat != BIG_INLOG)
		return;

	struct bt_leaf_entry local;
	struct bt_leaf_entry *keyvalue = NULL;

	switch (hp_node->type) {
	case KV_FORMAT:
		memset(&local.prefix, 0x00, PREFIX_SIZE);
		uint32_t key_size = *(uint32_t *)hp_node->KV;
		int size = key_size < PREFIX_SIZE ? key_size : PREFIX_SIZE;
		memcpy(&local.prefix, hp_node->KV + sizeof(uint32_t), size);
		local.dev_offt = (uint64_t)hp_node->KV;
		keyvalue = &local;
		break;
	case KV_PREFIX:
		keyvalue = (struct bt_leaf_entry *)hp_node->KV;
		break;
	default:
		log_info("Unhandled KV type");
		_Exit(EXIT_FAILURE);
	}

	uint64_t segment_offset =
		ABSOLUTE_ADDRESS(keyvalue->dev_offt) - (ABSOLUTE_ADDRESS(keyvalue->dev_offt) % SEGMENT_SIZE);
	char *kv = (char *)keyvalue->dev_offt;
	uint32_t key_size = *(uint32_t *)kv;
	assert(key_size <= MAX_KEY_SIZE);
	uint32_t value_size = *(uint32_t *)(kv + sizeof(uint32_t) + key_size);
	struct dups_node *node = find_element(heap->dups, (uint64_t)REAL_ADDRESS(segment_offset));

	if (node)
		node->kv_size += key_size + value_size + (sizeof(uint32_t) * 2);
	else
		append_node(heap->dups, (uint64_t)REAL_ADDRESS(segment_offset),
			    key_size + value_size + (sizeof(uint32_t) * 2));
}

static int sh_solve_tie(struct sh_heap *heap, struct sh_heap_node *nd_1, struct sh_heap_node *nd_2)
{
	int ret = 1;
	nd_1->duplicate = 0;
	nd_2->duplicate = 1;
	/*Is it an L0 conflict?*/
	if (!nd_1->level_id && !nd_2->level_id) {
		/*largest epoch wins*/
		if (nd_1->epoch < nd_2->epoch) {
			nd_1->duplicate = 1;
			nd_2->duplicate = 0;
			ret = -1;
		}
	}
	/*Otherwise smallest level_id wins*/
	if (nd_1->level_id > nd_2->level_id) {
		nd_1->duplicate = 1;
		nd_2->duplicate = 0;
		ret = -1;
	}
	if (nd_1->duplicate)
		push_back_duplicate_kv(heap, nd_1);
	if (nd_2->duplicate)
		push_back_duplicate_kv(heap, nd_2);

	//log_debug("Solving tie between %s from level: %u and %s from level: %u nd_1 duplicate?: %u nd_2:duplicate?: %u",
	//	  nd_1->KV + 4, nd_1->level_id, nd_2->KV + 4, nd_2->level_id, nd_1->duplicate, nd_2->duplicate);
	return ret;
}

static int sh_prefix_compare(struct key_compare *key1, struct key_compare *key2)
{
	uint32_t size = key1->key_size <= key2->key_size ? key1->key_size : key2->key_size;
	size = size < PREFIX_SIZE ? size : PREFIX_SIZE;

	int ret = memcmp(key1->key, key2->key, size);

	if (ret)
		return ret;

	if (PREFIX_SIZE == size)
		return 0;

	return key1->key_size - key2->key_size;
}

static int sh_cmp_heap_nodes(struct sh_heap *hp, struct sh_heap_node *nd_1, struct sh_heap_node *nd_2)
{
	struct key_compare key1_cmp = { 0 };
	struct key_compare key2_cmp = { 0 };
	init_key_cmp(&key1_cmp, nd_1->KV, nd_1->type);
	init_key_cmp(&key2_cmp, nd_2->KV, nd_2->type);

	/**
    * We use a custom prefix_compare for the following reason. Default
    * key_comparator (key_cmp) for KV_PREFIX keys will fetch keys from storage if
    * prefix comparison equals 0. This means that for KV_PREFIX we need to
    * translate log pointers (if they belong to level 0) which is an expensive
    * operation. To avoid this, since this code is executed for compactions and
    * scans so it is in the critical path, we use a custom prefix_compare
    * function that stops only in prefix comparison.
    */
	int ret = sh_prefix_compare(&key1_cmp, &key2_cmp);
	if (ret) {
		// log_debug("Result is %d", ret);
		return ret;
	}
	/**
    * Going for full key comparison, we are going to end up in the full key
    * comparator
  */
	struct bt_kv_log_address key1 = { 0 };
	if (key1_cmp.key_format == KV_PREFIX) {
		key1.addr = (char *)key1_cmp.kv_dev_offt;
		if (nd_1->cat == BIG_INLOG && 0 == nd_1->level_id) {
			key1 = bt_get_kv_log_address(&nd_1->db_desc->big_log, ABSOLUTE_ADDRESS(key1_cmp.kv_dev_offt));
		}
		init_key_cmp(&key1_cmp, key1.addr, KV_FORMAT);
	}

	struct bt_kv_log_address key2 = { 0 };
	if (key2_cmp.key_format == KV_PREFIX) {
		key2.addr = (char *)key2_cmp.kv_dev_offt;
		if (nd_2->cat == BIG_INLOG && 0 == nd_2->level_id)
			key2 = bt_get_kv_log_address(&nd_2->db_desc->big_log, ABSOLUTE_ADDRESS(key2_cmp.kv_dev_offt));
		init_key_cmp(&key2_cmp, key2.addr, KV_FORMAT);
	}

	ret = key_cmp(&key1_cmp, &key2_cmp);
	key1.in_tail ? bt_done_with_value_log_address(key1.log_desc, &key1) : (void)key1;
	key2.in_tail ? bt_done_with_value_log_address(key2.log_desc, &key2) : (void)key2;

	// log_debug("Result is %d", ret);
	if (ret)
		return ret;

	return ret ? ret : sh_solve_tie(hp, nd_1, nd_2);
}
/*Allocate a min heap using dynamic memory and zero initialize it */
struct sh_heap *sh_alloc_heap(void)
{
	struct sh_heap *new_heap = calloc(1, sizeof(struct sh_heap));
	return new_heap;
}

/*
 * Function to initialize the min heap
 */
void sh_init_heap(struct sh_heap *heap, int active_tree, enum sh_heap_type heap_type)
{
	heap->heap_size = 0;
	heap->dups = init_dups_list();
	(void)active_tree;
	heap->heap_type = heap_type;
	heap->active_tree = -1;
}

/*Destroy a min heap that was allocated using dynamic memory */
void sh_destroy_heap(struct sh_heap *heap)
{
	struct dups_list *heap_destroy = heap->dups;
	free_dups_list(&heap_destroy);
	assert(NULL == heap_destroy);
	free(heap);
}

/*
    Heapify function is used to make sure that the heap property is never
   violated
    In case of deletion of a heap_node, or creating a min heap from an array,
   heap property
    may be violated. In such cases, heapify function can be called to make sure
   that
    heap property is never violated
*/
static void heapify(struct sh_heap *hp, int i)
{
	int smallest = i;
	if (LCHILD(i) < hp->heap_size && sh_cmp_heap_nodes(hp, &hp->elem[LCHILD(i)], &hp->elem[i]) < 0)
		smallest = LCHILD(i);
	if (RCHILD(i) < hp->heap_size && sh_cmp_heap_nodes(hp, &hp->elem[RCHILD(i)], &hp->elem[smallest]) < 0)
		smallest = RCHILD(i);

	if (smallest != i) {
		// swap(&(hp->elem[i]), &(hp->elem[smallest]))
		struct sh_heap_node temp = hp->elem[i];
		hp->elem[i] = hp->elem[smallest];
		hp->elem[smallest] = temp;
		heapify(hp, smallest);
	}
}

/*
    Function to insert a heap_node into the min heap, by allocating space for
    that heap_node in the heap and also making sure that the heap property and
    shape propety are never violated.
*/
void sh_insert_heap_node(struct sh_heap *hp, struct sh_heap_node *nd)
{
	nd->duplicate = 0;
	if (hp->heap_size > HEAP_SIZE) {
		log_fatal("min max heap out of space resize heap accordingly");
		BUG_ON();
	}

	int i = hp->heap_size++;
	while (i && sh_cmp_heap_nodes(hp, nd, &(hp->elem[PARENT(i)])) < 0) {
		hp->elem[i] = hp->elem[PARENT(i)];
		i = PARENT(i);
	}

	hp->elem[i] = *nd;
}

enum sh_heap_status sh_remove_top(struct sh_heap *hp, struct sh_heap_node *heap_node)
{
	if (hp->heap_size) {
		*heap_node = hp->elem[0];
		//log_debug("key is %s",heap_node->data+4);

		if (hp->heap_size == 1) { // fast path
			hp->heap_size = 0;
		} else {
			hp->elem[0] = hp->elem[--hp->heap_size];
			heapify(hp, 0);
		}
		return GOT_HEAP;
	}
	return EMPTY_HEAP;
}

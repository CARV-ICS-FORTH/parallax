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
#include "../btree/kv_pairs.h"
#include "../common/common.h"
#include "../include/parallax/structures.h"
#include <assert.h>
#include <log.h>
#include <stdint.h>
#include <stdlib.h>

#define LCHILD(x) ((2 * x) + 1)
#define RCHILD(x) ((2 * x) + 2)
#define PARENT(x) ((x - 1) / 2)

static void push_back_duplicate_kv(struct sh_heap *heap, struct sh_heap_node *hp_node)
{
	if (hp_node->splice.kv_cat != BIG_INLOG)
		return;

	uint64_t kv_offt = kv_sep2_get_value_offt(hp_node->splice.kv_sep2);

	uint64_t segment_offset = kv_offt - (kv_offt % SEGMENT_SIZE);
	struct dups_node *node = find_element(heap->dups, (uint64_t)REAL_ADDRESS(segment_offset));

	struct kv_splice *splice = REAL_ADDRESS(kv_offt);
	if (node)
		node->kv_size += kv_splice_get_kv_size(splice);
	else
		append_node(heap->dups, (uint64_t)REAL_ADDRESS(segment_offset), kv_splice_get_kv_size(splice));
}

/**
 * Solves cases when we have duplicated keys across adjacent levels. It takes
 * into account the level id of each key to solve the tie. The rule is that the
 * key with the largest level id is duplicate and is ignored.
 * @returns negative int if nd_1 < nd_2, possitive if nd_1>nd_2, and 0 if equal
 * @param heap, pointer to min max heap
 * @param nd_1 heap node containing the actual key, its corresponding level_id
 * @param nd_2 heap node containing the key and its corresponding level_id
 */
static int sh_solve_tie(struct sh_heap *heap, struct sh_heap_node *nd_1, struct sh_heap_node *nd_2)
{
	int ret = 1;
	nd_1->duplicate = 0;
	nd_2->duplicate = 1;
	/*Is it an L0 conflict?*/
	if (0 == nd_1->level_id && 0 == nd_2->level_id) {
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

/**
 * The comparator function used from the min max heap to compare node
 * @param hp the pointer to the min max heap structure
 * @param nd_1 pointer to the heap node
 * @param nd_2 pointer to the heap node
 */
static int sh_cmp_heap_nodes(struct sh_heap *hp, struct sh_heap_node *nd_1, struct sh_heap_node *nd_2)
{
	int ret = kv_splice_base_compare(&nd_1->splice, &nd_2->splice);
	return ret ? ret : sh_solve_tie(hp, nd_1, nd_2);
}
/**
 * Allocates a min heap using dynamic memory and zero initialize it
 */
struct sh_heap *sh_alloc_heap(void)
{
	return calloc(1, sizeof(struct sh_heap));
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

/**
 *Destroy a min heap that was allocated using dynamic memory
 */
void sh_destroy_heap(struct sh_heap *heap)
{
	struct dups_list *heap_destroy = heap->dups;
	free_dups_list(&heap_destroy);
	assert(NULL == heap_destroy);
	free(heap);
}

/**
 * Heapify function is used to make sure that the heap property is never
 * violated In case of deletion of a heap_node, or creating a min heap from an
 * array, heap property may be violated. In such cases, heapify function can
 * be called to make sure that heap property is never violated
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

/**
 * Function to insert a heap_node into the min heap, by allocating space for
 * that heap_node in the heap and also making sure that the heap property and
 * shape propety are never violated.
 */
void sh_insert_heap_node(struct sh_heap *heap, struct sh_heap_node *node)
{
	node->duplicate = 0;
	if (heap->heap_size > HEAP_SIZE) {
		log_fatal("min max heap out of space resize heap accordingly");
		BUG_ON();
	}

	int i = heap->heap_size++;
	while (i && sh_cmp_heap_nodes(heap, node, &(heap->elem[PARENT(i)])) < 0) {
		heap->elem[i] = heap->elem[PARENT(i)];
		i = PARENT(i);
	}

	heap->elem[i] = *node;
}

/**
 * Removes the top element of the min max heap and writes to the variable
 * pointed to by heap node pointer.
 * @returns true if it founds and element or false if the heap is
 * empty.
 */
bool sh_remove_top(struct sh_heap *heap, struct sh_heap_node *node)
{
	if (0 == heap->heap_size)
		return false;

	*node = heap->elem[0];

	--heap->heap_size;
	if (0 == heap->heap_size)
		return true;

	heap->elem[0] = heap->elem[heap->heap_size];
	heapify(heap, 0);
	return true;
}

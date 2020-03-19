/*
	File:   minHeap.c
	Desc:   Program showing various operations on a binary min heap
	Author: Robin Thomas <robinthomas2591@gmail.com>
	Edited by Giorgos Saloustros (gesalous@ics.forth.gr) 21/07/2017
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include "min_max_heap.h"
#include "../allocator/allocator.h"
#include "../btree/btree.h"
#define LCHILD(x) 2 * x + 1
#define RCHILD(x) 2 * x + 2
#define PARENT(x) (x - 1) / 2

int _cmp_heap_nodes(minHeap *hp, heap_node *nd_1, heap_node *nd_2);

/*
 * Function to initialize the min heap with size = 0
 */
void initMinHeap(minHeap *heap, int active_tree)
{
	heap->size = 0;
	heap->active_tree = active_tree;
}

/*
    Heapify function is used to make sure that the heap property is never violated
    In case of deletion of a heap_node, or creating a min heap from an array, heap property
    may be violated. In such cases, heapify function can be called to make sure that
    heap property is never violated
*/
static inline void heapify(minHeap *hp, int i)
{
	int smallest =
		(LCHILD(i) < hp->size && _cmp_heap_nodes(hp, &hp->elem[LCHILD(i)], &hp->elem[i])) ? LCHILD(i) : i;
	if (RCHILD(i) < hp->size && _cmp_heap_nodes(hp, hp->elem[RCHILD(i)].data, hp->elem[smallest].data)) {
		smallest = RCHILD(i);
	}

	if (smallest != i) {
		// swap(&(hp->elem[i]), &(hp->elem[smallest]))
		heap_node temp = {
			.data = hp->elem[i].data,
			.level_id = hp->elem[i].level_id,
			.duplicate = hp->elem[i].duplicate,
		};

		hp->elem[i].data = hp->elem[smallest].data;
		hp->elem[i].level_id = hp->elem[smallest].level_id;
		hp->elem[i].duplicate = hp->elem[smallest].duplicate;

		hp->elem[smallest].data = temp.data;
		hp->elem[smallest].level_id = temp.level_id;
		hp->elem[smallest].duplicate = temp.duplicate;
		heapify(hp, smallest);
	}
}

int _cmp_heap_nodes(minHeap *hp, heap_node *nd_1, heap_node *nd_2)
{
	int64_t ret;
	ret = _tucana_key_cmp(nd_1->data, nd_2->data, KV_FORMAT, KV_FORMAT);
	if (ret == 0) /* duplicatelicate detected smallest level_id wins, needs more thinking */
	{
		if (nd_1->level_id == hp->active_tree) {
			nd_2->duplicate = 1;
			return 1;
		} else if (nd_2->level_id == hp->active_tree) {
			nd_1->duplicate = 1;
			return -1;
		}
		if (nd_1->level_id < nd_2->level_id) {
			nd_2->duplicate = 1;
			return 1;
		} else if (nd_1->level_id > nd_2->level_id) {
			nd_1->duplicate = 1;
			return -1;
		} else {
			printf("[%s:%s:%d] FATAL cannot resolve tie\n", __FILE__, __func__, __LINE__);
			printf("[%s:%s:%d] active tree = %d nd_1 level_id = %d nd_2 level_id = %d\n", __FILE__,
			       __func__, __LINE__, hp->active_tree, nd_1->level_id, nd_2->level_id);
			printf("[%s:%s:%d] key1 %s key2 %s\n", __FILE__, __func__, __LINE__, (char *)nd_1->data + 4,
			       (char *)nd_2->data + 4);
			exit(-1);
		}
	}
	return ret;
}

/*
    Function to insert a heap_node into the min heap, by allocating space for that heap_node in the
    heap and also making sure that the heap property and shape propety are never violated.
*/
void insertheap_node(minHeap *hp, heap_node *nd)
{
	int i;

	nd->duplicate = 0;
	if (hp->size > HEAP_SIZE) {
		printf("[%s:%s:%d] FATAL min max heap out of space resize heap accordingly\n", __FILE__, __func__,
		       __LINE__);
		exit(-1);
	}

	i = hp->size++;
	while (i && _cmp_heap_nodes(hp, nd, &(hp->elem[PARENT(i)])) < 0) {
		hp->elem[i].data = hp->elem[PARENT(i)].data;
		hp->elem[i].level_id = hp->elem[PARENT(i)].level_id;
		hp->elem[i].duplicate = hp->elem[PARENT(i)].duplicate;
		i = PARENT(i);
	}

	hp->elem[i].data = nd->data;
	hp->elem[i].level_id = nd->level_id;
	hp->elem[i].duplicate = nd->duplicate;
}

uint8_t getMinAndRemove(minHeap *hp, heap_node *heap_node)
{
	if (hp->size) {
		heap_node->data = hp->elem[0].data;
		heap_node->level_id = hp->elem[0].level_id;
		heap_node->duplicate = hp->elem[0].duplicate;

		if (hp->size == 1) { // fast path
			hp->size = 0;
		} else {
			hp->elem[0] = hp->elem[--(hp->size)];
			heapify(hp, 0);
		}
		return GOT_MIN_HEAP;
	} else {
		return EMPTY_MIN_HEAP;
	}
}

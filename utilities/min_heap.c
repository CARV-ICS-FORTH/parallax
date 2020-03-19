#include <stdint.h>
#include <stdlib.h>
#include "min_heap.h"

static void swap_nodes(min_heap_node * a, min_heap_node * b);
static int64_t compare_nodes(min_heap * heap, min_heap_node * a, min_heap_node * b);



static void swap_nodes(min_heap_node * a, min_heap_node * b){
	min_heap_node tmp;
	tmp = *a;
	*a = *b;
	*b = *a;
}



static int64_t compare_nodes(min_heap * heap, min_heap_node * a, min_heap_node * b){
	int64_t res = (*heap->comparator)(a->keyValue, b->keyValue, a->key_format, b->key_format);
	if(res != 0){
		return res;
	} else{
		if(a->tree_id >= b->tree_id){
			return 1;
		} else{
			return -1;
		}
	}
}


min_heap * create_and_initialize_heap(int size){

	min_heap * new_heap = (min_heap *)malloc(sizeof(min_heap) + (size * sizeof(min_heap_node)));
	new_heap->max_size = size;
	new_heap->num_elements = 0;
	new_heap->idx = 0;
	return new_heap;
}


void add_node(min_heap * heap, void * keyValue, int key_format, int tree_id){
	
	int64_t res;
	int parent_id;
	int curr_id;
	++heap->num_elements;
	heap->nodes[heap->idx].keyValue = keyValue;
	heap->nodes[heap->idx].tree_id = tree_id;
	heap->nodes[heap->idx].key_format = key_format; 
	++heap->idx;

	/*rebalance bitches*/
	curr_id = heap->num_elements - 1; 
	parent_id = (curr_id-1)/2;
	
	while(parent_id >= 0){
		res = compare_nodes(heap, &heap->nodes[parent_id], &heap->nodes[curr_id]);
		if(res > 0){
			swap_nodes(&heap->nodes[parent_id], &heap->nodes[curr_id]);
			curr_id = parent_id;
			parent_id = (curr_id-1)/2;
		} else{
			break;
		}
	}
}



min_heap_node pop_min(min_heap * heap){

	min_heap_node *parent;
	min_heap_node * left_child;
	min_heap_node * right_child;
	min_heap_node * smallest;
	int64_t res;
	int parent_id;
	int left_child_id;
	int right_child_id;
	int smallest_id;

	min_heap_node min = heap->nodes[0];
	heap->nodes[0] = heap->nodes[heap->num_elements-1];
	--heap->num_elements;
	--heap->idx;

	parent_id = 0;
	smallest_id = 0;
	left_child_id = 1;
	right_child_id = 2;
	parent = &heap->nodes[parent_id];
	smallest = &heap->nodes[parent_id];
	left_child = &heap->nodes[left_child_id];
	right_child = &heap->nodes[right_child_id];
	
	while(1){

		if(left_child_id < heap->num_elements){
			left_child = &heap->nodes[left_child_id];
			res = compare_nodes(heap,smallest, left_child);
			if(res > 0){
				smallest = left_child;
				smallest_id = left_child_id;
			}
		} else {
			left_child = NULL;
			left_child_id = -1;
		}
		
		if(right_child_id < heap->num_elements){
			right_child = &heap->nodes[right_child_id];
			res = compare_nodes(heap,smallest, right_child);
			if(res > 0){
				smallest = right_child;
				smallest_id = right_child_id;
			}
		} else {
			right_child = NULL;
			right_child_id = -1;
		}
		if(!left_child && !right_child){
			break;
		}
		if(smallest_id == parent_id){
			break;
		}
		swap_nodes(smallest, parent);
		parent_id = smallest_id;	
		smallest_id = parent_id;
		left_child_id = (2*parent_id)-1;
		right_child_id = (2*parent_id)+1;
	}
	return min;
}















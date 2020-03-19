#pragma once
#include <stdint.h>
typedef struct min_heap_node{
	void *keyValue;
	int tree_id;
	char key_format;
}min_heap_node;


typedef struct min_heap{
	int max_size;
	int num_elements;
	int idx;
	int64_t (*comparator)(void *,void *,char,char);
	min_heap_node * nodes;
}min_heap;

min_heap * create_and_initialize_heap(int size);
void add_to_min_heap(min_heap * heap, void * keyValue, int key_format, int tree_id);
min_heap_node pop_min(min_heap * heap);


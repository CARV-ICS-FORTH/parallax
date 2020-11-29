#pragma once
#include <stdint.h>
#include "../btree/btree.h"
enum sh_heap_status { EMPTY_MIN_HEAP = 4, GOT_MIN_HEAP = 5, HEAP_SIZE = 32 };

struct sh_heap_node {
	void *KV;
	uint8_t level_id;
	uint8_t active_tree;
	uint8_t duplicate;
	enum KV_type type;
	enum log_category2 cat;
};

struct sh_min_heap {
	struct sh_heap_node elem[HEAP_SIZE];
	int size;
	int active_tree;
};

void sh_init_heap(struct sh_min_heap *heap, int active_tree);
void sh_insert_heap_node(struct sh_min_heap *hp, struct sh_heap_node *nd);
enum sh_heap_status sh_remove_min(struct sh_min_heap *hp, struct sh_heap_node *heap_node);

#pragma once
#include <stdint.h>
#include "../btree/btree.h"

enum sh_max_heap_status { EMPTY_MAX_HEAP = 4, GOT_MAX_HEAP = 5 };
#define HEAP_SIZE 32

struct sh_max_heap_node {
	void *KV;
	struct db_descriptor *db_desc;
	uint32_t kv_size;
	uint8_t level_id;
	uint8_t active_tree;
	uint8_t duplicate;
	enum KV_type type;
	enum log_category cat;
};

struct sh_max_heap {
	struct sh_max_heap_node elem[HEAP_SIZE];
	struct dups_list *dups;
	int heap_size;
	int active_tree;
};

struct sh_max_heap *sh_alloc_max_heap(void);
void sh_init_max_heap(struct sh_max_heap *heap, int active_tree);
void sh_destroy_max_heap(struct sh_max_heap *heap);
void sh_insert_max_heap_node(struct sh_max_heap *hp, struct sh_max_heap_node *nd);
enum sh_max_heap_status sh_remove_max(struct sh_max_heap *hp, struct sh_max_heap_node *heap_node);

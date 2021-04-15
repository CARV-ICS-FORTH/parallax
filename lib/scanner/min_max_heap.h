#pragma once
#include <stdint.h>
#include "../btree/btree.h"

enum sh_heap_status { EMPTY_MIN_HEAP = 4, GOT_MIN_HEAP = 5 };
#define HEAP_SIZE 32
#define GC_ARRAY_SIZE 1024

struct sh_heap_node {
	void *KV;
	uint32_t kv_size;
	uint8_t level_id;
	uint8_t active_tree;
	uint8_t duplicate;
	enum KV_type type;
	enum log_category cat;
};

struct sh_min_heap {
	struct sh_heap_node elem[HEAP_SIZE];
	struct sh_heap_node *duplicate_large_kvs;
	int heap_size;
	int dup_array_entries;
	int active_tree;
};

struct sc_full_kv {
	struct kv_format *kv;
	uint8_t deleted;
};

struct sh_min_heap *sh_alloc_heap(void);
void sh_init_heap(struct sh_min_heap *heap, int active_tree);
void sh_destroy_heap(struct sh_min_heap *heap);
void sh_insert_heap_node(struct sh_min_heap *hp, struct sh_heap_node *nd);
enum sh_heap_status sh_remove_min(struct sh_min_heap *hp, struct sh_heap_node *heap_node);

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
#pragma once
#include "../btree/btree.h"
#include <stdint.h>

enum sh_heap_type { MIN_HEAP, MAX_HEAP };
enum sh_heap_status { UNITIALIZED, INITIALIZED, EMPTY_HEAP = 4, GOT_HEAP = 5 };
#define HEAP_SIZE 32

struct sh_heap_node {
	void *KV;
	struct db_descriptor *db_desc;
	uint64_t epoch;
	uint32_t kv_size;
	uint8_t level_id;
	uint8_t active_tree;
	uint8_t duplicate;
	uint8_t tombstone : 1;
	enum KV_type type;
	enum log_category cat;
};

struct sh_heap {
	struct sh_heap_node elem[HEAP_SIZE];
	struct dups_list *dups;
	int heap_size;
	int active_tree;
	enum sh_heap_type heap_type;
};

struct sh_heap *sh_alloc_heap(void);
void sh_init_heap(struct sh_heap *heap, int active_tree, enum sh_heap_type type);
void sh_destroy_heap(struct sh_heap *heap);
void sh_insert_heap_node(struct sh_heap *hp, struct sh_heap_node *nd);
enum sh_heap_status sh_remove_top(struct sh_heap *hp, struct sh_heap_node *heap_node);

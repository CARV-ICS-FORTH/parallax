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
	assert(key_size < MAX_KEY_SIZE);
	uint32_t value_size = *(uint32_t *)(kv + sizeof(uint32_t) + key_size);
	struct dups_node *node = find_element(heap->dups, (uint64_t)REAL_ADDRESS(segment_offset));

	if (node)
		node->kv_size += key_size + value_size + (sizeof(uint32_t) * 2);
	else
		append_node(heap->dups, (uint64_t)REAL_ADDRESS(segment_offset),
			    key_size + value_size + (sizeof(uint32_t) * 2));
}

static struct bt_kv_log_address sh_translate_log_address(struct sh_heap_node *heap_node)
{
	struct bt_kv_log_address log_address = { .addr = NULL, .in_tail = 0, .tail_id = UINT8_MAX, .log_desc = NULL };

	switch (heap_node->type) {
	case KV_FORMAT:
		log_address.addr = heap_node->KV;
		break;
	case KV_PREFIX: {
		struct bt_leaf_entry *leaf_entry = (struct bt_leaf_entry *)heap_node->KV;
		log_address.addr = (void *)leaf_entry->dev_offt;
		break;
	}
	default:
		log_fatal("Wrong category");
		_Exit(EXIT_FAILURE);
	}

	switch (heap_node->cat) {
	case BIG_INLOG:
		if (!heap_node->level_id) {
			log_address =
				bt_get_kv_log_address(&heap_node->db_desc->big_log, ABSOLUTE_ADDRESS(log_address.addr));
			log_address.log_desc = &heap_node->db_desc->big_log;
		}
		break;
#if MEDIUM_LOG_UNSORTED
	case MEDIUM_INLOG:
		if (!heap_node->level_id)
			log_address = bt_get_kv_log_address(&nd_1->db_desc->medium_log,
							    ABSOLUTE_ADDRESS(log_address->pointer));
		log_address.log_desc = &heap_node->db_desc->medium_log;
		break;
#endif
	default:
		break;
	}
	return log_address;
}

static int sh_cmp_heap_nodes(struct sh_heap *hp, struct sh_heap_node *nd_1, struct sh_heap_node *nd_2)
{
	struct bt_kv_log_address L1 = sh_translate_log_address(nd_1);
	struct bt_kv_log_address L2 = sh_translate_log_address(nd_2);
	struct key_compare key1_cmp, key2_cmp;

	int64_t ret;
	if (L1.in_tail && L2.in_tail) {
		/*key1 and key2 are KV_FORMATed*/
		init_key_cmp(&key1_cmp, L1.addr, KV_FORMAT);
		init_key_cmp(&key2_cmp, L2.addr, KV_FORMAT);
		ret = key_cmp(&key1_cmp, &key2_cmp);
	} else if (L1.in_tail) {
		/*key1 is KV_FORMATED key2 is nd2->type*/
		init_key_cmp(&key1_cmp, L1.addr, KV_FORMAT);
		init_key_cmp(&key2_cmp, nd_2->KV, nd_2->type);
		ret = key_cmp(&key1_cmp, &key2_cmp);
	} else if (L2.in_tail) {
		/*key1 is nd1_type key2 is KV_FORMAT*/
		init_key_cmp(&key1_cmp, nd_1->KV, nd_1->type);
		init_key_cmp(&key2_cmp, L2.addr, KV_FORMAT);
		ret = key_cmp(&key1_cmp, &key2_cmp);
	} else {
		/*key1 is nd1_type key2 is nd2_type*/
		init_key_cmp(&key1_cmp, nd_1->KV, nd_1->type);
		init_key_cmp(&key2_cmp, nd_2->KV, nd_2->type);
		ret = key_cmp(&key1_cmp, &key2_cmp);
	}
	if (L1.in_tail)
		bt_done_with_value_log_address(L1.log_desc, &L1);
	if (L2.in_tail)
		bt_done_with_value_log_address(L2.log_desc, &L2);

	if (ret == 0) {
		if (nd_1->level_id == hp->active_tree) {
			nd_2->duplicate = 1;
			push_back_duplicate_kv(hp, nd_2);
			return 1;
		} else if (nd_2->level_id == hp->active_tree) {
			nd_1->duplicate = 1;
			push_back_duplicate_kv(hp, nd_1);
			return -1;
		}
		if (nd_1->level_id < nd_2->level_id) {
			nd_2->duplicate = 1;
			push_back_duplicate_kv(hp, nd_2);
			return 1;
		} else if (nd_1->level_id > nd_2->level_id) {
			nd_1->duplicate = 1;
			push_back_duplicate_kv(hp, nd_1);
			return -1;
		} else {
			log_fatal("Cannot resolve tie active tree = %d nd_1 level_id = %d nd_2 "
				  "level_id = %d",
				  hp->active_tree, nd_1->level_id, nd_2->level_id);
			_Exit(EXIT_FAILURE);
		}
	}
	return ret;
}
/*Allocate a min heap using dynamic memory and zero initialize it */
struct sh_heap *sh_alloc_heap(void)
{
	struct sh_heap *new_heap = calloc(1, sizeof(struct sh_heap));
	if (!new_heap) {
		log_fatal("Calloc failed");
		_Exit(EXIT_FAILURE);
	}
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

static void copy_node(struct sh_heap_node *to, struct sh_heap_node *from)
{
	to->KV = from->KV;
	to->level_id = from->level_id;
	to->cat = from->cat;
	to->duplicate = from->duplicate;
	to->db_desc = from->db_desc;
	to->type = from->type;
	to->epoch = from->epoch;
	to->kv_size = from->kv_size;
	to->active_tree = from->active_tree;
}

static int check_for_duplicate_inL0(struct sh_heap *hp, struct sh_heap_node *nd)
{
	int i = hp->heap_size;
	int ret;
	struct key_compare key1_cmp, key2_cmp;
	while (i) {
		if (hp->elem[PARENT(i)].level_id == 0 && nd->level_id == 0) {
			/*key1 is nd_type key2 is PARENT type*/
			init_key_cmp(&key1_cmp, nd->KV, nd->type);
			init_key_cmp(&key2_cmp, hp->elem[PARENT(i)].KV, hp->elem[PARENT(i)].type);
			ret = key_cmp(&key1_cmp, &key2_cmp);
			if (ret == 0) {
				copy_node(&hp->elem[PARENT(i)], nd);
				return 1;
			}
		}
		i = PARENT(i);
	}
	return 0;
}

/*
    Function to insert a heap_node into the min heap, by allocating space for
   that heap_node in the
    heap and also making sure that the heap property and shape propety are never
   violated.
*/
void sh_insert_heap_node(struct sh_heap *hp, struct sh_heap_node *nd)
{
	int i;

	nd->duplicate = 0;
	if (hp->heap_size > HEAP_SIZE) {
		log_fatal("min max heap out of space resize heap accordingly");
		BUG_ON();
	}

	if (nd->level_id == 0 && check_for_duplicate_inL0(hp, nd))
		return;

	i = hp->heap_size++;
	while (i && sh_cmp_heap_nodes(hp, nd, &(hp->elem[PARENT(i)])) < 0) {
		hp->elem[i] = hp->elem[PARENT(i)];
		// hp->elem[i].data = hp->elem[PARENT(i)].data;
		// hp->elem[i].level_id = hp->elem[PARENT(i)].level_id;
		// hp->elem[i].duplicate = hp->elem[PARENT(i)].duplicate;
		i = PARENT(i);
	}

	hp->elem[i] = *nd;
}

enum sh_heap_status sh_remove_top(struct sh_heap *hp, struct sh_heap_node *heap_node)
{
	if (hp->heap_size) {
		*heap_node = hp->elem[0];
		//log_info("key is %s",heap_node->data+4);

		if (hp->heap_size == 1) { // fast path
			hp->heap_size = 0;
		} else {
			hp->elem[0] = hp->elem[--hp->heap_size];
			heapify(hp, 0);
		}
		return GOT_HEAP;
	} else
		return EMPTY_HEAP;
}

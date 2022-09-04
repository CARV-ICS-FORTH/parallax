// Copyright[2021][FORTH - ICS]
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
#include "scanner.h"
#include "../allocator/device_structures.h"
#include "../btree/btree.h"
#include "../btree/conf.h"
#include "../btree/dynamic_leaf.h"
#include "../btree/index_node.h"
#include "../common/common.h"
#include "../utilities/dups_list.h"
#include "min_max_heap.h"
#include "stack.h"
#include <assert.h>
#include <errno.h>
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int init_level_scanner(level_scanner *level_sc, void *start_key, char seek_mode)
{
	stack_init(&level_sc->stack);

	/* position scanner now to the appropriate row */
	if (level_scanner_seek(level_sc, start_key, seek_mode) == END_OF_DATABASE) {
		stack_destroy(&(level_sc->stack));
		return -1;
	}
	level_sc->type = LEVEL_SCANNER;
	return 0;
}

void init_generic_scanner(struct scannerHandle *sc, struct db_handle *handle, void *start_key, char seek_flag,
			  char dirty)
{
	struct sh_heap_node nd = { 0 };
	uint8_t active_tree;
	int retval;

	assert(start_key);
	if (sc == NULL) {
		log_fatal("NULL scannerHandle?");
		BUG_ON();
	}

	/**
  if (!dirty && handle->db_desc->dirty) {
		log_fatal("Unsupported operation");
		BUG_ON();
	}
  **/

	/*special care for level 0 due to double buffering*/
	if (dirty) {
		/*take read lock of all levels (Level-0 client writes, other for switching trees
		*after compaction
		*/
		for (int i = 0; i < MAX_LEVELS; i++)
			RWLOCK_RDLOCK(&handle->db_desc->levels[i].guard_of_level.rx_lock);
		__sync_fetch_and_add(&handle->db_desc->levels[0].active_operations, 1);
	}

	for (int i = 0; i < MAX_LEVELS; i++) {
		for (int j = 0; j < NUM_TREES_PER_LEVEL; j++) {
			sc->LEVEL_SCANNERS[i][j].valid = 0;
			if (dirty)
				sc->LEVEL_SCANNERS[i][j].dirty = 1;
		}
	}

	sc->type = FULL_SCANNER;
	active_tree = handle->db_desc->levels[0].active_tree;
	sc->db = handle;
	if (sc->type_of_scanner != FORWARD_SCANNER) {
		log_fatal("Unknown scanner type!");
		BUG_ON();
	}
	sh_init_heap(&sc->heap, active_tree, MIN_HEAP);

	for (int i = 0; i < NUM_TREES_PER_LEVEL; ++i) {
		struct node_header *root = handle->db_desc->levels[0].root_r[i];
		if (dirty && handle->db_desc->levels[0].root_w[i] != NULL)
			root = handle->db_desc->levels[0].root_w[i];

		sc->LEVEL_SCANNERS[0][i].valid = 0;

		if (!root)
			continue;
		sc->LEVEL_SCANNERS[0][i].db = handle;
		sc->LEVEL_SCANNERS[0][i].level_id = 0;
		sc->LEVEL_SCANNERS[0][i].root = root;
		retval = init_level_scanner(&(sc->LEVEL_SCANNERS[0][i]), start_key, seek_flag);

		if (retval)
			continue;
		sc->LEVEL_SCANNERS[0][i].valid = 1;
		nd.KV = sc->LEVEL_SCANNERS[0][i].keyValue;
		nd.kv_size = sc->LEVEL_SCANNERS[0][i].kv_size;
		nd.level_id = 0;
		nd.active_tree = i;
		nd.type = KV_FORMAT;
		nd.db_desc = handle->db_desc;
		nd.tombstone = sc->LEVEL_SCANNERS[0][i].tombstone;
		nd.epoch = handle->db_desc->levels[0].epoch[i];
		nd.cat = sc->LEVEL_SCANNERS[0][i].cat;
		sh_insert_heap_node(&sc->heap, &nd);
	}

	for (uint32_t level_id = 1; level_id < MAX_LEVELS; level_id++) {
		struct node_header *root = NULL;
		/*for persistent levels it is always the 0*/
		int tree_id = 0;
		root = handle->db_desc->levels[level_id].root_w[tree_id];
		if (!root)
			root = handle->db_desc->levels[level_id].root_r[tree_id];
		if (!root)
			continue;

		sc->LEVEL_SCANNERS[level_id][tree_id].db = handle;
		sc->LEVEL_SCANNERS[level_id][tree_id].level_id = level_id;
		sc->LEVEL_SCANNERS[level_id][tree_id].root = root;
		retval = init_level_scanner(&sc->LEVEL_SCANNERS[level_id][tree_id], start_key, seek_flag);
		if (retval == 0) {
			sc->LEVEL_SCANNERS[level_id][tree_id].valid = 1;
			nd.KV = sc->LEVEL_SCANNERS[level_id][tree_id].keyValue;
			nd.kv_size = sc->LEVEL_SCANNERS[level_id][tree_id].kv_size;
			nd.type = KV_FORMAT;
			//log_info("Tree[%d][%d] gave us key %s", level_id, 0, nd.KV + 4);
			nd.level_id = level_id;
			nd.active_tree = tree_id;
			nd.db_desc = handle->db_desc;
			nd.tombstone = sc->LEVEL_SCANNERS[level_id][tree_id].tombstone;
			sh_insert_heap_node(&sc->heap, &nd);

			sc->LEVEL_SCANNERS[level_id][tree_id].valid = 1;
		}
	}

	if (sc->type_of_scanner == FORWARD_SCANNER && !get_next(sc)) {
		log_debug("Reached end of database");
		sc->keyValue = NULL;
	}
}

void init_dirty_scanner(struct scannerHandle *sc, struct db_handle *handle, void *start_key, char seek_flag)
{
	if (DB_IS_CLOSING == handle->db_desc->stat) {
		log_warn("Sorry DB: %s is closing", handle->db_desc->db_superblock->db_name);
		return;
	}

	init_generic_scanner(sc, handle, start_key, seek_flag, 1);
}

static void read_lock_node(struct level_scanner *level_sc, struct node_header *node)
{
	if (!level_sc->dirty)
		return;
	if (level_sc->level_id > 0)
		return;

	struct lock_table *lock =
		_find_position((const lock_table **)level_sc->db->db_desc->levels[0].level_lock_table, node);
	int ret = 0;
	if ((ret = RWLOCK_RDLOCK(&lock->rx_lock)) != 0) {
		switch (ret) {
		case EBUSY:
			log_fatal("EBUSY");
			break;
		case EINVAL:
			log_fatal("EINVAL");
			break;
		case EAGAIN:
			log_fatal("EAGAIN");
			break;
		case EDEADLK:
			log_fatal("EDEADLK");
			break;
		default:
			break;
		}

		log_fatal("ERROR locking");
		perror("Reason");
		BUG_ON();
	}
}

static void read_unlock_node(struct level_scanner *level_sc, struct node_header *node)
{
	if (!level_sc->dirty)
		return;

	if (level_sc->level_id > 0)
		return;

	struct lock_table *lock =
		_find_position((const lock_table **)level_sc->db->db_desc->levels[0].level_lock_table, node);
	if (RWLOCK_UNLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR locking");
		BUG_ON();
	}
}

void close_scanner(scannerHandle *scanner)
{
	/*special care for L0*/
	for (int i = 0; i < NUM_TREES_PER_LEVEL; i++) {
		if (scanner->LEVEL_SCANNERS[0][i].valid && scanner->LEVEL_SCANNERS[0][i].dirty) {
			while (1) {
				stackElementT stack_top = stack_pop(&(scanner->LEVEL_SCANNERS[0][i].stack));
				if (stack_top.guard)
					break;
				read_unlock_node(&scanner->LEVEL_SCANNERS[0][i], stack_top.node);
			}
		}
		stack_destroy(&(scanner->LEVEL_SCANNERS[0][i].stack));
	}

	for (int i = 1; i < MAX_LEVELS; i++) {
		if (scanner->LEVEL_SCANNERS[i][0].valid) {
			stack_destroy(&(scanner->LEVEL_SCANNERS[i][0].stack));
		}
	}
	/*finally*/
	if (scanner->LEVEL_SCANNERS[0][0].dirty) {
		for (int i = 0; i < MAX_LEVELS; i++)
			RWLOCK_UNLOCK(&scanner->db->db_desc->levels[i].guard_of_level.rx_lock);

		__sync_fetch_and_sub(&scanner->db->db_desc->levels[0].active_operations, 1);
	}

	free_dups_list(&scanner->heap.dups);

	free(scanner);
}

static void fill_compaction_scanner(struct level_scanner *level_sc, struct level_descriptor *level,
				    struct node_header *node, int32_t position)
{
	struct bt_dynamic_leaf_node *dlnode = (struct bt_dynamic_leaf_node *)node;
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(dlnode);
	switch (get_kv_format(slot_array[position].key_category)) {
	case KV_INPLACE: {
		level_sc->keyValue = get_kv_offset(dlnode, level->leaf_size, slot_array[position].index);
		uint32_t key_size = KEY_SIZE(level_sc->keyValue);
		uint32_t value_size = VALUE_SIZE(level_sc->keyValue + sizeof(uint32_t) + key_size);
		level_sc->kv_format = KV_FORMAT;
		level_sc->cat = slot_array[position].key_category;
		level_sc->tombstone = slot_array[position].tombstone;
		level_sc->kv_size = sizeof(key_size) + sizeof(value_size) + key_size + value_size;

		break;
	}
	case KV_INLOG: {
		struct bt_leaf_entry *kv_entry =
			(struct bt_leaf_entry *)get_kv_offset(dlnode, level->leaf_size, slot_array[position].index);
		level_sc->kv_entry = *kv_entry;
		level_sc->kv_entry.dev_offt = (uint64_t)REAL_ADDRESS(kv_entry->dev_offt);
		level_sc->keyValue = (char *)&level_sc->kv_entry;
		level_sc->cat = slot_array[position].key_category;
		level_sc->tombstone = slot_array[position].tombstone;
		level_sc->kv_size = sizeof(struct bt_leaf_entry);
		level_sc->kv_format = KV_PREFIX;
		break;
	}
	default:
		BUG_ON();
	}
}

static void fill_normal_scanner(struct level_scanner *level_sc, struct level_descriptor *level,
				struct node_header *node, int32_t position)
{
	struct bt_dynamic_leaf_node *dlnode = (struct bt_dynamic_leaf_node *)node;
	struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(dlnode);

	switch (get_kv_format(slot_array[position].key_category)) {
	case KV_INPLACE: {
		level_sc->keyValue = get_kv_offset(dlnode, level->leaf_size, slot_array[position].index);
		uint32_t key_size = KEY_SIZE(level_sc->keyValue);
		uint32_t value_size = VALUE_SIZE(level_sc->keyValue + sizeof(uint32_t) + key_size);
		level_sc->kv_size = sizeof(key_size) + sizeof(value_size) + key_size + value_size;
		level_sc->kv_format = KV_FORMAT;
		level_sc->cat = slot_array[position].key_category;
		level_sc->tombstone = slot_array[position].tombstone;
		break;
	}
	case KV_INLOG: {
		struct bt_leaf_entry *kv_entry =
			(struct bt_leaf_entry *)get_kv_offset(dlnode, level->leaf_size, slot_array[position].index);
		level_sc->kv_entry = *kv_entry;
		level_sc->kv_format = KV_FORMAT;
		level_sc->kv_entry.dev_offt = (uint64_t)REAL_ADDRESS(kv_entry->dev_offt);
		level_sc->keyValue = (void *)level_sc->kv_entry.dev_offt;

		if (level_sc->level_id) {
			uint32_t key_size = KEY_SIZE(level_sc->keyValue);
			uint32_t value_size = VALUE_SIZE(level_sc->keyValue + sizeof(uint32_t) + key_size);
			level_sc->kv_size = sizeof(key_size) + sizeof(value_size) + key_size + value_size;
		} else
			level_sc->kv_size = UINT32_MAX;
		level_sc->cat = slot_array[position].key_category;
		level_sc->tombstone = slot_array[position].tombstone;
		break;
	}
	default:
		BUG_ON();
	}
}

int32_t level_scanner_get_next(level_scanner *sc)
{
	enum level_scanner_status_t { GET_NEXT_KV = 1, POP_STACK, PUSH_STACK };

	stackElementT stack_element = stack_pop(&(sc->stack)); /*get the element*/

	if (stack_element.guard) {
		sc->keyValue = NULL;
		return END_OF_DATABASE;
	}

	if (stack_element.node->type != leafNode && stack_element.node->type != leafRootNode) {
		log_fatal("Corrupted scanner stack, top element should be a leaf node");
		assert(0);
		BUG_ON();
	}

	enum level_scanner_status_t status = GET_NEXT_KV;
	while (1) {
		switch (status) {
		case GET_NEXT_KV:
			//log_debug("get_next kv");

			if (++stack_element.idx >= stack_element.node->num_entries) {
				read_unlock_node(sc, stack_element.node);
				status = POP_STACK;
				break;
			}

			if (COMPACTION_BUFFER_SCANNER == sc->type)
				fill_compaction_scanner(sc, &sc->db->db_desc->levels[sc->level_id], stack_element.node,
							stack_element.idx);
			else
				fill_normal_scanner(sc, &sc->db->db_desc->levels[sc->level_id], stack_element.node,
						    stack_element.idx);
			//log_debug("Get next Returning Leaf:%lu idx is %d num_entries %d", stack_element.node,
			//	  stack_element.idx, stack_element.node->num_entries);
			stack_push(&sc->stack, stack_element);

			return PARALLAX_SUCCESS;

		case PUSH_STACK:;
			//log_debug("Pushing stack");
			struct pivot_pointer *pivot = index_iterator_get_pivot_pointer(&stack_element.iterator);
			stack_push(&sc->stack, stack_element);
			memset(&stack_element, 0x00, sizeof(stack_element));
			stack_element.node = REAL_ADDRESS(pivot->child_offt);

			read_lock_node(sc, stack_element.node);
			if (stack_element.node->type == leafNode || stack_element.node->type == leafRootNode) {
				stack_element.idx = -1;
				status = GET_NEXT_KV;
				break;
			}

			index_iterator_init((struct index_node *)stack_element.node, &stack_element.iterator);
			break;

		case POP_STACK:
			stack_element = stack_pop(&(sc->stack));

			if (stack_element.guard)
				return END_OF_DATABASE;

			assert(stack_element.node->type == internalNode || stack_element.node->type == rootNode);
			if (index_iterator_is_valid(&stack_element.iterator)) {
				status = PUSH_STACK;
				//log_debug("Proceeding with the next pivot of node: %lu", stack_element.node);
			} else {
				//log_debug("Done with index node unlock");
				read_unlock_node(sc, stack_element.node);
			}
			break;
		default:
			log_fatal("Unhandled state");
			BUG_ON();
		}
	}

	return PARALLAX_SUCCESS;
}

int32_t level_scanner_seek(level_scanner *level_sc, void *start_key_buf, SEEK_SCANNER_MODE mode)
{
	uint32_t level_id = level_sc->level_id;

	struct pivot_key *start_key = start_key_buf;

	// cppcheck-suppress variableScope
	char zero_key_buf[16];
	if (!start_key) {
		memset(zero_key_buf, 0x00, sizeof(zero_key_buf));
		start_key = (struct pivot_key *)zero_key_buf;
		start_key->size = 0;
	}

	/*
   * For L0 already safe we have read lock of guard lock else its just a root_r
   * of levels >= 1
	 */
	read_lock_node(level_sc, level_sc->root);

	if (!level_sc->root) {
		read_unlock_node(level_sc, level_sc->root);
		return END_OF_DATABASE;
	}

	if (level_sc->root->type == leafRootNode && level_sc->root->num_entries == 0) {
		/*we seek in an empty tree*/
		read_unlock_node(level_sc, level_sc->root);
		return END_OF_DATABASE;
	}

	/*Drop all paths*/
	stack_reset(&(level_sc->stack));
	/*Insert stack guard*/
	stackElementT guard_element = { .guard = 1, .idx = 0, .node = NULL, .iterator = { 0 } };
	stack_push(&(level_sc->stack), guard_element);

	stackElementT element = { .guard = 0, .idx = INT32_MAX, .node = NULL, .iterator = { 0 } };

	struct node_header *node = level_sc->root;

	while (node->type != leafNode && node->type != leafRootNode) {
		element.node = node;
		index_iterator_init_with_key((struct index_node *)element.node, &element.iterator, start_key);

		if (!index_iterator_is_valid(&element.iterator)) {
			log_fatal("Invalid index node iterator during seek");
			BUG_ON();
		}

		struct pivot_pointer *piv_pointer = index_iterator_get_pivot_pointer(&element.iterator);
		stack_push(&(level_sc->stack), element);

		node = REAL_ADDRESS(piv_pointer->child_offt);
		read_lock_node(level_sc, node);
	}
	assert(node->type == leafNode || node->type == leafRootNode);

	/*Whole path root to leaf is locked. Now set the element for the leaf node*/
	memset(&element, 0x00, sizeof(element));
	element.node = node;

	/*now perform binary search inside the leaf*/
	db_descriptor *db_desc = level_sc->db->db_desc;
	struct dl_bsearch_result dlresult = { .middle = 0, .status = INSERT, .op = DYNAMIC_LEAF_INSERT };
	bt_insert_req req = { 0 };

	req.key_value_buf = (char *)start_key;

	req.metadata.kv_size = PIVOT_KEY_SIZE(start_key);
	db_handle handle = { .db_desc = db_desc, .volume_desc = NULL };
	req.metadata.handle = &handle;
	req.metadata.key_format = KV_FORMAT;
	req.metadata.level_id = level_sc->level_id;
	binary_search_dynamic_leaf((struct bt_dynamic_leaf_node *)node, db_desc->levels[level_id].leaf_size, &req,
				   &dlresult);
	assert(dlresult.status != ERROR);

	element.idx = dlresult.middle;

	stack_push(&level_sc->stack, element);

	if ((mode == GREATER && FOUND == dlresult.status) || element.idx >= node->num_entries) {
		if (END_OF_DATABASE == level_scanner_get_next(level_sc))
			return END_OF_DATABASE;
	}

	element = stack_pop(&level_sc->stack);
	if (level_sc->type == COMPACTION_BUFFER_SCANNER)
		fill_compaction_scanner(level_sc, &db_desc->levels[level_sc->level_id], element.node, element.idx);
	else
		fill_normal_scanner(level_sc, &db_desc->levels[level_sc->level_id], element.node, element.idx);

	stack_push(&level_sc->stack, element);
	return PARALLAX_SUCCESS;
}

/**
 * Compaction buffer operation will use this scanner. Traversal begins from
 * root_w and free all index nodes (leaves and index) during traversal.However,
 * since we have also root_r we need to rescan root_r to free possible staff.
 * Free operations will be written in a matrix which later is gonna be sorted
 * to eliminate the duplicates and apply the free operations (applying twice a
 * free operation for the same address may result in CORRUPTION :-S
 */
level_scanner *_init_compaction_buffer_scanner(db_handle *handle, int level_id, node_header *node, void *start_key)
{
	level_scanner *level_sc = calloc(1, sizeof(level_scanner));
	if (!level_sc) {
		log_fatal("Calloc failed");
		BUG_ON();
	}
	assert(level_sc);
	stack_init(&level_sc->stack);
	level_sc->db = handle;
	level_sc->root = node;
	level_sc->level_id = level_id;
	level_sc->type = COMPACTION_BUFFER_SCANNER;

	if (level_scanner_seek(level_sc, start_key, GREATER_OR_EQUAL) == END_OF_DATABASE) {
		log_info("empty internal buffer during compaction operation, is that possible?");
		return NULL;
	}
	return level_sc;
}

void close_compaction_buffer_scanner(level_scanner *level_sc)
{
	stack_destroy(&(level_sc->stack));
	free(level_sc);
}

bool get_next(scannerHandle *scanner)
{
	while (1) {
		struct sh_heap_node node = { 0 };

		if (!sh_remove_top(&scanner->heap, &node))
			return false;

		scanner->keyValue = node.KV;
		scanner->kv_level_id = node.level_id;
		scanner->kv_cat = scanner->LEVEL_SCANNERS[node.level_id][node.active_tree].cat;
		assert(scanner->LEVEL_SCANNERS[node.level_id][node.active_tree].valid);
		if (level_scanner_get_next(&(scanner->LEVEL_SCANNERS[node.level_id][node.active_tree])) !=
		    END_OF_DATABASE) {
			struct sh_heap_node next_node = { 0 };
			next_node.level_id = node.level_id;
			next_node.active_tree = node.active_tree;
			next_node.type = node.type;
			next_node.cat = scanner->LEVEL_SCANNERS[node.level_id][node.active_tree].cat;
			next_node.KV = scanner->LEVEL_SCANNERS[node.level_id][node.active_tree].keyValue;
			next_node.kv_size = scanner->LEVEL_SCANNERS[node.level_id][node.active_tree].kv_size;
			next_node.db_desc = scanner->db->db_desc;
			next_node.tombstone = scanner->LEVEL_SCANNERS[node.level_id][node.active_tree].tombstone;
			sh_insert_heap_node(&scanner->heap, &next_node);
		}
		if (node.duplicate == 1 || node.tombstone == 1) {
			//log_warn("ommiting duplicate %s", (char *)nd.KV + 4);
			continue;
		}
		return true;
	}
}

#if MEASURE_SST_USED_SPACE
void perf_preorder_count_leaf_capacity(level_descriptor *level, node_header *root)
{
	if (!root->height) {
		level->leaf_used_space += 1.0 / (level->leaf_size / root->leaf_log_size);
		++level->count_leaves;
		return;
	}

	node_header *node;
	struct index_node *inode = (struct index_node *)root;
	for (uint64_t i = 0; i < root->num_entries; i++) {
		node = REAL_ADDRESS(inode->p[i].left[0]);
		perf_preorder_count_leaf_capacity(level, node);
	}
	(void)node;
	/* node = REAL_ADDRESS(inode->p[root->num_entries].left); */
	/* perf_preorder_count_leaf_capacity(level,node); */
}

// cppcheck-suppress unusedFunction
void perf_measure_leaf_capacity(db_handle *hd, int level_id)
{
	node_header *root = hd->db_desc->levels[level_id].root_r[0];
	assert(root);
	level_descriptor *level = &hd->db_desc->levels[level_id];
	log_info("level_id %d", level_id);
	perf_preorder_count_leaf_capacity(level, root);
}
#endif

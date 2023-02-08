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
#include "../btree/btree_node.h"
#include "../btree/conf.h"
#include "../btree/dynamic_leaf.h"
#include "../btree/index_node.h"
#include "../btree/key_splice.h"
#include "../btree/kv_pairs.h"
#include "../common/common.h"
#include "../include/parallax/structures.h"
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
#include <unistd.h>
struct key_splice;
bool level_scanner_init(struct level_scanner *level_scanner, db_handle *database, uint8_t level_id, uint8_t tree_id)
{
	memset(level_scanner, 0x00, sizeof(*level_scanner));
	stack_init(&level_scanner->stack);
	level_scanner->db = database;
	level_scanner->level_id = level_id;
	level_scanner->is_compaction_scanner = false;
	level_scanner->root = database->db_desc->levels[level_id].root[tree_id];

	return true;
}

static void read_lock_node(struct level_scanner *level_scanner, struct node_header *node)
{
	if (level_scanner->level_id > 0)
		return;

	struct lock_table *lock =
		find_lock_position((const lock_table **)level_scanner->db->db_desc->levels[0].level_lock_table, node);
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
	if (level_sc->level_id > 0)
		return;

	struct lock_table *lock =
		find_lock_position((const lock_table **)level_sc->db->db_desc->levels[0].level_lock_table, node);
	if (RWLOCK_UNLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR locking");
		BUG_ON();
	}
}

bool level_scanner_seek(struct level_scanner *level_scanner, struct key_splice *start_key_splice,
			enum seek_scanner_mode seek_mode)
{
	// cppcheck-suppress variableScope
	char smallest_possible_pivot[SMALLEST_POSSIBLE_PIVOT_SIZE];
	if (!start_key_splice) {
		bool malloced = false;
		start_key_splice =
			key_splice_create_smallest(smallest_possible_pivot, SMALLEST_POSSIBLE_PIVOT_SIZE, &malloced);
		if (malloced) {
			log_fatal("Buffer not large enough to create smallest possible key_splice");
			_exit(EXIT_FAILURE);
		}
	}
	/*
   * For L0 already safe we have read lock of guard lock else its just a root_r
   * of levels >= 1
	 */
	read_lock_node(level_scanner, level_scanner->root);

	if (!level_scanner->root) {
		read_unlock_node(level_scanner, level_scanner->root);
		return false;
	}

	if (level_scanner->root->type == leafRootNode && level_scanner->root->num_entries == 0) {
		/*we seek in an empty tree*/
		read_unlock_node(level_scanner, level_scanner->root);
		return false;
	}

	/*Drop all paths*/
	stack_reset(&(level_scanner->stack));
	/*Insert stack guard*/
	stackElementT guard_element = { .guard = 1, .idx = 0, .node = NULL, .iterator = { 0 } };
	stack_push(&(level_scanner->stack), guard_element);

	stackElementT element = { .guard = 0, .idx = INT32_MAX, .node = NULL, .iterator = { 0 } };

	struct node_header *node = level_scanner->root;
	while (node->type != leafNode && node->type != leafRootNode) {
		element.node = node;
		index_iterator_init_with_key((struct index_node *)element.node, &element.iterator, start_key_splice);

		if (!index_iterator_is_valid(&element.iterator)) {
			log_fatal("Invalid index node iterator during seek");
			BUG_ON();
		}

		struct pivot_pointer *piv_pointer = index_iterator_get_pivot_pointer(&element.iterator);
		stack_push(&(level_scanner->stack), element);

		node = REAL_ADDRESS(piv_pointer->child_offt);
		read_lock_node(level_scanner, node);
	}
	assert(node->type == leafNode || node->type == leafRootNode);

	/*Whole path root to leaf is locked and inserted into the stack. Now set the element for the leaf node*/
	memset(&element, 0x00, sizeof(element));
	element.node = node;

	/*now perform binary search inside the leaf*/

	bool exact_match = false;
	element.idx = dl_search_get_pos((struct leaf_node *)node, key_splice_get_key_offset(start_key_splice),
					key_splice_get_key_size(start_key_splice), &exact_match);

	if (!exact_match)
		++element.idx;

	stack_push(&level_scanner->stack, element);

	if ((seek_mode == GREATER && exact_match) || element.idx >= node->num_entries) {
		if (!level_scanner_get_next(level_scanner))
			return false;
	}

	element = stack_pop(&level_scanner->stack);

	level_scanner->splice = dl_get_general_splice((struct leaf_node *)element.node, element.idx);
	// log_debug("Level scanner seek reached splice %.*s at idx %d node entries %d",
	// 	  kv_splice_base_get_key_size(&level_sc->splice), kv_splice_base_get_key_buf(&level_sc->splice),
	// 	  element.idx, element.node->num_entries);
	stack_push(&level_scanner->stack, element);
	return true;
}

bool level_scanner_get_next(struct level_scanner *level_scanner)
{
	enum level_scanner_status_t { GET_NEXT_KV = 1, POP_STACK, PUSH_STACK };

	stackElementT stack_element = stack_pop(&(level_scanner->stack)); /*get the element*/

	if (stack_element.guard)
		return false;

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
				read_unlock_node(level_scanner, stack_element.node);
				status = POP_STACK;
				break;
			}

			level_scanner->splice =
				dl_get_general_splice((struct leaf_node *)stack_element.node, stack_element.idx);
			// log_debug("Get next Returning Leaf:%lu idx is %d num_entries %d", stack_element.node,
			// 	  stack_element.idx, stack_element.node->num_entries);
			stack_push(&level_scanner->stack, stack_element);

			return true;

		case PUSH_STACK:;
			//log_debug("Pushing stack");
			struct pivot_pointer *pivot = index_iterator_get_pivot_pointer(&stack_element.iterator);
			stack_push(&level_scanner->stack, stack_element);
			memset(&stack_element, 0x00, sizeof(stack_element));
			stack_element.node = REAL_ADDRESS(pivot->child_offt);

			read_lock_node(level_scanner, stack_element.node);
			if (stack_element.node->type == leafNode || stack_element.node->type == leafRootNode) {
				stack_element.idx = -1;
				status = GET_NEXT_KV;
				break;
			}

			index_iterator_init((struct index_node *)stack_element.node, &stack_element.iterator);
			break;

		case POP_STACK:
			stack_element = stack_pop(&(level_scanner->stack));

			if (stack_element.guard)
				return false;

			assert(stack_element.node->type == internalNode || stack_element.node->type == rootNode);
			if (index_iterator_is_valid(&stack_element.iterator)) {
				status = PUSH_STACK;
				//log_debug("Proceeding with the next pivot of node: %lu", stack_element.node);
			} else {
				//log_debug("Done with index node unlock");
				read_unlock_node(level_scanner, stack_element.node);
			}
			break;
		default:
			log_fatal("Unhandled state");
			BUG_ON();
		}
	}

	return true;
}

struct level_scanner *level_scanner_init_compaction_scanner(db_handle *database, uint8_t level_id, uint8_t tree_id)
{
	struct level_scanner *level_scanner = calloc(1UL, sizeof(struct level_scanner));
	if (!level_scanner_init(level_scanner, database, level_id, tree_id)) {
		log_fatal("Failed to initialize scanner");
		BUG_ON();
	}
	level_scanner->is_compaction_scanner = true;

	if (!level_scanner_seek(level_scanner, NULL, FETCH_FIRST)) {
		log_warn("empty internal buffer during compaction operation, is that possible?");
		return NULL;
	}
	log_debug("Compaction scanner initialized successfully");
	return level_scanner;
}

void level_scanner_close(struct level_scanner *level_scanner)
{
	stack_destroy(&(level_scanner->stack));
	free(level_scanner);
}

void scanner_init(struct scanner *scanner, db_handle *database, void *start_key, enum seek_scanner_mode seek_flag)
{
	if (scanner == NULL) {
		log_fatal("NULL scannerHandle?");
		BUG_ON();
	}

	if (DB_IS_CLOSING == database->db_desc->db_state) {
		log_warn("Sorry DB: %s is closing", database->db_desc->db_superblock->db_name);
		return;
	}

	for (int i = 0; i < MAX_LEVELS; i++)
		RWLOCK_RDLOCK(&database->db_desc->levels[i].guard_of_level.rx_lock);

	__sync_fetch_and_add(&database->db_desc->levels[0].active_operations, 1);

	memset(scanner, 0x00, sizeof(*scanner));

	scanner->db = database;

	sh_init_heap(&scanner->heap, database->db_desc->levels[0].active_tree, MIN_HEAP);

	for (int level_id = 0; level_id < MAX_LEVELS; ++level_id) {
		for (int tree_id = 0; tree_id < NUM_TREES_PER_LEVEL; ++tree_id) {
			if (level_id > 0 && tree_id > 0)
				continue;

			struct node_header *root = database->db_desc->levels[level_id].root[tree_id];

			if (!root)
				continue;
			level_scanner_init(&scanner->level_scanner[level_id][tree_id], database, level_id, tree_id);

			if (!level_scanner_seek(&scanner->level_scanner[level_id][tree_id], start_key, seek_flag))
				continue;

			scanner->level_scanner[level_id][tree_id].valid = 1;
			struct sh_heap_node heap_node = { 0 };
			heap_node.splice = scanner->level_scanner[level_id][tree_id].splice;
			heap_node.level_id = level_id;
			heap_node.active_tree = tree_id;
			heap_node.db_desc = database->db_desc;
			heap_node.epoch = level_id == 0 ? database->db_desc->levels[0].epoch[tree_id] : UINT64_MAX;
			// log_debug("Initializing scanner with splice size: %d data %s from level_id %u tree_id %u",
			// 	  kv_general_splice_get_key_size(&heap_node.splice),
			// 	  kv_general_splice_get_key_buf(&heap_node.splice), level_id, tree_id);
			sh_insert_heap_node(&scanner->heap, &heap_node);
		}
	}

	if (!scanner_get_next(scanner)) {
		log_debug("Reached end of database");
		scanner->keyValue = NULL;
	}
}

void scanner_close(struct scanner *scanner)
{
	/*special care for L0*/
	for (int i = 0; i < NUM_TREES_PER_LEVEL; i++) {
		if (scanner->level_scanner[0][i].valid) {
			while (1) {
				stackElementT stack_top = stack_pop(&(scanner->level_scanner[0][i].stack));
				if (stack_top.guard)
					break;
				read_unlock_node(&scanner->level_scanner[0][i], stack_top.node);
			}
		}
		stack_destroy(&(scanner->level_scanner[0][i].stack));
	}

	// for (int i = 1; i < MAX_LEVELS; i++) {
	// 	if (scanner->level_scanner[i][0].valid) {
	// 		stack_destroy(&(scanner->level_scanner[i][0].stack));
	// 	}
	// }
	for (int i = 0; i < MAX_LEVELS; i++)
		RWLOCK_UNLOCK(&scanner->db->db_desc->levels[i].guard_of_level.rx_lock);

	__sync_fetch_and_sub(&scanner->db->db_desc->levels[0].active_operations, 1);

	free_dups_list(&scanner->heap.dups);

	free(scanner);
}

bool scanner_get_next(struct scanner *scanner)
{
	while (1) {
		struct sh_heap_node node = { 0 };

		if (!sh_remove_top(&scanner->heap, &node))
			return false;

		scanner->keyValue = node.splice.kv_splice;
		if (node.splice.kv_type == KV_PREFIX) {
			uint64_t kv_dev_offt = kv_sep2_get_value_offt(node.splice.kv_sep2);
			scanner->keyValue = REAL_ADDRESS(kv_dev_offt);
		}
		scanner->kv_cat = node.splice.kv_cat;
		scanner->kv_level_id = node.level_id;

		assert(scanner->level_scanner[node.level_id][node.active_tree].valid);
		if (level_scanner_get_next(&scanner->level_scanner[node.level_id][node.active_tree])) {
			struct sh_heap_node next_node = { 0 };
			next_node.level_id = node.level_id;
			next_node.active_tree = node.active_tree;
			next_node.db_desc = scanner->db->db_desc;
			next_node.splice = scanner->level_scanner[node.level_id][node.active_tree].splice;
			sh_insert_heap_node(&scanner->heap, &next_node);
		}
		if (node.duplicate || node.splice.is_tombstone) {
			// log_warn("ommiting duplicate");
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

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
#include "../btree/device_level.h"
#include "../btree/kv_pairs.h"
#include "../common/common.h"
#include "../utilities/dups_list.h"
#include "min_max_heap.h"
#include "stack.h"
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
struct device_level;
struct node_header;
//*
//XXX TODO XXX start_key is actually a key splice please fix the API call
void scanner_seek(struct scanner *scanner, db_handle *database, void *start_key, enum seek_scanner_mode seek_flag)
{
	if (scanner == NULL) {
		log_fatal("NULL scannerHandle?");
		BUG_ON();
	}

	if (DB_IS_CLOSING == database->db_desc->db_state) {
		log_warn("Sorry DB: %s is closing", database->db_desc->db_superblock->db_name);
		return;
	}

	// memset(scanner, 0x00, sizeof(*scanner));

	RWLOCK_RDLOCK(&database->db_desc->L0.guard_of_level.rx_lock);
	__sync_fetch_and_add(&database->db_desc->L0.active_operations, 1);

	for (int level_id = 1; level_id < MAX_LEVELS; level_id++)
		scanner->tickets[level_id] = level_enter_as_reader(database->db_desc->dev_levels[level_id]);

	scanner->db = database;

	sh_init_heap(&scanner->heap, database->db_desc->L0.active_tree, MIN_HEAP);

	for (int tree_id = 0; tree_id < NUM_TREES_PER_LEVEL; ++tree_id) {
		struct node_header *root = database->db_desc->L0.root[tree_id];
		if (!root)
			continue;
		L0_scanner_init(&scanner->L0_scanner[tree_id], database, 0, tree_id);

		if (!L0_scanner_seek(&scanner->L0_scanner[tree_id], start_key, seek_flag == GREATER))
			continue;

		scanner->L0_scanner[tree_id].valid = 1;
		struct sh_heap_node heap_node = { 0 };
		heap_node.splice = scanner->L0_scanner[tree_id].splice;
		heap_node.level_id = 0;
		heap_node.active_tree = tree_id;
		heap_node.db_desc = database->db_desc;
		heap_node.epoch = database->db_desc->L0.epoch[tree_id];
		// log_debug("Initializing scanner with splice size: %d data %s from level_id %u tree_id %u",
		// 	  kv_general_splice_get_key_size(&heap_node.splice),
		// 	  kv_general_splice_get_key_buf(&heap_node.splice), level_id, tree_id);
		sh_insert_heap_node(&scanner->heap, &heap_node);
	}

	//Fill from the device levels
	scanner->dev_scanner[0] = NULL;
	for (uint8_t level_id = 1; level_id < MAX_LEVELS; level_id++) {
		//Old school
		// if (NULL == level_get_root(database->db_desc->dev_levels[level_id], 0)) {
		// 	scanner->dev_scanner[level_id] = NULL;
		// 	continue;
		// }
		if (level_is_empty(database->db_desc->dev_levels[level_id], 0)) {
			scanner->dev_scanner[level_id] = NULL;
			continue;
		}
		scanner->dev_scanner[level_id] = level_scanner_dev_init(scanner->db, level_id, 0);
		bool success = level_scanner_dev_seek(scanner->dev_scanner[level_id], start_key, seek_flag == GREATER);
		if (!success) {
			level_scanner_dev_close(scanner->dev_scanner[level_id]);
			scanner->dev_scanner[level_id] = NULL;
			continue;
		}

		struct sh_heap_node heap_node = { 0 };
		success = level_scanner_dev_curr(scanner->dev_scanner[level_id], &heap_node.splice);
		if (!success) {
			level_scanner_dev_close(scanner->dev_scanner[level_id]);
			scanner->dev_scanner[level_id] = NULL;
			continue;
		}

		heap_node.level_id = level_id;
		heap_node.active_tree = 0;
		heap_node.db_desc = database->db_desc;
		heap_node.epoch = UINT64_MAX;
		sh_insert_heap_node(&scanner->heap, &heap_node);
	}

	if (!scanner_get_next(scanner)) {
		log_debug("Reached end of database");
		scanner->keyValue = NULL;
	}
}

void scanner_close(struct scanner *scanner)
{
	/*special care for L0*/
	for (int tree_id = 0; tree_id < NUM_TREES_PER_LEVEL; tree_id++) {
		if (scanner->L0_scanner[tree_id].valid) {
			while (1) {
				stackElementT stack_top = stack_pop(&(scanner->L0_scanner[tree_id].stack));
				if (stack_top.guard)
					break;
				L0_scanner_read_unlock_node(&scanner->L0_scanner[tree_id], stack_top.node);
			}
		}
		stack_destroy(&(scanner->L0_scanner[tree_id].stack));
	}

	RWLOCK_UNLOCK(&scanner->db->db_desc->L0.guard_of_level.rx_lock);
	__sync_fetch_and_sub(&scanner->db->db_desc->L0.active_operations, 1);

	for (uint32_t level_id = 1; level_id < MAX_LEVELS; level_id++) {
		level_leave_as_reader(scanner->db->db_desc->dev_levels[level_id], scanner->tickets[level_id]);
		if (scanner->dev_scanner[level_id])
			level_scanner_dev_close(scanner->dev_scanner[level_id]);
	}

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

		// assert(scanner->level_scanner[node.level_id][node.active_tree].valid);
		//refill
		bool refill = 0 == node.level_id ? L0_scanner_get_next(&scanner->L0_scanner[node.active_tree]) :
						   level_scanner_dev_next(scanner->dev_scanner[node.level_id]);
		if (refill) {
			struct sh_heap_node next_node = { 0 };
			next_node.level_id = node.level_id;
			next_node.active_tree = node.active_tree;
			next_node.db_desc = scanner->db->db_desc;
			bool ret = true;
			if (0 == node.level_id)
				next_node.splice = scanner->L0_scanner[node.active_tree].splice;
			else
				ret = level_scanner_dev_curr(scanner->dev_scanner[node.level_id], &next_node.splice);
			if (ret)
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

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
#include <stdlib.h>
#include <string.h>

int _init_level_scanner(level_scanner *level_sc, void *start_key, char seek_mode);

static void init_generic_scanner(struct scannerHandle *sc, struct db_handle *handle, void *start_key, char seek_flag,
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

	for (int i = 0; i < NUM_TREES_PER_LEVEL; i++) {
		struct node_header *root;
		if (dirty) {
			if (handle->db_desc->levels[0].root_w[i] != NULL)
				root = handle->db_desc->levels[0].root_w[i];
			else
				root = handle->db_desc->levels[0].root_r[i];
		} else
			root = handle->db_desc->levels[0].root_r[i];

		if (root != NULL) {
			sc->LEVEL_SCANNERS[0][i].db = handle;
			sc->LEVEL_SCANNERS[0][i].level_id = 0;
			sc->LEVEL_SCANNERS[0][i].root = root;
			retval = _init_level_scanner(&(sc->LEVEL_SCANNERS[0][i]), start_key, seek_flag);

			if (retval == 0) {
				sc->LEVEL_SCANNERS[0][i].valid = 1;
				nd.KV = sc->LEVEL_SCANNERS[0][i].keyValue;
				nd.kv_size = sc->LEVEL_SCANNERS[0][i].kv_size;
				nd.level_id = 0;
				nd.active_tree = i;
				nd.type = KV_FORMAT;
				nd.db_desc = handle->db_desc;
				nd.tombstone = sc->LEVEL_SCANNERS[0][i].tombstone;
				nd.epoch = handle->db_desc->levels[0].epoch[i];
				sh_insert_heap_node(&sc->heap, &nd);

			} else
				sc->LEVEL_SCANNERS[0][i].valid = 0;
		}
	}

	for (uint32_t level_id = 1; level_id < MAX_LEVELS; level_id++) {
		struct node_header *root = NULL;
		/*for persistent levels it is always the 0*/
		int tree_id = 0;
		root = handle->db_desc->levels[level_id].root_w[tree_id];
		if (!root)
			root = handle->db_desc->levels[level_id].root_r[tree_id];

		if (root != NULL) {
			sc->LEVEL_SCANNERS[level_id][tree_id].db = handle;
			sc->LEVEL_SCANNERS[level_id][tree_id].level_id = level_id;
			sc->LEVEL_SCANNERS[level_id][tree_id].root = root;
			retval = _init_level_scanner(&sc->LEVEL_SCANNERS[level_id][tree_id], start_key, seek_flag);
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
	}

	if (sc->type_of_scanner == FORWARD_SCANNER && getNext(sc) == END_OF_DATABASE) {
		log_warn("Reached end of database");
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
		}
		log_fatal("ERROR locking");
		perror("Reason");
		assert(0);
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

void closeScanner(scannerHandle *sc)
{
	stackElementT stack_top = { 0 };
	/*special care for L0*/
	for (int i = 0; i < NUM_TREES_PER_LEVEL; i++) {
		if (sc->LEVEL_SCANNERS[0][i].valid && sc->LEVEL_SCANNERS[0][i].dirty) {
			while (1) {
				stack_top = stack_pop(&(sc->LEVEL_SCANNERS[0][i].stack));
				if (stack_top.guard)
					break;
				read_unlock_node(&sc->LEVEL_SCANNERS[0][i], stack_top.node);
			}
		}
		stack_destroy(&(sc->LEVEL_SCANNERS[0][i].stack));
	}

	for (int i = 1; i < MAX_LEVELS; i++) {
		if (sc->LEVEL_SCANNERS[i][0].valid) {
			stack_destroy(&(sc->LEVEL_SCANNERS[i][0].stack));
		}
	}
	/*finally*/
	if (sc->LEVEL_SCANNERS[0][0].dirty) {
		for (int i = 0; i < MAX_LEVELS; i++)
			RWLOCK_UNLOCK(&sc->db->db_desc->levels[i].guard_of_level.rx_lock);

		__sync_fetch_and_sub(&sc->db->db_desc->levels[0].active_operations, 1);
	}

	free_dups_list(&sc->heap.dups);

	free(sc);
}

/*XXX TODO XXX, please check if this is legal*/
inline int isValid(scannerHandle *sc)
{
	return sc->keyValue != NULL;
}

int32_t get_key_size(scannerHandle *sc)
{
	return *(int32_t *)(sc->keyValue);
}

int32_t get_value_size(scannerHandle *sc)
{
	int32_t key_size = get_key_size(sc);
	int32_t *val_ptr = (int32_t *)((char *)(sc->keyValue) + sizeof(int32_t) + key_size);
	return *val_ptr;
}

uint32_t get_kv_size(scannerHandle *sc)
{
	uint32_t kv_size = sizeof(uint32_t) + get_key_size(sc) + sizeof(uint32_t) + get_value_size(sc);
	return kv_size;
}

//#ifdef NEW_INDEX_NODE_LAYOUT
static void new_index_fill_compaction_scanner(struct level_scanner *level_sc, struct level_descriptor *level,
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

static void new_index_fill_normal_scanner(struct level_scanner *level_sc, struct level_descriptor *level,
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
		level_sc->cat = slot_array[position].key_category;
		level_sc->tombstone = slot_array[position].tombstone;
		break;
	}
	default:
		BUG_ON();
	}
}

int32_t new_index_level_scanner_get_next(level_scanner *sc)
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
				//log_debug("Leaf idx is %d num_entries %d", stack_element.idx,
				//	  stack_element.node->num_entries);

				read_unlock_node(sc, stack_element.node);
				status = POP_STACK;
				break;
			}
			//log_debug("Leaf idx is %d num_entries %d", stack_element.idx, stack_element.node->num_entries);
			if (COMPACTION_BUFFER_SCANNER == sc->type)
				new_index_fill_compaction_scanner(sc, &sc->db->db_desc->levels[sc->level_id],
								  stack_element.node, stack_element.idx);
			else
				new_index_fill_normal_scanner(sc, &sc->db->db_desc->levels[sc->level_id],
							      stack_element.node, stack_element.idx);
			stack_push(&sc->stack, stack_element);
			return PARALLAX_SUCCESS;

		case PUSH_STACK: {
			//log_debug("Pushing stack");
			struct pivot_pointer *pivot = new_index_iterator_get_pivot_pointer(&stack_element.iterator);
			stack_push(&sc->stack, stack_element);
			memset(&stack_element, 0x00, sizeof(stack_element));
			stack_element.node = REAL_ADDRESS(pivot->child_offt);

			read_lock_node(sc, stack_element.node);
			if (stack_element.node->type == leafNode || stack_element.node->type == leafRootNode) {
				stack_element.idx = -1;
				status = GET_NEXT_KV;
				//log_debug("Found a leaf");
				break;
			}

			new_index_iterator_init((struct new_index_node *)stack_element.node, &stack_element.iterator);
			break;
		}

		case POP_STACK:
			//log_debug("Popping stack");
			stack_element = stack_pop(&(sc->stack));

			if (stack_element.guard)
				return END_OF_DATABASE;

			assert(stack_element.node->type == internalNode || stack_element.node->type == rootNode);
			if (new_index_iterator_is_valid(&stack_element.iterator)) {
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

int32_t new_index_level_scanner_seek(level_scanner *level_sc, void *start_key_buf, SEEK_SCANNER_MODE mode)
{
	uint32_t level_id = level_sc->level_id;

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
	stackElementT guard_element = {
		.guard = 1, .leftmost = 0, .rightmost = 0, .idx = 0, .node = NULL, .iterator = { 0 }
	};
	stack_push(&(level_sc->stack), guard_element);

	stackElementT element = { .guard = 0, .leftmost = 0, .rightmost = 0, .idx = 0, .node = NULL, .iterator = { 0 } };

	char zero_key_buf[64];
	struct pivot_key *start_key = start_key_buf;
	if (!start_key_buf) {
		start_key = (struct pivot_key *)zero_key_buf;
		start_key->size = 1;
		start_key->data[0] = 0x00;
	}
	struct node_header *node = level_sc->root;

	while (node->type != leafNode && node->type != leafRootNode) {
		element.node = node;
		new_index_iterator_init_with_key((struct new_index_node *)element.node, &element.iterator, start_key);

		if (!new_index_iterator_is_valid(&element.iterator)) {
			log_fatal("Invalid index node iterator during seek");
			assert(0);
			BUG_ON();
		}

		struct pivot_pointer *piv_pointer = new_index_iterator_get_pivot_pointer(&element.iterator);
		stack_push(&(level_sc->stack), element);

		node = REAL_ADDRESS(piv_pointer->child_offt);
		read_lock_node(level_sc, node);
	}

	/*Whole path root to leaf is locked. Now set the element for the leaf node*/
	memset(&element, 0x00, sizeof(element));
	element.node = node;

	/*now perform binary search inside the leaf*/
	db_descriptor *db_desc = level_sc->db->db_desc;
	struct dl_bsearch_result dlresult = { .middle = 0, .status = INSERT, .op = DYNAMIC_LEAF_INSERT, .debug = 0 };
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
		if (END_OF_DATABASE == new_index_level_scanner_get_next(level_sc))
			return END_OF_DATABASE;
	}

	element = stack_pop(&level_sc->stack);
	if (level_sc->type == COMPACTION_BUFFER_SCANNER)
		new_index_fill_compaction_scanner(level_sc, &db_desc->levels[level_sc->level_id], element.node,
						  element.idx);
	else
		new_index_fill_normal_scanner(level_sc, &db_desc->levels[level_sc->level_id], element.node,
					      element.idx);

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
	/*typicall 20 bytes 8 prefix the address to the KV log
	 position scanner now to the appropriate row */
#ifdef NEW_INDEX_NODE_LAYOUT
	if (new_index_level_scanner_seek(level_sc, start_key, GREATER_OR_EQUAL) == END_OF_DATABASE) {
		log_info("empty internal buffer during compaction operation, is that possible?");
		return NULL;
	}
#else
	if (_seek_scanner(level_sc, start_key, GREATER_OR_EQUAL) == END_OF_DATABASE) {
		log_info("empty internal buffer during compaction operation, is that possible?");
		return NULL;
	}
#endif
	return level_sc;
}

int _init_level_scanner(level_scanner *level_sc, void *start_key, char seek_mode)
{
	stack_init(&level_sc->stack);

	/* position scanner now to the appropriate row */
#ifdef NEW_INDEX_NODE_LAYOUT
	if (new_index_level_scanner_seek(level_sc, start_key, seek_mode) == END_OF_DATABASE) {
		stack_destroy(&(level_sc->stack));
		return -1;
	}
#else
	if (_seek_scanner(level_sc, start_key, seek_mode) == END_OF_DATABASE) {
		// log_info("EMPTY DATABASE after seek for key %u:%s!", *(uint32_t
		// *)start_key,
		//	 start_key + sizeof(uint32_t));
		stack_destroy(&(level_sc->stack));
		return -1;
	}
#endif
	level_sc->type = LEVEL_SCANNER;
	return 0;
}

void _close_compaction_buffer_scanner(level_scanner *level_sc)
{
	stack_destroy(&(level_sc->stack));
	free(level_sc);
}

//#else
int32_t _seek_scanner(level_scanner *level_sc, void *start_key_buf, SEEK_SCANNER_MODE mode)
{
	char key_buf_prefix[PREFIX_SIZE + sizeof(uint32_t) + MAX_KEY_SIZE];
	stackElementT element;
	db_descriptor *db_desc = level_sc->db->db_desc;
	void *full_pivot_key;
	void *addr = NULL;
	struct index_node *inode;
	node_header *node;
	int64_t ret;
	uint32_t level_id = level_sc->level_id;
	int32_t middle;
	struct key_compare key1_cmp, key2_cmp;
	/*drop all paths*/
	stack_reset(&(level_sc->stack));
	/*put guard*/
	element.guard = 1;
	element.leftmost = 0;
	element.rightmost = 0;
	element.idx = 0;
	element.node = NULL;

	stack_push(&(level_sc->stack), element);
	/* for L0 already safe we have read lock of guard lock
	 * else its just a root_r of levels >= 1
	 */
	node = level_sc->root;
	read_lock_node(level_sc, node);

	if (node == NULL) {
		read_unlock_node(level_sc, node);
		return END_OF_DATABASE;
	}

	if (node->type == leafRootNode && node->num_entries == 0) {
		/*we seek in an empty tree*/
		read_unlock_node(level_sc, node);
		return END_OF_DATABASE;
	}

	while (node->type != leafNode && node->type != leafRootNode) {
		inode = (struct index_node *)node;
		int32_t start_idx = 0;
		int32_t end_idx = inode->header.num_entries - 1;

		while (1) {
			middle = (start_idx + end_idx) / 2;
			/*reconstruct full key*/
			addr = &(inode->p[middle].pivot);
			full_pivot_key = (void *)REAL_ADDRESS(*(uint64_t *)addr);
			init_key_cmp(&key1_cmp, full_pivot_key, KV_FORMAT);
			init_key_cmp(&key2_cmp, start_key_buf, KV_FORMAT);
			ret = key_cmp(&key1_cmp, &key2_cmp);

			if (ret == 0) {
				break;
			} else if (ret > 0) {
				end_idx = middle - 1;
				if (start_idx > end_idx)
					break;
			} else {
				start_idx = middle + 1;
				if (start_idx > end_idx)
					break;
			}
		}

		assert(middle < (int64_t)node->num_entries);
		element.node = node;
		element.guard = 0;
		int num_entries = node->num_entries;
		/*the path we need to follow*/
		if (ret <= 0)
			node = (node_header *)REAL_ADDRESS(inode->p[middle + 1].left);
		else
			node = (node_header *)REAL_ADDRESS(inode->p[middle].left);

		read_lock_node(level_sc, node);

		/*cornercases leftmost path and rightmost path*/
		if (middle == 0 && ret > 0) {
			/*first path of node*/
			//log_info("leftmost path");
			element.leftmost = 1;
			element.rightmost = 0;
			element.idx = 0;
		} else if (middle >= (int64_t)num_entries - 1 && ret <= 0) {
			/*last path of node*/
			//log_info("rightmost path middle = %d num entries = %d",middle, num_entries);
			//log_info("pivot %s seek key %s",full_pivot_key+4,start_key_buf+4);
			element.leftmost = 0;
			element.rightmost = 1;
			element.idx = middle;
		} else {
			element.leftmost = 0;
			element.rightmost = 0;
			if (ret > 0)
				element.idx = --middle;
			else
				element.idx = middle;
		}
		stack_push(&(level_sc->stack), element);
	}

	int kv_size = 0;
	enum KV_type key_format;
	/*reached leaf node, lock already there setup prefixes*/
	if (start_key_buf == NULL) {
		memset(key_buf_prefix, 0, sizeof(key_buf_prefix));
		key_format = KV_FORMAT;
	} else {
		uint32_t s_key_size = *(uint32_t *)start_key_buf;
		if (s_key_size >= PREFIX_SIZE) {
			memcpy(key_buf_prefix, (void *)((uint64_t)start_key_buf + sizeof(uint32_t)), PREFIX_SIZE);
		} else {
			s_key_size = *(uint32_t *)start_key_buf;
			memcpy(key_buf_prefix, (void *)((uint64_t)start_key_buf + sizeof(uint32_t)), s_key_size);
			memset(key_buf_prefix + s_key_size, 0x00, PREFIX_SIZE - s_key_size);
		}
		((struct bt_leaf_entry *)key_buf_prefix)->dev_offt = (uint64_t)start_key_buf;

		kv_size = *(uint32_t *)start_key_buf;
		key_format = KV_PREFIX;
	}

	/*now perform binary search inside the leaf*/
	middle = 0;
	struct dl_bsearch_result dlresult = { .middle = 0, .status = INSERT, .op = DYNAMIC_LEAF_FIND, .debug = 0 };
	bt_insert_req req;
	req.key_value_buf = key_buf_prefix;
	req.metadata.kv_size = kv_size;
	db_handle handle = { .db_desc = db_desc, .volume_desc = NULL };
	req.metadata.handle = &handle;
	req.metadata.key_format = key_format;
	req.metadata.level_id = level_sc->level_id;
	binary_search_dynamic_leaf((struct bt_dynamic_leaf_node *)node, db_desc->levels[level_id].leaf_size, &req,
				   &dlresult);
	assert(dlresult.status != ERROR);

	middle = dlresult.middle;

	/*further checks*/
	if (middle <= 0 && node->num_entries > 1) {
		element.node = node;
		element.idx = 0;
		element.leftmost = 1;
		element.rightmost = 0;
		element.guard = 0;
		//log_debug("Leftmost boom %llu", node->num_entries);
		stack_push(&(level_sc->stack), element);
		middle = 0;
	} else if (middle >= (int64_t)node->num_entries - 1) {
		//log_info("rightmost");
		element.node = node;
		element.idx = 0;
		element.leftmost = 0;
		element.rightmost = 1;
		element.guard = 0;
		stack_push(&(level_sc->stack), element);
		middle = node->num_entries - 1;
	} else {
		//log_info("middle is %d", middle);
		element.node = node;
		element.idx = middle;
		element.leftmost = 0;
		element.rightmost = 0;
		element.guard = 0;
		stack_push(&(level_sc->stack), element);
	}

	if (level_sc->type == COMPACTION_BUFFER_SCANNER) {
		struct bt_dynamic_leaf_node *dlnode = (struct bt_dynamic_leaf_node *)node;
		struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(dlnode);
		switch (get_kv_format(slot_array[middle].key_category)) {
		case KV_INPLACE: {
			uint32_t key_size, value_size;
			level_sc->keyValue =
				get_kv_offset(dlnode, db_desc->levels[level_id].leaf_size, slot_array[middle].index);
			key_size = KEY_SIZE(level_sc->keyValue);
			value_size = VALUE_SIZE(level_sc->keyValue + 4 + key_size);
			level_sc->kv_format = KV_FORMAT;
			level_sc->cat = slot_array[middle].key_category;
			level_sc->tombstone = slot_array[middle].tombstone;
			level_sc->kv_size = sizeof(key_size) + sizeof(value_size) + key_size + value_size;

			break;
		}
		case KV_INLOG: {
			struct bt_leaf_entry *kv_entry = (struct bt_leaf_entry *)get_kv_offset(
				dlnode, db_desc->levels[level_id].leaf_size, slot_array[middle].index);
			level_sc->kv_entry = *kv_entry;
			level_sc->kv_entry.dev_offt = (uint64_t)REAL_ADDRESS(kv_entry->dev_offt);
			level_sc->keyValue = (char *)&level_sc->kv_entry;
			level_sc->cat = slot_array[middle].key_category;
			level_sc->tombstone = slot_array[middle].tombstone;
			level_sc->kv_size = sizeof(struct bt_leaf_entry);
			level_sc->kv_format = KV_PREFIX;
			break;
		}
		default:
			BUG_ON();
		}

	} else { /*normal scanner*/
		struct bt_dynamic_leaf_node *dlnode = (struct bt_dynamic_leaf_node *)node;
		struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(dlnode);
		switch (get_kv_format(slot_array[middle].key_category)) {
		case KV_INPLACE: {
			uint32_t key_size, value_size;
			level_sc->keyValue =
				get_kv_offset(dlnode, db_desc->levels[level_id].leaf_size, slot_array[middle].index);
			key_size = KEY_SIZE(level_sc->keyValue);
			value_size = VALUE_SIZE(level_sc->keyValue + 4 + key_size);
			level_sc->kv_size = sizeof(key_size) + sizeof(value_size) + key_size + value_size;
			level_sc->kv_format = KV_FORMAT;
			/* log_info("%*s", *(uint32_t *)level_sc->keyValue, level_sc->keyValue + 4); */
			level_sc->cat = slot_array[middle].key_category;
			level_sc->tombstone = slot_array[middle].tombstone;
			break;
		}
		case KV_INLOG: {
			struct bt_leaf_entry *kv_entry = (struct bt_leaf_entry *)get_kv_offset(
				dlnode, db_desc->levels[level_id].leaf_size, slot_array[middle].index);
			level_sc->kv_entry = *kv_entry;
			level_sc->kv_format = KV_FORMAT;
			level_sc->kv_entry.dev_offt = (uint64_t)REAL_ADDRESS(kv_entry->dev_offt);
			level_sc->keyValue = (void *)level_sc->kv_entry.dev_offt;
			level_sc->cat = slot_array[middle].key_category;
			level_sc->tombstone = slot_array[middle].tombstone;
			/* REAL_ADDRESS(*(uint64_t*)get_kv_offset( */
			/* dlnode, db_desc->levels[level_id].leaf_size, slot_array[middle].index)); */
			break;
		}
		default:
			BUG_ON();
		}
	}

	if (!start_key_buf)
		return PARALLAX_SUCCESS;

	while (1) {
		struct bt_kv_log_address log_address = { .addr = level_sc->keyValue,
							 .tail_id = UINT8_MAX,
							 .in_tail = 0 };

		if (!level_sc->level_id && BIG_INLOG == level_sc->cat)
			log_address = bt_get_kv_log_address(&level_sc->db->db_desc->big_log,
							    ABSOLUTE_ADDRESS(level_sc->keyValue));
		/*key1 is level_sc->kv_format key2 is KV_FORMAT*/
		init_key_cmp(&key1_cmp, log_address.addr, level_sc->kv_format);
		init_key_cmp(&key2_cmp, start_key_buf, KV_FORMAT);
		ret = key_cmp(&key1_cmp, &key2_cmp);
		if (log_address.in_tail)
			bt_done_with_value_log_address(&level_sc->db->db_desc->big_log, &log_address);
		switch (mode) {
		case GREATER:
			if (ret <= 0)
				break;
			return PARALLAX_SUCCESS;
		case GREATER_OR_EQUAL:
			if (ret < 0)
				break;
			return PARALLAX_SUCCESS;
		default:
			log_fatal("Unknown Scanner mode");
			BUG_ON();
		}

		if (_get_next_KV(level_sc) == END_OF_DATABASE)
			return END_OF_DATABASE;
	}
	return PARALLAX_SUCCESS;
}

/**
 * 05/01/2015 11:01 : Returns a serialized buffer in the following form:
 * Key_len|key|value_length|value
 * update: 25/10/2016 14:21: for tucana_2 related scans buffer returned will
 * in the following form:
 * prefix(8 bytes)|hash(4 bytes)|address_to_data(8 bytes)
 * update: 09/03/2017 14:15: for COMPACTION_BUFFER_SCANNER only we ll return codes
 * when a leaf search is exhausted
 **/
int32_t _get_next_KV(level_scanner *sc)
{
	db_descriptor *db_desc = sc->db->db_desc;
	stackElementT stack_top;
	node_header *node;
	struct index_node *inode;
	uint32_t level_id = sc->level_id;
	int32_t idx;
	uint32_t up = 1;

	stack_top = stack_pop(&(sc->stack)); /*get the element*/
	if (stack_top.guard) {
		sc->keyValue = NULL;
		return END_OF_DATABASE;
	}
	if (stack_top.node->type != leafNode && stack_top.node->type != leafRootNode) {
		log_fatal("Corrupted scanner stack, top element should be a leaf node");
		BUG_ON();
	}
	node = stack_top.node;
	// log_info("stack top rightmost %d leftmost %d", stack_top.rightmost,
	// stack_top.leftmost);
	while (1) {
		if (up) {
			/*check if we can advance in the current node*/
			if (stack_top.rightmost) {
				read_unlock_node(sc, stack_top.node);

				stack_top = stack_pop(&(sc->stack));
				if (!stack_top.guard) {
					continue;
				} else {
					return END_OF_DATABASE;
				}
			} else if (stack_top.leftmost) {
				stack_top.leftmost = 0;

				if (stack_top.node->type == leafNode || stack_top.node->type == leafRootNode) {
					if (stack_top.node->num_entries > 1) {
						idx = 1;
						stack_top.idx = 1;
						node = stack_top.node;
						if (node->num_entries == 2)
							stack_top.rightmost = 1;
						stack_push(&sc->stack, stack_top);
						break;
					} else {
						stack_top = stack_pop(&(sc->stack));
						if (!stack_top.guard) {
							continue;
						} else
							return END_OF_DATABASE;
					}
				} else if (stack_top.node->type == internalNode || stack_top.node->type == rootNode) {
					/*special case applies only for the root*/
					if (stack_top.node->num_entries == 1)
						stack_top.rightmost = 1;
					stack_top.idx = 0;
					stack_push(&sc->stack, stack_top);
					inode = (struct index_node *)stack_top.node;
					node = (node_header *)REAL_ADDRESS(inode->p[1].left);
					assert(node->type == rootNode || node->type == leafRootNode ||
					       node->type == internalNode || node->type == leafNode);
					up = 0;
					continue;
				} else {
					log_fatal("Corrupted node");
					BUG_ON();
				}
			} else {
				++stack_top.idx;
				if (stack_top.idx >= stack_top.node->num_entries - 1)
					stack_top.rightmost = 1;
			}
			stack_push(&sc->stack, stack_top);

			if (stack_top.node->type == leafNode || stack_top.node->type == leafRootNode) {
				idx = stack_top.idx;
				node = stack_top.node;
				break;
			} else if (stack_top.node->type == internalNode || stack_top.node->type == rootNode) {
				inode = (struct index_node *)stack_top.node;
				node = (node_header *)REAL_ADDRESS(inode->p[stack_top.idx + 1].left);
				up = 0;

				assert(node->type == rootNode || node->type == leafRootNode ||
				       node->type == internalNode || node->type == leafNode);
				continue;
			} else {
				log_fatal("Corrupted node");
				BUG_ON();
			}
		} else {
			/*push yourself, update node and continue*/
			stack_top.node = node;

			read_lock_node(sc, stack_top.node);

			stack_top.idx = 0;
			stack_top.leftmost = 1;
			stack_top.rightmost = 0;
			stack_top.guard = 0;
			stack_push(&sc->stack, stack_top);
			if (node->type == leafNode || node->type == leafRootNode) {
				// log_info("consumed first entry of leaf");
				idx = 0;
				break;
			} else if (node->type == internalNode || node->type == rootNode) {
				inode = (struct index_node *)node;
				node = (node_header *)REAL_ADDRESS(inode->p[0].left);
			} else {
				log_fatal("Reached corrupted node");
				BUG_ON();
			}
		}
	}
	/*fill buffer and return*/
	if (sc->type == COMPACTION_BUFFER_SCANNER) {
		/*prefix first*/
		struct bt_dynamic_leaf_node *dlnode = (struct bt_dynamic_leaf_node *)node;
		struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(dlnode);
		switch (get_kv_format(slot_array[idx].key_category)) {
		case KV_INPLACE: {
			uint32_t key_size, value_size;
			sc->keyValue =
				get_kv_offset(dlnode, db_desc->levels[level_id].leaf_size, slot_array[idx].index);
			key_size = KEY_SIZE(sc->keyValue);
			value_size = VALUE_SIZE(sc->keyValue + sizeof(key_size) + key_size);
			sc->kv_format = KV_FORMAT;
			sc->cat = slot_array[idx].key_category;
			sc->tombstone = slot_array[idx].tombstone;
			sc->kv_size = sizeof(key_size) + sizeof(value_size) + key_size + value_size;
			//log_info("offset %d",slot_array[idx].index);
			break;
		}
		case KV_INLOG: {
			struct bt_leaf_entry *kv_entry = (struct bt_leaf_entry *)get_kv_offset(
				dlnode, db_desc->levels[level_id].leaf_size, slot_array[idx].index);

			sc->kv_entry = *kv_entry;
			sc->kv_entry.dev_offt = (uint64_t)REAL_ADDRESS(kv_entry->dev_offt);
			sc->keyValue = (char *)&sc->kv_entry;
			sc->kv_format = KV_PREFIX;
			sc->cat = slot_array[idx].key_category;
			sc->tombstone = slot_array[idx].tombstone;
			sc->kv_size = sizeof(struct bt_leaf_entry);
			break;
		}
		default:
			BUG_ON();
			break;
		}

		assert(idx < node->num_entries);
	} else {
		// normal scanner
		struct bt_dynamic_leaf_node *dlnode = (struct bt_dynamic_leaf_node *)node;
		struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(dlnode);
		switch (get_kv_format(slot_array[idx].key_category)) {
		case KV_INPLACE: {
			uint32_t key_size, value_size;

			sc->keyValue =
				get_kv_offset(dlnode, db_desc->levels[level_id].leaf_size, slot_array[idx].index);
			assert(*(uint32_t *)sc->keyValue < 100);
			sc->kv_format = KV_FORMAT;
			sc->cat = slot_array[idx].key_category;
			sc->tombstone = slot_array[idx].tombstone;
			sc->keyValue =
				get_kv_offset(dlnode, db_desc->levels[level_id].leaf_size, slot_array[idx].index);
			key_size = KEY_SIZE(sc->keyValue);
			value_size = VALUE_SIZE(sc->keyValue + sizeof(key_size) + key_size);
			sc->kv_size = sizeof(key_size) + sizeof(value_size) + key_size + value_size;

			break;
		}
		case KV_INLOG: {
			struct bt_leaf_entry *kv_entry = (struct bt_leaf_entry *)get_kv_offset(
				dlnode, db_desc->levels[level_id].leaf_size, slot_array[idx].index);

			sc->kv_entry = *kv_entry;
			sc->kv_entry.dev_offt = (uint64_t)REAL_ADDRESS(kv_entry->dev_offt);
			sc->keyValue = (void *)sc->kv_entry.dev_offt;
			sc->kv_format = KV_FORMAT;
			sc->tombstone = slot_array[idx].tombstone;
			sc->cat = slot_array[idx].key_category;
			break;
		}
		default:
			BUG_ON();
			break;
		}
	}
	return PARALLAX_SUCCESS;
}
//#endif

int32_t getNext(scannerHandle *sc)
{
	struct sh_heap_node nd = { 0 };
	struct sh_heap_node next_nd = { 0 };

	while (1) {
		enum sh_heap_status stat = sh_remove_top(&sc->heap, &nd);
		if (stat != EMPTY_HEAP) {
			sc->keyValue = nd.KV;
			sc->kv_level_id = nd.level_id;
			sc->kv_cat = sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree].cat;
			assert(sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree].valid);
#ifdef NEW_INDEX_NODE_LAYOUT
			if (new_index_level_scanner_get_next(&(sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree])) !=
			    END_OF_DATABASE) {
#else
			if (_get_next_KV(&(sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree])) != END_OF_DATABASE) {
#endif

				//log_info("refilling from level_id %d\n", nd.level_id);
				next_nd.level_id = nd.level_id;
				next_nd.active_tree = nd.active_tree;
				next_nd.type = nd.type;
				next_nd.cat = sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree].cat;
				next_nd.KV = sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree].keyValue;
				next_nd.kv_size = sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree].kv_size;
				next_nd.db_desc = sc->db->db_desc;
				next_nd.tombstone = sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree].tombstone;
				sh_insert_heap_node(&sc->heap, &next_nd);
			}
			if (nd.duplicate == 1 || nd.tombstone == 1) {
				//log_warn("ommiting duplicate %s", (char *)nd.KV + 4);
				continue;
			}
			return PARALLAX_SUCCESS;
		}
		return END_OF_DATABASE;
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

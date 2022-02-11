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
#include "../utilities/dups_list.h"
#include "min_max_heap.h"
#include "stack.h"
#include <assert.h>
#include <log.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int _init_level_scanner(level_scanner *level_sc, void *start_key, char seek_mode);

char *node_type(nodeType_t type)
{
	switch (type) {
	case leafNode:
		return "leafNode";
	case leafRootNode:
		return "leafRootnode";
	case rootNode:
		return "rootNode";
	case internalNode:
		return "internalNode";
	default:
		assert(0);
		log_fatal("UNKNOWN NODE TYPE");
		exit(EXIT_FAILURE);
	}
}

/**
 * Compaction buffer operation will use this scanner. Traversal begins from root_w
 * and
 * free all index nodes (leaves and index) during traversal.However, since we
 * have also
 * root_r we need to rescan root_r to free possible staff. Free operations will
 * be written in a matrix
 * which later is gonna be sorted to eliminate the duplicates and apply the free
 * operations (applying twice a 	* free operation for the same address
 * may
 * result in CORRUPTION :-S
 */
level_scanner *_init_compaction_buffer_scanner(db_handle *handle, int level_id, node_header *node, void *start_key)
{
	level_scanner *level_sc = calloc(1, sizeof(level_scanner));
	if (!level_sc) {
		log_fatal("Calloc failed");
		exit(EXIT_FAILURE);
	}
	assert(level_sc);
	stack_init(&level_sc->stack);
	level_sc->db = handle;
	level_sc->root = node;
	level_sc->level_id = level_id;
	level_sc->type = COMPACTION_BUFFER_SCANNER;
	/*typicall 20 bytes 8 prefix the address to the KV log
	 position scanner now to the appropriate row */
	if (_seek_scanner(level_sc, start_key, GREATER_OR_EQUAL) == END_OF_DATABASE) {
		log_info("empty internal buffer during compaction operation, is that possible?");
		return NULL;
	}
	return level_sc;
}

void _close_compaction_buffer_scanner(level_scanner *level_sc)
{
	stack_destroy(&(level_sc->stack));
	free(level_sc);
}

static void init_generic_scanner(struct scannerHandle *sc, struct db_handle *handle, void *start_key, char seek_flag,
				 char dirty)
{
	struct sh_heap_node nd = { 0 };
	uint8_t active_tree;
	int retval;

	assert(start_key);
	if (sc == NULL) {
		log_fatal("NULL scannerHandle?");
		exit(EXIT_FAILURE);
	}

	/**
  if (!dirty && handle->db_desc->dirty) {
		log_fatal("Unsupported operation");
		exit(EXIT_FAILURE);
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
	if (sc->type_of_scanner == FORWARD_SCANNER)
		sh_init_heap(&sc->heap, active_tree, MIN_HEAP);
	else if (sc->type_of_scanner == BACKWARD_SCANNER) {
		sh_init_heap(&sc->heap, active_tree, MAX_HEAP);
	} else {
		log_fatal("Unknown scanner type!");
		assert(0);
		exit(EXIT_FAILURE);
	}

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
				if (sc->type_of_scanner == FORWARD_SCANNER) {
					nd.epoch = handle->db_desc->levels[0].epoch[i];
					sh_insert_heap_node(&sc->heap, &nd);
				} else //reverse scanners are not supported for now
					sh_insert_heap_node(&sc->heap, (struct sh_heap_node *)&nd);

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
				if (sc->type_of_scanner == FORWARD_SCANNER)
					sh_insert_heap_node(&sc->heap, &nd);
				else
					sh_insert_heap_node(&sc->heap, (struct sh_heap_node *)&nd);

				sc->LEVEL_SCANNERS[level_id][tree_id].valid = 1;
			}
		}
	}

	if (sc->type_of_scanner == FORWARD_SCANNER && getNext(sc) == END_OF_DATABASE) {
		log_warn("Reached end of database");
		sc->keyValue = NULL;
	} else if (sc->type_of_scanner == BACKWARD_SCANNER && getPrev(sc) == END_OF_DATABASE) {
		log_warn("Reached end of database");
		sc->keyValue = NULL;
	}
	return;
}

/*no snaphsot scanner (with lock)*/
void init_dirty_scanner(struct scannerHandle *sc, struct db_handle *handle, void *start_key, char seek_flag)
{
	if (DB_IS_CLOSING == handle->db_desc->stat) {
		log_warn("Sorry DB: %s is closing", handle->db_desc->db_superblock->db_name);
		return;
	}

	init_generic_scanner(sc, handle, start_key, seek_flag, 1);
}

scannerHandle *initScanner(scannerHandle *sc, db_handle *handle, void *start_key, char seek_flag)
{
	if (sc == NULL) {
		log_fatal("Null scanner is not acceptable");
		exit(EXIT_FAILURE);
	}
	init_generic_scanner(sc, handle, start_key, seek_flag, 0);
	return sc;
}

int _init_level_scanner(level_scanner *level_sc, void *start_key, char seek_mode)
{
	stack_init(&level_sc->stack);

	/* position scanner now to the appropriate row */
	if (_seek_scanner(level_sc, start_key, seek_mode) == END_OF_DATABASE) {
		// log_info("EMPTY DATABASE after seek for key %u:%s!", *(uint32_t
		// *)start_key,
		//	 start_key + sizeof(uint32_t));
		stack_destroy(&(level_sc->stack));
		return -1;
	}
	level_sc->type = LEVEL_SCANNER;
	return 0;
}

static void read_lock_node(struct level_scanner *level_sc, struct node_header *node)
{
	if (!level_sc->dirty)
		return;
	if (level_sc->level_id > 0)
		return;

	struct lock_table *lock = _find_position(level_sc->db->db_desc->levels[0].level_lock_table, node);
	if (RWLOCK_RDLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR locking");
		exit(EXIT_FAILURE);
	}
	return;
}

static void read_unlock_node(struct level_scanner *level_sc, struct node_header *node)
{
	if (!level_sc->dirty)
		return;
	if (level_sc->level_id > 0)
		return;

	struct lock_table *lock = _find_position(level_sc->db->db_desc->levels[0].level_lock_table, node);
	if (RWLOCK_UNLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR locking");
		exit(EXIT_FAILURE);
	}
	return;
}

void closeScanner(scannerHandle *sc)
{
	stackElementT stack_top;
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

void *get_key_ptr(scannerHandle *sc)
{
	return (void *)((char *)(sc->keyValue) + sizeof(int32_t));
}

int32_t get_value_size(scannerHandle *sc)
{
	int32_t key_size = get_key_size(sc);
	int32_t *val_ptr = (int32_t *)((char *)(sc->keyValue) + sizeof(int32_t) + key_size);
	return *val_ptr;
}

void *get_value_ptr(scannerHandle *sc)
{
	int32_t key_size = get_key_size(sc);
	char *val_ptr = (char *)(sc->keyValue) + sizeof(int32_t) + key_size;
	return val_ptr + sizeof(int32_t);
}

uint32_t get_kv_size(scannerHandle *sc)
{
	uint32_t kv_size = sizeof(uint32_t) + get_key_size(sc) + sizeof(uint32_t) + get_value_size(sc);
	return kv_size;
}

int32_t _seek_scanner(level_scanner *level_sc, void *start_key_buf, SEEK_SCANNER_MODE mode)
{
	char key_buf_prefix[PREFIX_SIZE + sizeof(uint32_t) + MAX_KEY_SIZE];
	stackElementT element;
	db_descriptor *db_desc = level_sc->db->db_desc;
	void *full_pivot_key;
	void *addr = NULL;
	index_node *inode;
	node_header *node;
	int64_t ret;
	uint32_t level_id = level_sc->level_id;
	int32_t start_idx = 0;
	int32_t end_idx = 0;
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
		inode = (index_node *)node;
		start_idx = 0;
		end_idx = inode->header.num_entries - 1;

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
			node = (node_header *)REAL_ADDRESS(inode->p[middle].right[0]);
		else
			node = (node_header *)REAL_ADDRESS(inode->p[middle].left[0]);

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
		switch (slot_array[middle].kv_loc) {
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
			level_sc->keyValue = &level_sc->kv_entry;
			level_sc->cat = slot_array[middle].key_category;
			level_sc->tombstone = slot_array[middle].tombstone;
			level_sc->kv_size = sizeof(struct bt_leaf_entry);
			level_sc->kv_format = KV_PREFIX;
			break;
		}
		default:
			assert(0);
		}

	} else { /*normal scanner*/
		struct bt_dynamic_leaf_node *dlnode = (struct bt_dynamic_leaf_node *)node;
		struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(dlnode);
		switch (slot_array[middle].kv_loc) {
		case KV_INPLACE:;
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
			assert(0);
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
			exit(EXIT_FAILURE);
		}

		if (_get_next_KV(level_sc) == END_OF_DATABASE)
			return END_OF_DATABASE;
	}
	return PARALLAX_SUCCESS;
}

int32_t getNext(scannerHandle *sc)
{
	enum sh_heap_status stat = { 0 };
	struct sh_heap_node nd = { 0 };
	struct sh_heap_node next_nd = { 0 };

	while (1) {
		stat = sh_remove_top(&sc->heap, &nd);
		if (stat != EMPTY_HEAP) {
			sc->keyValue = nd.KV;
			sc->kv_level_id = nd.level_id;
			sc->kv_cat = sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree].cat;
			assert(sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree].valid);
			if (_get_next_KV(&(sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree])) != END_OF_DATABASE) {
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
				// assert(0);
				//log_warn("ommiting duplicate %s", (char *)nd.KV + 4);
				continue;
			}
			return PARALLAX_SUCCESS;
		} else
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
	index_node *inode = (index_node *)root;
	for (uint64_t i = 0; i < root->num_entries; i++) {
		node = REAL_ADDRESS(inode->p[i].left[0]);
		perf_preorder_count_leaf_capacity(level, node);
	}

	/* node = REAL_ADDRESS(inode->p[root->num_entries].left); */
	/* perf_preorder_count_leaf_capacity(level,node); */
}

void perf_measure_leaf_capacity(db_handle *hd, int level_id)
{
	node_header *root = hd->db_desc->levels[level_id].root_r[0];
	assert(root);
	level_descriptor *level = &hd->db_desc->levels[level_id];
	log_info("level_id %d", level_id);
	perf_preorder_count_leaf_capacity(level, root);
}
#endif

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
	index_node *inode;
	uint32_t level_id = sc->level_id;
	uint32_t idx;
	uint32_t up = 1;

	stack_top = stack_pop(&(sc->stack)); /*get the element*/
	if (stack_top.guard) {
		sc->keyValue = NULL;
		return END_OF_DATABASE;
	}
	if (stack_top.node->type != leafNode && stack_top.node->type != leafRootNode) {
		log_fatal("Corrupted scanner stack, top element should be a leaf node");
		exit(EXIT_FAILURE);
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
					// log_debug("rightmost in stack throw and continue type %s",
					//	  node_type(stack_top.node->type));
					continue;
				} else {
					return END_OF_DATABASE;
				}
			} else if (stack_top.leftmost) {
				// log_debug("leftmost? %s", node_type(stack_top.node->type));
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
							//log_debug("rightmost in stack throw and continue type %s",
							// node_type(stack_top.node->type));
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
					inode = (index_node *)stack_top.node;
					node = (node_header *)REAL_ADDRESS(inode->p[0].right[0]);
					assert(node->type == rootNode || node->type == leafRootNode ||
					       node->type == internalNode || node->type == leafNode);
					up = 0;
					continue;
				} else {
					log_fatal("Corrupted node");
					assert(0);
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
				inode = (index_node *)stack_top.node;
				node = (node_header *)REAL_ADDRESS(inode->p[stack_top.idx].right[0]);
				up = 0;

				assert(node->type == rootNode || node->type == leafRootNode ||
				       node->type == internalNode || node->type == leafNode);
				continue;
			} else {
				log_fatal("Corrupted node");
				assert(0);
				exit(EXIT_FAILURE);
			}
		} else {
			/*push yourself, update node and continue*/
			stack_top.node = node;

			read_lock_node(sc, stack_top.node);

			// log_debug("Saved type %s", node_type(stack_top.node->type));
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
				inode = (index_node *)node;
				node = (node_header *)REAL_ADDRESS(inode->p[0].left[0]);
			} else {
				log_fatal("Reached corrupted node");
				assert(0);
			}
		}
	}
	/*fill buffer and return*/
	if (sc->type == COMPACTION_BUFFER_SCANNER) {
		/*prefix first*/
		struct bt_dynamic_leaf_node *dlnode = (struct bt_dynamic_leaf_node *)node;
		struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(dlnode);
		switch (slot_array[idx].kv_loc) {
		case KV_INPLACE:;
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

		case KV_INLOG: {
			struct bt_leaf_entry *kv_entry = (struct bt_leaf_entry *)get_kv_offset(
				dlnode, db_desc->levels[level_id].leaf_size, slot_array[idx].index);

			sc->kv_entry = *kv_entry;
			sc->kv_entry.dev_offt = (uint64_t)REAL_ADDRESS(kv_entry->dev_offt);
			sc->keyValue = &sc->kv_entry;
			sc->kv_format = KV_PREFIX;
			sc->cat = slot_array[idx].key_category;
			sc->tombstone = slot_array[idx].tombstone;
			sc->kv_size = sizeof(struct bt_leaf_entry);
			break;
		}
		default:
			assert(0);
			break;
		}

		assert(idx < node->num_entries);
	} else {
		// normal scanner
		struct bt_dynamic_leaf_node *dlnode = (struct bt_dynamic_leaf_node *)node;
		struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(dlnode);
		switch (slot_array[idx].kv_loc) {
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
			assert(0);
			exit(EXIT_FAILURE);
			break;
		}
	}
	return PARALLAX_SUCCESS;
}

int32_t _get_prev_KV(level_scanner *sc)
{
	db_descriptor *db_desc = sc->db->db_desc;
	uint32_t level_id = sc->level_id;
	stackElementT stack_top;
	node_header *node;
	index_node *inode;
	uint32_t idx;
	uint32_t up = 1;

	stack_top = stack_pop(&(sc->stack)); /*get the element*/
	if (stack_top.guard) {
		sc->keyValue = NULL;
		return END_OF_DATABASE;
	}

	if (stack_top.node->type != leafNode && stack_top.node->type != leafRootNode) {
		log_fatal("Corrupted scanner stack, top element should be a leaf node");
		exit(EXIT_FAILURE);
	}

	node = stack_top.node;
	//log_info("stack top rightmost %d leftmost %d", stack_top.rightmost, stack_top.leftmost);
	while (1) {
		if (up) {
			/*check if we can advance in the current node*/
			if (stack_top.leftmost) {
				read_unlock_node(sc, stack_top.node);

				stack_top = stack_pop(&(sc->stack));
				//printf("rightmost? %s", stack_top.node->type);
				//node_type(stack_top.node->type);
				if (!stack_top.guard) {
					continue;
				} else {
					return END_OF_DATABASE;
				}
			} else if (stack_top.rightmost) {
				//log_debug("rightmost? %s", node_type(stack_top.node->type));
				stack_top.rightmost = 0;
				if (stack_top.node->type == leafNode || stack_top.node->type == leafRootNode) {
					//log_info("got a rightmost leaf advance");
					if (stack_top.node->num_entries > 1) {
						idx = stack_top.node->num_entries - 2;
						stack_top.idx = stack_top.node->num_entries - 2;
						if (node->num_entries == 2)
							stack_top.leftmost = 1;
						node = stack_top.node;
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
					if (stack_top.node->num_entries == 1)
						stack_top.leftmost = 1;
					stack_top.idx = stack_top.node->num_entries - 1;
					stack_push(&sc->stack, stack_top);
					inode = (index_node *)stack_top.node;
					node = (node_header *)REAL_ADDRESS(inode->p[stack_top.idx].left[0]);
					assert(node->type == rootNode || node->type == leafRootNode ||
					       node->type == internalNode || node->type == leafNode);
					up = 0;
					continue;
				} else {
					log_fatal("Corrupted node");
					assert(0);
				}
			} else {
				--stack_top.idx;
				if (stack_top.idx <= 0)
					stack_top.leftmost = 1;
			}
			stack_push(&sc->stack, stack_top);
			if (stack_top.node->type == leafNode || stack_top.node->type == leafRootNode) {
				idx = stack_top.idx;
				node = stack_top.node;
				break;
			} else if (stack_top.node->type == internalNode || stack_top.node->type == rootNode) {
				inode = (index_node *)stack_top.node;
				node = (node_header *)REAL_ADDRESS(inode->p[stack_top.idx].left[0]);
				up = 0;
				assert(node->type == rootNode || node->type == leafRootNode ||
				       node->type == internalNode || node->type == leafNode);
				continue;
			} else {
				log_fatal("Corrupted node");
				assert(0);
				exit(EXIT_FAILURE);
			}
		} else {
			stack_top.node = node;

			read_lock_node(sc, stack_top.node);

			stack_top.idx = stack_top.node->num_entries - 1;
			stack_top.leftmost = 0;
			stack_top.rightmost = 1;
			stack_top.guard = 0;
			stack_push(&sc->stack, stack_top);
			if (node->type == leafNode || node->type == leafRootNode) {
				idx = stack_top.node->num_entries - 1;
				break;
			} else if (node->type == internalNode || node->type == rootNode) {
				inode = (index_node *)node;
				node = (node_header *)REAL_ADDRESS(inode->p[stack_top.idx].right[0]);
			} else {
				log_fatal("Reached corrupted node");
				assert(0);
			}
		}
	}

	/*fill buffer and return*/
	if (sc->type == COMPACTION_BUFFER_SCANNER) {
		/*prefix first*/
		struct bt_dynamic_leaf_node *dlnode = (struct bt_dynamic_leaf_node *)node;
		struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(dlnode);
		switch (slot_array[idx].kv_loc) {
		case KV_INPLACE:;
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

		case KV_INLOG: {
			struct bt_leaf_entry *kv_entry = (struct bt_leaf_entry *)get_kv_offset(
				dlnode, db_desc->levels[level_id].leaf_size, slot_array[idx].index);

			sc->kv_entry = *kv_entry;
			sc->kv_entry.dev_offt = (uint64_t)REAL_ADDRESS(kv_entry->dev_offt);
			sc->keyValue = &sc->kv_entry;
			sc->kv_format = KV_PREFIX;
			sc->cat = slot_array[idx].key_category;
			sc->tombstone = slot_array[idx].tombstone;
			sc->kv_size = sizeof(struct bt_leaf_entry);
			break;
		}
		default:
			assert(0);
			break;
		}

		assert(idx < node->num_entries);
	} else {
		// normal scanner
		struct bt_dynamic_leaf_node *dlnode = (struct bt_dynamic_leaf_node *)node;
		struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(dlnode);
		switch (slot_array[idx].kv_loc) {
		case KV_INPLACE:;
			uint32_t key_size, value_size;

			sc->keyValue =
				get_kv_offset(dlnode, db_desc->levels[level_id].leaf_size, slot_array[idx].index);
			assert(*(uint32_t *)sc->keyValue < 100);
			sc->kv_format = KV_FORMAT;
			sc->cat = slot_array[idx].key_category;
			sc->keyValue =
				get_kv_offset(dlnode, db_desc->levels[level_id].leaf_size, slot_array[idx].index);
			key_size = KEY_SIZE(sc->keyValue);
			value_size = VALUE_SIZE(sc->keyValue + sizeof(key_size) + key_size);
			sc->kv_size = sizeof(key_size) + sizeof(value_size) + key_size + value_size;

			break;

		case KV_INLOG: {
			struct bt_leaf_entry *kv_entry = (struct bt_leaf_entry *)get_kv_offset(
				dlnode, db_desc->levels[level_id].leaf_size, slot_array[idx].index);

			sc->kv_entry = *kv_entry;
			sc->kv_entry.dev_offt = (uint64_t)REAL_ADDRESS(kv_entry->dev_offt);
			sc->keyValue = (void *)sc->kv_entry.dev_offt;
			sc->kv_format = KV_FORMAT;
			sc->cat = slot_array[idx].key_category;
			break;
		}
		default:
			assert(0);
			exit(EXIT_FAILURE);
			break;
		}
	}
	return PARALLAX_SUCCESS;
}

int32_t getPrev(scannerHandle *sc)
{
	enum sh_heap_status stat;
	struct sh_heap_node nd;
	struct sh_heap_node next_nd;

	while (1) {
		stat = sh_remove_top(&sc->heap, &nd);
		if (stat != EMPTY_HEAP) {
			sc->keyValue = nd.KV;

			assert(sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree].valid);
			if (_get_prev_KV(&(sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree])) != END_OF_DATABASE) {
				//log_info("refilling from level_id %d\n", nd.level_id);
				next_nd.level_id = nd.level_id;
				next_nd.active_tree = nd.active_tree;
				next_nd.type = nd.type;
				next_nd.cat = sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree].cat;
				next_nd.KV = sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree].keyValue;
				next_nd.kv_size = sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree].kv_size;
				next_nd.db_desc = sc->db->db_desc;
				sh_insert_heap_node(&sc->heap, &next_nd);
			}
			if (nd.duplicate == 1 || nd.tombstone == 1) {
				// assert(0);
				//log_warn("ommiting duplicate %s", (char *)nd.data + 4);
				continue;
			}
			return PARALLAX_SUCCESS;
		} else
			return END_OF_DATABASE;
	}
}

static int find_last_key(level_scanner *level_sc)
{
	char key_buf_prefix[PREFIX_SIZE + sizeof(uint32_t) + MAX_KEY_SIZE];
	stackElementT element;
	db_descriptor *db_desc = level_sc->db->db_desc;
	index_node *inode;
	node_header *node;
	uint32_t level_id = level_sc->level_id;
	int32_t end_idx = 0;
	int32_t middle;
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
		read_unlock_node(level_sc, node);
		return END_OF_DATABASE;
	}

	while (node->type != leafNode && node->type != leafRootNode) {
		inode = (index_node *)node;
		end_idx = inode->header.num_entries - 1;

		element.guard = 0;
		element.node = node;

		node = (node_header *)REAL_ADDRESS(inode->p[end_idx].right[0]);

		read_lock_node(level_sc, node);

		element.leftmost = 0;
		element.rightmost = 1;
		stack_push(&(level_sc->stack), element);
	}

	int kv_size = 0;
	int key_format;
	/*reached leaf node, lock already there setup prefixes*/
	memset(key_buf_prefix, 0, sizeof(key_buf_prefix));
	key_format = KV_FORMAT;

	/*now perform binary search inside the leaf*/
	middle = 0;
	struct dl_bsearch_result dlresult = { .middle = 0, .status = INSERT, .op = DYNAMIC_LEAF_FIND, .debug = 0 };
	bt_insert_req req;
	req.key_value_buf = key_buf_prefix;
	req.metadata.kv_size = kv_size;
	req.metadata.key_format = key_format;

	binary_search_dynamic_leaf((struct bt_dynamic_leaf_node *)node, db_desc->levels[level_id].leaf_size, &req,
				   &dlresult);
	assert(dlresult.status != ERROR);

	middle = dlresult.middle;

	/*further checks*/
	if (middle <= 0 && node->num_entries > 1) {
		element.node = node;
		element.idx = 0;
		element.leftmost = 0;
		element.rightmost = 1;
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

	//we just need the last key of the leaf.
	middle = node->num_entries - 1;

	if (level_sc->type == COMPACTION_BUFFER_SCANNER) {
		struct bt_dynamic_leaf_node *dlnode = (struct bt_dynamic_leaf_node *)node;
		struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(dlnode);
		switch (slot_array[middle].kv_loc) {
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
			level_sc->kv_format = KV_PREFIX;
			level_sc->kv_entry.dev_offt = (uint64_t)REAL_ADDRESS(kv_entry->dev_offt);
			level_sc->keyValue = &level_sc->kv_entry;
			level_sc->cat = slot_array[middle].key_category;
			level_sc->tombstone = slot_array[middle].tombstone;
			level_sc->kv_size = sizeof(struct bt_leaf_entry);
			break;
		}
		default:
			assert(0);
		}

	} else { /*normal scanner*/
		struct bt_dynamic_leaf_node *dlnode = (struct bt_dynamic_leaf_node *)node;
		struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(dlnode);
		switch (slot_array[middle].kv_loc) {
		case KV_INPLACE:;
			uint32_t key_size, value_size;
			level_sc->keyValue =
				get_kv_offset(dlnode, db_desc->levels[level_id].leaf_size, slot_array[middle].index);
			key_size = KEY_SIZE(level_sc->keyValue);
			value_size = VALUE_SIZE(level_sc->keyValue + 4 + key_size);
			level_sc->kv_size = sizeof(key_size) + sizeof(value_size) + key_size + value_size;
			level_sc->kv_format = KV_FORMAT;
			/* log_info("%*s", *(uint32_t *)level_sc->keyValue, level_sc->keyValue + 4); */
			level_sc->tombstone = slot_array[middle].tombstone;
			level_sc->cat = slot_array[middle].key_category;
			break;
		case KV_INLOG: {
			struct bt_leaf_entry *kv_entry = (struct bt_leaf_entry *)get_kv_offset(
				dlnode, db_desc->levels[level_id].leaf_size, slot_array[middle].index);
			level_sc->kv_entry = *kv_entry;
			level_sc->kv_entry.dev_offt = (uint64_t)REAL_ADDRESS(kv_entry->dev_offt);
			level_sc->keyValue = (void *)level_sc->kv_entry.dev_offt;
			level_sc->kv_format = KV_FORMAT;
			level_sc->cat = slot_array[middle].key_category;
			level_sc->tombstone = slot_array[middle].tombstone;
			/* REAL_ADDRESS(*(uint64_t*)get_kv_offset( */
			/* dlnode, db_desc->levels[level_id].leaf_size, slot_array[middle].index)); */
			break;
		}
		default:
			assert(0);
		}
	}

	return PARALLAX_SUCCESS;
}

static int fetch_last(level_scanner *level_sc)
{
	stack_init(&level_sc->stack);

	if (find_last_key(level_sc) == END_OF_DATABASE) {
		stack_destroy(&(level_sc->stack));
		return -1;
	}
	level_sc->type = LEVEL_SCANNER;
	return 0;
}

void seek_to_last(struct scannerHandle *sc, struct db_handle *handle)
{
	struct sh_heap_node nd;
	uint8_t active_tree;
	int retval;

	char dirty = 1;

	if (sc == NULL) {
		log_fatal("NULL scannerHandle?");
		exit(EXIT_FAILURE);
	}

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
	//its a backward scanner
	sh_init_heap(&sc->heap, active_tree, MAX_HEAP);

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
			retval = fetch_last(&(sc->LEVEL_SCANNERS[0][i]));

			if (retval == 0) {
				sc->LEVEL_SCANNERS[0][i].valid = 1;
				nd.KV = sc->LEVEL_SCANNERS[0][i].keyValue;
				nd.kv_size = sc->LEVEL_SCANNERS[0][i].kv_size;
				nd.level_id = 0;
				nd.active_tree = i;
				nd.type = KV_FORMAT;
				nd.db_desc = handle->db_desc;

				sh_insert_heap_node(&sc->heap, (struct sh_heap_node *)&nd);
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
			retval = fetch_last(&sc->LEVEL_SCANNERS[level_id][tree_id]);
			if (retval == 0) {
				sc->LEVEL_SCANNERS[level_id][tree_id].valid = 1;
				nd.KV = sc->LEVEL_SCANNERS[level_id][tree_id].keyValue;
				nd.kv_size = sc->LEVEL_SCANNERS[level_id][tree_id].kv_size;
				nd.type = KV_FORMAT;
				//log_info("Tree[%d][%d] gave us key %s", level_id, 0, nd.KV + 4);
				nd.level_id = level_id;
				nd.active_tree = tree_id;
				nd.db_desc = handle->db_desc;

				sh_insert_heap_node(&sc->heap, (struct sh_heap_node *)&nd);

				sc->LEVEL_SCANNERS[level_id][tree_id].valid = 1;
			}
		}
	}

	if (getPrev(sc) == END_OF_DATABASE) {
		log_warn("Reached end of database");
		sc->keyValue = NULL;
	}
	return;
}

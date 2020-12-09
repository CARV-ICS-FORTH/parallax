#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include "stack.h"
#include <log.h>
#include "scanner.h"
#include "../btree/btree.h"
#include "../btree/static_leaf.h"
#include "../btree/dynamic_leaf.h"
#include "../btree/conf.h"

extern int32_t index_order;

int32_t _get_next_KV(level_scanner *sc);
int _init_level_scanner(level_scanner *level_sc, void *start_key, char seek_mode);

/**
 * Spill buffer operation will use this scanner. Traversal begins from root_w
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
level_scanner *_init_spill_buffer_scanner(db_handle *handle, int level_id, node_header *node, void *start_key)
{
	level_scanner *level_sc = malloc(sizeof(level_scanner));
	assert(level_sc);
	stack_init(&level_sc->stack);
	level_sc->db = handle;
	level_sc->root = node;
	level_sc->level_id = level_id;
	level_sc->type = SPILL_BUFFER_SCANNER;
	//level_sc->keyValue = (void *)malloc(PREFIX_SIZE + sizeof(uint64_t));
	/*typicall 20 bytes 8 prefix the address to the KV log
	 position scanner now to the appropriate row */
	if (_seek_scanner(level_sc, start_key, GREATER_OR_EQUAL) == END_OF_DATABASE) {
		log_info("empty internal buffer during spill operation, is that possible?");
		// will happen in close_spill_buffer_scanner stack_destroy(&(sc->stack));
		// free(sc);
		return NULL;
	}
	return level_sc;
}

void _close_spill_buffer_scanner(level_scanner *level_sc, node_header *root)
{
	stack_destroy(&(level_sc->stack));
	free(level_sc);
}

static void init_generic_scanner(struct scannerHandle *sc, struct db_handle *handle, void *start_key, char seek_flag,
				 char dirty)
{
	struct sh_heap_node nd;
	uint8_t active_tree;
	int retval;

	if (sc == NULL) {
		log_fatal("NULL scannerHandle?");
		exit(EXIT_FAILURE);
	}

	if (!dirty && handle->db_desc->dirty)
		snapshot(handle->volume_desc);

	/*special care for level 0 due to double buffering*/
	if (dirty) {
		/*take read lock of all levels (Level-0 client writes, other for switching trees
		*after compaction
		*/
		//for (int i = 0; i < MAX_LEVELS; i++)
		RWLOCK_RDLOCK(&handle->db_desc->levels[0].guard_of_level.rx_lock);
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
	sh_init_heap(&sc->heap, active_tree);

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
				//log_info("Tree[%d][%d] gave us key %s", 0, i, nd.KV + 4);
				nd.level_id = 0;
				nd.active_tree = active_tree;
				nd.type = KV_FORMAT;
				sh_insert_heap_node(&sc->heap, &nd);
			}
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
				nd.type = KV_FORMAT;
				//log_info("Tree[%d][%d] gave us key %s", level_id, 0, nd.KV + 4);
				nd.level_id = level_id;
				nd.active_tree = tree_id;
				sh_insert_heap_node(&sc->heap, &nd);
				sc->LEVEL_SCANNERS[level_id][tree_id].valid = 1;
			}
		}
	}

	if (getNext(sc) == END_OF_DATABASE) {
		log_warn("Reached end of database");
		sc->keyValue = NULL;
	}
	return;
}

/*no snaphsot scanner (with lock)*/
void init_dirty_scanner(struct scannerHandle *sc, struct db_handle *handle, void *start_key, char seek_flag)
{
	init_generic_scanner(sc, handle, start_key, seek_flag, 1);
	return;
}

scannerHandle *initScanner(scannerHandle *sc, db_handle *handle, void *start_key, char seek_flag)
{
	if (sc == NULL) { // this is for mongodb
		sc = malloc(sizeof(scannerHandle));
		sc->malloced = 1;
		snapshot(handle->volume_desc);
	} else {
		sc->malloced = 0;
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
		//for (int i = 0; i < MAX_LEVELS; i++)
		RWLOCK_UNLOCK(&sc->db->db_desc->levels[0].guard_of_level.rx_lock);
	}
	if (sc->malloced)
		free(sc);
}

void close_dirty_scanner(scannerHandle *sc)
{
	closeScanner(sc);

	struct db_descriptor *db_desc = sc->db->db_desc;
	for (int i = 0; i < MAX_LEVELS; i++)
		RWLOCK_UNLOCK(&db_desc->levels[i].guard_of_level.rx_lock);
}

/*XXX TODO XXX, please check if this is legal*/
inline int isValid(scannerHandle *sc)
{
	return sc->keyValue != NULL;
}

int32_t getKeySize(scannerHandle *sc)
{
	return *(int32_t *)(sc->keyValue);
}

void *getKeyPtr(scannerHandle *sc)
{
	return (void *)((char *)(sc->keyValue) + sizeof(int32_t));
}

int32_t getValueSize(scannerHandle *sc)
{
	int32_t key_size = getKeySize(sc);
	int32_t *val_ptr = (int32_t *)((char *)(sc->keyValue) + sizeof(int32_t) + key_size);
	return *val_ptr;
}

void *getValuePtr(scannerHandle *sc)
{
	int32_t key_size = getKeySize(sc);
	char *val_ptr = (char *)(sc->keyValue) + sizeof(int32_t) + key_size;
	return val_ptr + sizeof(int32_t);
}

int32_t _seek_scanner(level_scanner *level_sc, void *start_key_buf, SEEK_SCANNER_MODE mode)
{
	char key_buf_prefix[PREFIX_SIZE];
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
	char level_key_format;

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

	if (node->type == leafRootNode && node->num_entries == 0) {
		/*we seek in an empty tree*/
		read_unlock_node(level_sc, node);
		return END_OF_DATABASE;
	}

	while (node->type != leafNode && node->type != leafRootNode) {
		inode = (index_node *)node;
		start_idx = 0;
		end_idx = inode->header.num_entries - 1;
		middle = (start_idx + end_idx) / 2;

		while (1) {
			middle = (start_idx + end_idx) / 2;
			/*reconstruct full key*/
			addr = &(inode->p[middle].pivot);
			full_pivot_key = (void *)(MAPPED + *(uint64_t *)addr);
			ret = _tucana_key_cmp(full_pivot_key, start_key_buf, KV_FORMAT, KV_FORMAT);
			// log_info("pivot %u:%s app %u:%s ret %lld", *(uint32_t
			// *)(full_pivot_key), full_pivot_key + 4,
			//	 *(uint32_t *)start_key_buf, start_key_buf + 4, ret);

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
			node = (node_header *)(MAPPED + inode->p[middle].right[0]);
		else
			node = (node_header *)(MAPPED + inode->p[middle].left[0]);

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

	/*reached leaf node, lock already there setup prefixes*/
	if (start_key_buf == NULL)
		memset(key_buf_prefix, 0, PREFIX_SIZE * sizeof(char));
	else {
		uint32_t s_key_size = *(uint32_t *)start_key_buf;
		if (s_key_size >= PREFIX_SIZE)
			memcpy(key_buf_prefix, (void *)((uint64_t)start_key_buf + sizeof(int32_t)), PREFIX_SIZE);
		else {
			uint32_t s_key_size = *(uint32_t *)start_key_buf;
			memcpy(key_buf_prefix, (void *)((uint64_t)start_key_buf + sizeof(int32_t)), s_key_size);
			memset(key_buf_prefix + s_key_size, 0x00, PREFIX_SIZE - s_key_size);
		}
	}

	/*now perform binary search inside the leaf*/
	middle = 0;
	switch (db_desc->levels[level_id].node_layout) {
	case STATIC_LEAF:;
		struct sl_bsearch_result slresult = { .middle = 0, .status = INSERT, .op = STATIC_LEAF_FIND };
		{
			binary_search_static_leaf((struct bt_static_leaf_node *)node, &db_desc->levels[level_id],
						  (struct splice *)key_buf_prefix, &slresult);
			middle = slresult.middle;
			assert(slresult.status != ERROR);
			break;
		}
	case DYNAMIC_LEAF:;
		struct dl_bsearch_result dlresult = { .middle = 0, .status = INSERT, .op = DYNAMIC_LEAF_FIND };
		{
			bt_insert_req req;
			req.key_value_buf = key_buf_prefix;
			req.metadata.kv_size = PREFIX_SIZE;

			/* req.key_value_buf =  */
			binary_search_dynamic_leaf((struct bt_dynamic_leaf_node *)node,
						   db_desc->levels[level_id].leaf_size, &req, &dlresult);
			middle = dlresult.middle;
			assert(dlresult.status != ERROR);
			break;
		}
	default:
		assert(0);
	}

	/*further checks*/
	if (middle <= 0 && node->num_entries > 1) {
		element.node = node;
		element.idx = 0;
		element.leftmost = 1;
		element.rightmost = 0;
		element.guard = 0;
		// log_debug("Leftmost boom");
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
		// log_info("middle is %d", middle);
		element.node = node;
		element.idx = middle;
		element.leftmost = 0;
		element.rightmost = 0;
		element.guard = 0;
		stack_push(&(level_sc->stack), element);
	}

	if (level_sc->type == SPILL_BUFFER_SCANNER) {
		level_key_format = KV_FORMAT;
		// log_info("stack_top %llu node %llu leaf_order %llu and
		// sizeof(node_header) %d", (LLU)addr, (LLU)node,
		//	 leaf_order, sizeof(node_header));
		/*we assume that sc->keyValue has size of PREFIX_SIZE + sizeof(uint64_t)*/
		/*prefix first*/
		//memcpy(level_sc->keyValue, &lnode->prefix[middle][0], PREFIX_SIZE);
		/*pointer second*/
		//*(uint64_t *)(level_sc->keyValue + PREFIX_SIZE) = MAPPED + lnode->pointer[middle];
		switch (db_desc->levels[level_id].node_layout) {
		case STATIC_LEAF: {
			struct bt_static_leaf_node *slnode = (struct bt_static_leaf_node *)node;
			struct bt_static_leaf_structs src;
			/* struct bt_leaf_entry *leaf_entry = level_sc->keyValue; */
			retrieve_static_leaf_structures(slnode, &src, &db_desc->levels[level_id]);
			level_sc->keyValue = REAL_ADDRESS(src.kv_entries[src.slot_array[middle].index].pointer);
			//log_info("Offset %llu", src.kv_entries[src.slot_array[middle].index].pointer);
			/* *leaf_entry = src.kv_entries[src.slot_array[middle].index]; */
			/* leaf_entry->pointer = (uint64_t)REAL_ADDRESS(leaf_entry->pointer); */
			/* log_info("GONE BACK %d", *(uint32_t *)level_sc->keyValue); */
			break;
		}
		case DYNAMIC_LEAF: {
			struct bt_dynamic_leaf_node *dlnode = (struct bt_dynamic_leaf_node *)node;
			struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(dlnode);
			switch (slot_array[middle].bitmap) {
			case KV_INPLACE:
				level_sc->keyValue = get_kv_offset(dlnode, db_desc->levels[level_id].leaf_size,
								   slot_array[middle].index);
				log_info("%*s", *(uint32_t *)level_sc->keyValue, level_sc->keyValue + 4);
				level_key_format = level_sc->kv_format = KV_FORMAT;
				level_sc->cat = slot_array[middle].key_category;
				break;
			case KV_INLOG: {
				struct bt_leaf_entry *kv_entry = (struct bt_leaf_entry *)get_kv_offset(
					dlnode, db_desc->levels[level_id].leaf_size, slot_array[middle].index);
				level_sc->kv_entry = *kv_entry;
				level_sc->kv_entry.pointer = (uint64_t)REAL_ADDRESS(kv_entry->pointer);
				level_sc->keyValue = &level_sc->kv_entry;
				level_sc->cat = slot_array[middle].key_category;
				level_key_format = level_sc->kv_format = KV_PREFIX;

				/* REAL_ADDRESS(*(uint64_t*)get_kv_offset( */
				/* dlnode, db_desc->levels[level_id].leaf_size, slot_array[middle].index)); */
				break;
			}
			default:
				assert(0);
			}
			break;
		}
		default:
			assert(0);
		}

		// log_info("key is %s\n", (MAPPED + *(uint64_t *)addr) + sizeof(int32_t));
	} else { /*normal scanner*/
		switch (db_desc->levels[level_id].node_layout) {
		case STATIC_LEAF: {
			struct bt_static_leaf_node *slnode = (struct bt_static_leaf_node *)node;
			struct bt_static_leaf_structs src;
			/* struct bt_leaf_entry *leaf_entry = level_sc->keyValue; */
			retrieve_static_leaf_structures(slnode, &src, &db_desc->levels[level_id]);
			level_sc->keyValue = REAL_ADDRESS(src.kv_entries[src.slot_array[middle].index].pointer);
			//log_info("Offset %llu", src.kv_entries[src.slot_array[middle].index].pointer);
			/* *leaf_entry = src.kv_entries[src.slot_array[middle].index]; */
			/* leaf_entry->pointer = (uint64_t)REAL_ADDRESS(leaf_entry->pointer); */
			/* log_info("GONE BACK %d", *(uint32_t *)level_sc->keyValue); */
			break;
		}
		case DYNAMIC_LEAF: {
			struct bt_dynamic_leaf_node *dlnode = (struct bt_dynamic_leaf_node *)node;
			struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(dlnode);
			switch (slot_array[middle].bitmap) {
			case KV_INPLACE:
				level_sc->keyValue = get_kv_offset(dlnode, db_desc->levels[level_id].leaf_size,
								   slot_array[middle].index);
				log_info("%*s", *(uint32_t *)level_sc->keyValue, level_sc->keyValue + 4);
				level_key_format = level_sc->kv_format = KV_FORMAT;
				level_sc->cat = slot_array[middle].key_category;
				break;
			case KV_INLOG: {
				struct bt_leaf_entry *kv_entry = (struct bt_leaf_entry *)get_kv_offset(
					dlnode, db_desc->levels[level_id].leaf_size, slot_array[middle].index);
				level_sc->kv_entry = *kv_entry;
				level_sc->kv_entry.pointer = (uint64_t)REAL_ADDRESS(kv_entry->pointer);
				level_sc->keyValue = &level_sc->kv_entry;
				level_sc->cat = slot_array[middle].key_category;
				level_key_format = level_sc->kv_format = KV_PREFIX;

				/* REAL_ADDRESS(*(uint64_t*)get_kv_offset( */
				/* dlnode, db_desc->levels[level_id].leaf_size, slot_array[middle].index)); */
				break;
			}
			default:
				assert(0);
			}
			break;
		}
		default:
			assert(0);
		}

		//level_sc->keyValue = (void *)MAPPED + lnode->pointer[middle];
		//log_info("full key is %s", level_sc->keyValue + 4);
	}

	if (start_key_buf != NULL) {
		if (mode == GREATER) {
			while (_tucana_key_cmp(level_sc->keyValue, start_key_buf,
					       level_sc->kv_format /* level_key_format */, KV_FORMAT) <= 0) {
				if (_get_next_KV(level_sc) == END_OF_DATABASE)
					return END_OF_DATABASE;
			}
		} else if (mode == GREATER_OR_EQUAL) {
			while (_tucana_key_cmp(level_sc->keyValue, start_key_buf,
					       level_sc->kv_format /* level_key_format */, KV_FORMAT) < 0) {
				//log_info("compated index key %s with seek key %s", level_sc->keyValue + 4,
				//	 start_key_buf + 4);
				if (_get_next_KV(level_sc) == END_OF_DATABASE)
					return END_OF_DATABASE;
			}
		}
	}
#ifdef DEBUG_SCAN
	if (start_key_buf != NULL)
		log_info("start_key_buf = %s sc->keyValue = %s\n", start_key_buf + 4, level_sc->keyValue);
	else
		log_info("start_key_buf NULL sc->keyValue = %s\n", level_sc->keyValue);
#endif
	return SUCCESS;
}

int32_t getNext(scannerHandle *sc)
{
	enum sh_heap_status stat;
	struct sh_heap_node nd;
	struct sh_heap_node next_nd;

	while (1) {
		stat = sh_remove_min(&sc->heap, &nd);
		if (stat != EMPTY_MIN_HEAP) {
			sc->keyValue = nd.KV;
			if (_get_next_KV(&(sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree])) != END_OF_DATABASE) {
				//log_info("refilling from level_id %d\n", nd.level_id);
				next_nd.level_id = nd.level_id;
				next_nd.active_tree = nd.active_tree;
				next_nd.type = nd.type;
				next_nd.cat = sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree].cat;
				next_nd.KV = sc->LEVEL_SCANNERS[nd.level_id][nd.active_tree].keyValue;
				sh_insert_heap_node(&sc->heap, &next_nd);
			}
			if (nd.duplicate == 1) {
				// assert(0);
				//log_warn("ommiting duplicate %s", (char *)nd.data + 4);
				continue;
			}
			return KREON_OK;
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
 * update: 09/03/2017 14:15: for SPILL_BUFFER_SCANNER only we ll return codes
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
					// log_debug("Calculate and push type %s",
					// node_type(stack_top.node->type));
					/*special case applies only for the root*/
					if (stack_top.node->num_entries == 1)
						stack_top.rightmost = 1;
					stack_top.idx = 0;
					stack_push(&sc->stack, stack_top);
					inode = (index_node *)stack_top.node;
					node = (node_header *)(MAPPED + inode->p[0].right[0]);
					assert(node->type == rootNode || node->type == leafRootNode ||
					       node->type == internalNode || node->type == leafNode);
					// stack_top.node = node;
					// log_debug("Calculate and push type %s",
					// node_type(stack_top.node->type));
					// stack_push(&sc->stack, stack_top);
					up = 0;
					continue;
				} else {
					log_fatal("Corrupted node");
					assert(0);
				}
			} else {
				// log_debug("Advancing, %s idx = %d entries %d",
				// node_type(stack_top.node->type),
				//	  stack_top.idx, stack_top.node->numberOfEntriesInNode);
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
				node = (node_header *)(MAPPED + (uint64_t)inode->p[stack_top.idx].right[0]);
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
				node = (node_header *)(MAPPED + (uint64_t)inode->p[0].left[0]);
			} else {
				log_fatal("Reached corrupted node");
				assert(0);
			}
		}
	}
	//log_warn("Key %lu:%s idx is %d", *(uint32_t *)(MAPPED + (uint64_t)lnode->pointer[idx]),
	//MAPPED + lnode->pointer[idx] + 4, idx);
	/*fill buffer and return*/
	if (sc->type == SPILL_BUFFER_SCANNER) {
		/*prefix first*/
		//memcpy(sc->keyValue, &lnode->prefix[idx][0], PREFIX_SIZE);
		/*pointer second*/
		//*(uint64_t *)(sc->keyValue + PREFIX_SIZE) = MAPPED + lnode->pointer[idx];
		switch (db_desc->levels[level_id].node_layout) {
		case STATIC_LEAF:;
			struct bt_static_leaf_node *slnode = (struct bt_static_leaf_node *)node;
			struct bt_static_leaf_structs src;
			//struct bt_leaf_entry *leaf_entry = sc->keyValue;
			retrieve_static_leaf_structures(slnode, &src, &db_desc->levels[level_id]);
			/* log_info("GONE HERE %d", idx); */
			//*leaf_entry = src.kv_entries[src.slot_array[idx].index];
			sc->keyValue = REAL_ADDRESS(src.kv_entries[src.slot_array[idx].index].pointer);
			/* log_info("address %llu %s", src.kv_entries[src.slot_array[idx].index].pointer, */
			/* 	 (MAPPED + src.kv_entries[src.slot_array[idx].index].pointer) + 4); */
			/* leaf_entry->pointer = (uint64_t)REAL_ADDRESS(leaf_entry->pointer); */
			/* log_info("GONE HERE1 %d ", *(uint32_t *)sc->keyValue); */
			break;

		case DYNAMIC_LEAF:;
			struct bt_dynamic_leaf_node *dlnode = (struct bt_dynamic_leaf_node *)node;
			struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(dlnode);
			switch (slot_array[idx].bitmap) {
			case KV_INPLACE:
				sc->keyValue = get_kv_offset(dlnode, db_desc->levels[level_id].leaf_size,
							     slot_array[idx].index);
				sc->kv_format = KV_FORMAT;
				sc->cat = slot_array[idx].key_category;
				//log_info("offset %d",slot_array[idx].index);
				break;

			case KV_INLOG: {
				struct bt_leaf_entry *kv_entry = (struct bt_leaf_entry *)get_kv_offset(
					dlnode, db_desc->levels[level_id].leaf_size, slot_array[idx].index);

				/* kv_entry->pointer = (uint64_t) REAL_ADDRESS(kv_entry->pointer); */
				sc->kv_entry = *kv_entry;
				sc->kv_entry.pointer = (uint64_t)REAL_ADDRESS(kv_entry->pointer);
				sc->keyValue = &sc->kv_entry;
				sc->kv_format = KV_PREFIX;
				sc->cat = slot_array[idx].key_category;
				/* REAL_ADDRESS(*(uint64_t*)get_kv_offset( */
				/* dlnode, db_desc->levels[level_id].leaf_size, slot_array[idx].index)) */;
				/* log_info("%d %s",*(uint32_t*)sc->keyValue,(char *)(sc->keyValue + 4)); */
				break;
			}
			default:
				assert(0);
				break;
			}
			break;
		}

		assert(idx < node->num_entries);
		if (sc->kv_format == KV_FORMAT)
			assert(*(uint32_t *)sc->keyValue < 100);

		//log_info("key %d x %d numberofentries %llu %d", *(uint32_t*)sc->keyValue, x, node->numberOfEntriesInNode, idx);
	} else {
		switch (db_desc->levels[level_id].node_layout) {
		case STATIC_LEAF:;
			struct bt_static_leaf_node *slnode = (struct bt_static_leaf_node *)node;
			struct bt_static_leaf_structs src;
			//struct bt_leaf_entry *leaf_entry = sc->keyValue;
			retrieve_static_leaf_structures(slnode, &src, &db_desc->levels[level_id]);
			/* log_info("GONE HERE %d", idx); */
			//*leaf_entry = src.kv_entries[src.slot_array[idx].index];
			sc->keyValue = REAL_ADDRESS(src.kv_entries[src.slot_array[idx].index].pointer);
			/* log_info("address %llu %s", src.kv_entries[src.slot_array[idx].index].pointer, */
			/* 	 (MAPPED + src.kv_entries[src.slot_array[idx].index].pointer) + 4); */
			/* leaf_entry->pointer = (uint64_t)REAL_ADDRESS(leaf_entry->pointer); */
			/* log_info("GONE HERE1 %d ", *(uint32_t *)sc->keyValue); */
			break;
		case DYNAMIC_LEAF:;
			struct bt_dynamic_leaf_node *dlnode = (struct bt_dynamic_leaf_node *)node;
			struct bt_dynamic_leaf_slot_array *slot_array = get_slot_array_offset(dlnode);
			switch (slot_array[idx].bitmap) {
			case KV_INPLACE:
				sc->keyValue = get_kv_offset(dlnode, db_desc->levels[level_id].leaf_size,
							     slot_array[idx].index);
				sc->kv_format = KV_FORMAT;
				sc->cat = slot_array[idx].key_category;
				//log_info("offset %d",slot_array[idx].index);
				break;

			case KV_INLOG: {
				struct bt_leaf_entry *kv_entry = (struct bt_leaf_entry *)get_kv_offset(
					dlnode, db_desc->levels[level_id].leaf_size, slot_array[idx].index);

				/* kv_entry->pointer = (uint64_t) REAL_ADDRESS(kv_entry->pointer); */
				sc->kv_entry = *kv_entry;
				sc->kv_entry.pointer = (uint64_t)REAL_ADDRESS(kv_entry->pointer);
				sc->keyValue = &sc->kv_entry;
				sc->kv_format = KV_PREFIX;
				sc->cat = slot_array[idx].key_category;
				/* REAL_ADDRESS(*(uint64_t*)get_kv_offset( */
				/* dlnode, db_desc->levels[level_id].leaf_size, slot_array[idx].index)) */;
				/* log_info("%d %s",*(uint32_t*)sc->keyValue,(char *)(sc->keyValue + 4)); */
				break;
			}
			default:
				assert(0);
				break;
			}
			break;
		}

		/*normal scanner*/
		/* sc->keyValue = (void *)MAPPED + lnode->pointer[idx]; */
		//log_info("consuming idx %d key %s num entries %lu",idx,sc->keyValue+4,lnode->header.numberOfEntriesInNode);
	}
	// else if (sc->type != CLOSE_SPILL_BUFFER_SCANNER) /*Do nothing for
	// close_buffer_Scanner*/
	//	sc->keyValue = (void *)MAPPED + *(uint64_t *)stack_top;
	return SUCCESS;
}

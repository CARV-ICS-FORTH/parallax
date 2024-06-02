#include "L0_scanner.h"
#include "../btree/dynamic_leaf.h"
#include "../lib/btree/btree.h"
#include "../lib/btree/btree_node.h"
#include "../lib/btree/conf.h"
#include "../lib/btree/index_node.h"
#include "../lib/btree/key_splice.h"
#include "../lib/common/common.h"
#include <assert.h>
#include <log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct key_splice;

void L0_scanner_read_lock_node(struct L0_scanner *L0_scanner, struct node_header *node)
{
	assert(0 == L0_scanner->level_id);

	struct lock_table *lock =
		find_lock_position((const lock_table **)L0_scanner->db->db_desc->L0.level_lock_table, node);
	if ((RWLOCK_RDLOCK(&lock->rx_lock)) != 0) {
		log_fatal("ERROR locking");
		perror("Reason");
		BUG_ON();
	}
}

void L0_scanner_read_unlock_node(struct L0_scanner *L0_scanner, struct node_header *node)
{
	assert(0 == L0_scanner->level_id);

	struct lock_table *lock =
		find_lock_position((const lock_table **)L0_scanner->db->db_desc->L0.level_lock_table, node);
	if (RWLOCK_UNLOCK(&lock->rx_lock) != 0) {
		log_fatal("ERROR locking");
		BUG_ON();
	}
}

bool L0_scanner_init(struct L0_scanner *L0_scanner, db_handle *database, uint8_t level_id, uint8_t tree_id)
{
	assert(0 == level_id);
	memset(L0_scanner, 0x00, sizeof(*L0_scanner));
	stack_init(&L0_scanner->stack);
	L0_scanner->db = database;
	L0_scanner->level_id = level_id;
	L0_scanner->is_compaction_scanner = false;
	L0_scanner->root = database->db_desc->L0.root[tree_id];

	return true;
}

bool L0_scanner_seek(struct L0_scanner *L0_scanner, struct key_splice *start_key_splice,
		     enum seek_scanner_mode seek_mode)
{
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
	L0_scanner_read_lock_node(L0_scanner, L0_scanner->root);

	if (!L0_scanner->root) {
		L0_scanner_read_unlock_node(L0_scanner, L0_scanner->root);
		return false;
	}

	if (L0_scanner->root->type == leafRootNode && L0_scanner->root->num_entries == 0) {
		/*we seek in an empty tree*/
		L0_scanner_read_unlock_node(L0_scanner, L0_scanner->root);
		return false;
	}

	/*Drop all paths*/
	stack_reset(&(L0_scanner->stack));
	/*Insert stack guard*/
	stackElementT guard_element = { .guard = 1, .idx = 0, .node = NULL, .iterator = { 0 } };
	stack_push(&(L0_scanner->stack), guard_element);

	stackElementT element = { .guard = 0, .idx = INT32_MAX, .node = NULL, .iterator = { 0 } };

	struct node_header *node = L0_scanner->root;
	while (node->type != leafNode && node->type != leafRootNode) {
		element.node = node;

		index_iterator_init_with_key((struct index_node *)element.node, &element.iterator, start_key_splice);

		if (!index_iterator_is_valid(&element.iterator)) {
			log_fatal("Invalid index node iterator during seek");
			BUG_ON();
		}

		struct pivot_pointer *piv_pointer = index_iterator_get_pivot_pointer(&element.iterator);
		stack_push(&(L0_scanner->stack), element);

		node = REAL_ADDRESS(piv_pointer->child_offt);
		L0_scanner_read_lock_node(L0_scanner, node);
	}
	assert(node->type == leafNode || node->type == leafRootNode);

	/*Whole path root to leaf is locked and inserted into the stack. Now set the element for the leaf node*/
	memset(&element, 0x00, sizeof(element));
	element.node = node;

	/*now perform binary search inside the leaf*/

	bool exact_match = false;
	element.idx = dl_search_get_pos((struct leaf_node *)node, key_splice_get_key_offset(start_key_splice),
					key_splice_get_key_size(start_key_splice), &exact_match);
	element.idx = exact_match ? element.idx : element.idx + 1;

	stack_push(&L0_scanner->stack, element);

	if ((seek_mode == GREATER && exact_match) || element.idx >= node->num_entries) {
		if (!L0_scanner_get_next(L0_scanner))
			return false;
	}

	element = stack_pop(&L0_scanner->stack);

	L0_scanner->splice = dl_get_general_splice((struct leaf_node *)element.node, element.idx);
	// log_debug("Level scanner seek reached splice %.*s at idx %d node entries %d",
	// 	  kv_splice_base_get_key_size(&level_sc->splice), kv_splice_base_get_key_buf(&level_sc->splice),
	// 	  element.idx, element.node->num_entries);
	stack_push(&L0_scanner->stack, element);
	return true;
}

bool L0_scanner_get_next(struct L0_scanner *L0_scanner)
{
	enum level_scanner_status_t { GET_NEXT_KV = 1, SEEK_DEV_LEVEL_SCANNER, POP_STACK, PUSH_STACK };

	stackElementT stack_element = stack_pop(&(L0_scanner->stack)); /*get the element*/

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

			if (0 == L0_scanner->level_id && ++stack_element.idx >= stack_element.node->num_entries) {
				L0_scanner_read_unlock_node(L0_scanner, stack_element.node);
				status = POP_STACK;
				break;
			}

			L0_scanner->splice =
				dl_get_general_splice((struct leaf_node *)stack_element.node, stack_element.idx);
			stack_push(&L0_scanner->stack, stack_element);

			return true;

		case PUSH_STACK:;
			//log_debug("Pushing stack");
			struct pivot_pointer *pivot = index_iterator_get_pivot_pointer(&stack_element.iterator);
			stack_push(&L0_scanner->stack, stack_element);
			memset(&stack_element, 0x00, sizeof(stack_element));
			stack_element.node = REAL_ADDRESS(pivot->child_offt);

			L0_scanner_read_lock_node(L0_scanner, stack_element.node);
			if ((stack_element.node->type == leafNode || stack_element.node->type == leafRootNode)) {
				stack_element.idx = -1;
				status = GET_NEXT_KV;
				break;
			}

			index_iterator_init((struct index_node *)stack_element.node, &stack_element.iterator);
			break;

		case POP_STACK:
			stack_element = stack_pop(&(L0_scanner->stack));

			if (stack_element.guard)
				return false;

			assert(stack_element.node->type == internalNode || stack_element.node->type == rootNode);
			if (index_iterator_is_valid(&stack_element.iterator)) {
				status = PUSH_STACK;
				//log_debug("Proceeding with the next pivot of node: %lu", stack_element.node);
			} else {
				//log_debug("Done with index node unlock");
				L0_scanner_read_unlock_node(L0_scanner, stack_element.node);
			}
			break;
		default:
			log_fatal("Unhandled state");
			BUG_ON();
		}
	}

	return true;
}

struct L0_scanner *L0_scanner_init_compaction_scanner(db_handle *database, uint8_t level_id, uint8_t tree_id)
{
	struct L0_scanner *level_scanner = calloc(1UL, sizeof(struct L0_scanner));
	if (!L0_scanner_init(level_scanner, database, level_id, tree_id)) {
		log_fatal("Failed to initialize scanner");
		BUG_ON();
	}
	level_scanner->is_compaction_scanner = true;

	if (!L0_scanner_seek(level_scanner, NULL, FETCH_FIRST)) {
		log_warn("empty internal buffer during compaction operation, is that possible?");
		return NULL;
	}
	log_debug("Compaction scanner initialized successfully");
	return level_scanner;
}

void L0_scanner_close(struct L0_scanner *L0_scanner)
{
	stack_destroy(&(L0_scanner->stack));
	free(L0_scanner);
}

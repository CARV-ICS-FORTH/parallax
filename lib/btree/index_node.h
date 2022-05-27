#ifndef INDEX_NODE_H
#define INDEX_NODE_H
#include "../common/common.h"
#include "btree.h"
#include "conf.h"
#include <stdbool.h>
#include <stdint.h>

struct pivot_key {
	uint32_t size;
	char data[];
};

struct pivot_pointer {
	uint64_t child_offt;
};

struct new_index_node_iterator {
	struct index_node *node;
	struct pivot_key *key;
	int32_t position;
	int32_t num_entries;
};

struct insert_pivot_req_t {
	struct index_node *node;
	struct pivot_pointer *left_child;
	struct pivot_key *key;
	struct pivot_pointer *right_child;
};

struct new_index_slot_array_entry {
	uint16_t pivot;
} __attribute__((packed));

struct index_node {
	struct node_header header;
	char rest_space[INDEX_NODE_SIZE - sizeof(struct node_header)];
} __attribute__((packed));

enum add_guard_option_t { INVALID_GUARD_STATE = 0, ADD_GUARD, DO_NOT_ADD_GUARD };

/**
 * Initializes a freshly allocated index node. It initializes all of its fields
 * and inserts the guard zero key with node device offset set to UINT64_MAX.
 *
 * @param add_zero_guard: if set to a value greater than 0 inserts the zero
 * guard as pivot. The zero guard is the smallest possible key (aka pivot key
 * <size: 1, data: 0x00), with an initial device children offset set to
 * UINT64_MAX.
 *
 * @param node:  The node to be intialized.
 *
 * @param type: The node type, valid values are rootNode or internalNode.
*/
void index_init_node(enum add_guard_option_t option, struct index_node *node, nodeType_t type);

/**
  * Sets the height of the node
  * @param node
  * @param height
  */
void index_set_height(struct index_node *node, int32_t height);

/**
  * Sets the type of the node
  * @param node
  * @param node_type: Valid values are internalNode and rootNode
  * @return 0 on sucess 1 on failure
  */
bool index_set_type(struct index_node *node, nodeType_t node_type);

/**
  * @return 1 if the index node DOES NOT contain any entries even a guard.
  * Otherwise returns 0.
  */
uint8_t index_is_empty(const struct index_node *node);

/**
  * Inserts a guard pivot (aka the smallest possible pivot key <size: 1, data:
  * 0x00) in the index node.
  *
  * @param node: The node to add the new guard.
  *
  * @param child_node_dev_offt: the child nodedevice offset that queries for
  * keys that are larger or equal to the guard will be forwarded.
*/
void new_index_add_guard(struct index_node *node, uint64_t child_node_dev_offt);

/*
 * Inserts a new pivot in the index node. When we split a leaf or an index node
 * we create two children left and right. Right contains all the keys greater
 * or equal to the pivot_key. Left contains all the keys that are greater or
 * equal of the previous pivot key
 * @return 0 on success, 1 on failure
 */

bool index_insert_pivot(struct insert_pivot_req_t *ins_pivot_req);

/*
 * Appends a new pivot in the index node. When we split a leaf or an index node
 * we create two children left and right. Right contains all the keys greater
 * or equal to the pivot_key. Left contains all the keys that are greater or
 * equal of the previous pivot key. 
 * 
 * @param ins_pivot_req contains the node,
 * right_child, and pivot_key. Caution left_child arg is ignored from this
 * function. 
 * 
 * @return 0 on success, 1 on failure.
 */
bool index_append_pivot(struct insert_pivot_req_t *ins_pivot_req);

/**
  * Worst case analysis here. If the remaining space is smaller than the
  * maximum possible pivot key we report that this node needs to be split
  * @param node: The index node that the function checks
  * @return: 0 if the nodes does not need splitting >0 otherwise
  */
int index_is_split_needed(struct index_node *node, uint32_t max_pivot_size);

/**
  * Search index node and returns the pivot associated with the lookup key. The pivot entry consists of
  * uint32_t pivot_size and data and the device offset to the node which should be visitted next. Doing the operation
  * pivot_key + PIVOT_KEY_SIZE we get the pivot pointer
  */
struct pivot_pointer *index_search_get_pivot(struct index_node *node, void *lookup_key, enum KV_type lookup_key_format);

/**
  * Removes last  pivot_key followd by the pivot pointer from node. The
  * returned buffer is malloced so the caller must call free after it consumes.
  * @param node: The node for which we return the last pivot_key
  * @return: The malloced buffer or NULL in case the node is empty
  */
struct pivot_key *index_remove_last_pivot_key(struct index_node *node);

/*
 * Performs binary search in an index node and returns the device offt of the
 * children node that we need to follow
 */
uint64_t index_binary_search(struct index_node *node, void *lookup_key, enum KV_type lookup_key_format);

/**
 * Splits an index node into two child index nodes.
 */
struct bt_rebalance_result index_split_node(struct index_node *node, bt_insert_req *ins_req);

/**
 * Iterators for parsing index nodes. Compaction, scanner, and other future
 * entiries must use this API in order to abstact the index node
 * implementation. This iterator starts from the first pivot of the node.
 */
void index_iterator_init(struct index_node *node, struct new_index_node_iterator *iterator);

/**
  * Initializes a new iterator and positions it to a pivot pointer greater or
  * equal to the pivo key
  * @param node: the index node to search
  * @param iterator: pointer to the iterator to be initialized
  * @parama key: Key to position itself
  */
void index_iterator_init_with_key(struct index_node *node, struct new_index_node_iterator *iterator,
				  struct pivot_key *key);

uint8_t index_iterator_is_valid(struct new_index_node_iterator *iterator);

struct pivot_key *index_iterator_get_pivot_key(struct new_index_node_iterator *iterator);

struct pivot_pointer *index_iterator_get_pivot_pointer(struct new_index_node_iterator *iterator);

#define PIVOT_KEY_SIZE(X) ((X) ? (X)->size + sizeof(*X) : BUG_ON_UINT32T())
#define PIVOT_SIZE(X) (PIVOT_KEY_SIZE(X) + sizeof(struct pivot_pointer))
#define NEW_INDEX_PIVOT_ADDRESS(X, Y) ((uint64_t)(X) + (Y))
#endif

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
#ifndef INDEX_NODE_H
#define INDEX_NODE_H
#include "btree_node.h"
#include "key_splice.h"
#include <stdbool.h>
#include <stdint.h>
struct index_node;
struct key_splice;

#define SMALLEST_POSSIBLE_PIVOT_SIZE 16
#define MAX_PIVOT_SIZE (MAX_KEY_SPLICE_SIZE + sizeof(struct pivot_pointer))
struct pivot_pointer {
	uint64_t child_offt;
};

struct index_node_iterator {
	struct index_node *node;
	struct key_splice *key_splice;
	int32_t position;
	int32_t num_entries;
};

struct insert_pivot_req {
	struct index_node *node;
	struct pivot_pointer *left_child;
	struct key_splice *key_splice;
	struct pivot_pointer *right_child;
};

struct index_node_split_request {
	struct index_node *node;
	struct index_node *left_child;
	struct index_node *right_child;
};

struct index_node_split_reply {
	char *pivot_buf;
	uint32_t pivot_buf_size;
};

struct index_slot_array_entry {
	uint16_t pivot;
} __attribute__((packed));

enum add_guard_option { INVALID_GUARD_STATE = 0, ADD_GUARD, DO_NOT_ADD_GUARD };

struct pivot_pointer *index_get_pivot_pointer(struct key_splice *key_splice);
/**
 * Initializes a freshly allocated index node. It initializes all of its fields
 * and inserts the guard zero key with node device offset set to UINT64_MAX.
 *
 * @param option: if set to a value greater than 0 inserts the zero
 * guard as pivot. The zero guard is the smallest possible key (aka pivot key
 * <size: 1, data: 0x00), with an initial device children offset set to
 * UINT64_MAX.
 * @param node:  The node to be intialized.
 *
 * @param type: The node type, valid values are rootNode or internalNode.
*/
void index_init_node(enum add_guard_option option, struct index_node *node, nodeType_t type);

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
  * @return true on sucess false on failure
  */
bool index_set_type(struct index_node *node, nodeType_t node_type);

/**
  * @return true if the index node DOES NOT contain any entries even a guard.
  * Otherwise returns false.
  */
bool index_is_empty(struct index_node *node);

/**
  * Inserts a guard pivot (aka the smallest possible pivot key <size: 1, data:
  * 0x00) in the index node.
  *
  * @param node: The node to add the new guard.
  *
  * @param child_node_dev_offt: the child nodedevice offset that queries for
  * keys that are larger or equal to the guard will be forwarded.
*/
void index_add_guard(struct index_node *node, uint64_t child_node_dev_offt);

/**
 * Inserts a new pivot in the index node. When we split a leaf or an index node
 * we create two children left and right. Right contains all the keys greater
 * or equal to the pivot_key. Left contains all the keys that are greater or
 * equal of the previous pivot key.
 * @return true on success, false on failure
 */

bool index_insert_pivot(struct insert_pivot_req *ins_pivot_req);

/**
 * Appends a new pivot in the index node. When we split a leaf or an index node
 * we create two children left and right. Right contains all the keys greater
 * or equal to the pivot_key. Left contains all the keys that are greater or
 * equal of the previous pivot key.
 *
 * @param ins_pivot_req contains the node,
 * right_child, and pivot_key. Caution left_child arg is ignored from this
 * function.
 *
 * @return true on success, false on failure.
 */
bool index_append_pivot(struct insert_pivot_req *ins_pivot_req);

/**
  * Worst case analysis here. If the remaining space is smaller than the
  * maximum possible pivot key we report that this node needs to be split
  * @param node: The index node that the function checks
  * @param max_pivot_size: The maximum size of a pivot key
  * @return: true if the nodes does not need splitting false otherwise
  */
bool index_is_split_needed(struct index_node *node, uint32_t max_pivot_size);

/**
  * Search index node and returns the pivot associated with the lookup key. The pivot entry consists of
  * int32_t pivot_size and data and the device offset to the node which should be visitted next. Doing the operation
  * pivot_key + PIVOT_KEY_SIZE we get the pivot pointer.
  */
struct pivot_pointer *index_search_get_pivot(struct index_node *node, const char *lookup_key, int32_t lookup_key_size);

/**
  * Removes last  pivot_key followd by the pivot pointer from node. The
  * returned buffer is malloced so the caller must call free after it consumes.
  * @param node: The node for which we return the last pivot_key
  * @return: The malloced buffer or NULL in case the node is empty
  */
struct key_splice *index_remove_last_pivot_key(struct index_node *node);

/**
 * Performs binary search in an index node and returns the device offt of the
 * children node that we need to follow
 */
uint64_t index_binary_search(struct index_node *node, const char *lookup_key, int32_t lookup_key_size);

/**
 * Splits an index node into two child index nodes.
 */
void index_split_node(struct index_node_split_request *request, struct index_node_split_reply *reply);

/**
 * Iterators for parsing index nodes. Compaction, scanner, and other future
 * entiries must use this API in order to abstact the index node
 * implementation. This iterator starts from the first pivot of the node.
 */
void index_iterator_init(struct index_node *node, struct index_node_iterator *iterator);

/**
  * Initializes a new iterator and positions it to a pivot pointer greater or
  * equal to the pivot key.
  * @param node: the index node to search
  * @param iterator: pointer to the iterator to be initialized
  * @param key_splice: Key to position itself
  */
void index_iterator_init_with_key(struct index_node *node, struct index_node_iterator *iterator,
				  struct key_splice *key_splice);

/**
  * initializes the smallest pivot key which has some = INDEX_GUARD_SIZE and payload 0x00
  * @param buffer: smallest pivot to be constructed
  * @param size: size of the buffer
  */
struct key_splice *fill_smallest_possible_pivot(char *buffer, int size);

/**
  * checks if the position of an index iterator is less that the number of entries inside the index node
  * @param iterator: an iteration pointing to an index node
  */
uint8_t index_iterator_is_valid(const struct index_node_iterator *iterator);

/**
 * proceed index iterator to the next position in the index node
 * @param iterator: an iteration pointing to an index node
 */
bool index_iterator_next(struct index_node_iterator *iterator);

/**
  * returns the pivot key of where the index iterator is pointing;
  * @param iterator: an iteration pointing to an index node
  */
struct key_splice *index_iterator_get_pivot_key(struct index_node_iterator *iterator);

/**
  * returns the pivot pointer a.k.a. the child of this pivot
  * @param iterator: an iteration pointing to an index node
  */
struct pivot_pointer *index_iterator_get_pivot_pointer(struct index_node_iterator *iterator);

/**
  * sets the key of a given pivot_key
  * @param pivot_splice: the given pivot_key
  * @param key: the key to be set
  * @param key_size: the key_size of the key to be set
  */
void set_pivot_key(struct key_splice *pivot_splice, void *key, int32_t key_size);

/**
  * returns a pointer to the node's node->header memory location
  * @param node: an index_node
  */
struct node_header *index_node_get_header(struct index_node *node);
/**
  * returns the sizeof(struct index_node)
  */
uint64_t index_node_get_size(void);

void index_node_print(struct index_node *node);
#endif

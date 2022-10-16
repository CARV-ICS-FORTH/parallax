#include "index_node.h"
#include "../common/common.h"
#include "../common/kv_pairs.h"
#include "btree.h"
#include "segment_allocator.h"
#include <assert.h>
#include <log.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define INDEX_GUARD_SIZE 1

static struct pivot_pointer *index_get_pivot_pointer(struct pivot_key *key)
{
	return (struct pivot_pointer *)&((char *)key)[PIVOT_KEY_SIZE(key)];
}

static struct index_slot_array_entry *index_get_slot_array(struct index_node *node)
{
	char *node_array = (char *)node;
	return (struct index_slot_array_entry *)&node_array[sizeof(struct node_header)];
}

void index_add_guard(struct index_node *node, uint64_t child_node_dev_offt)
{
	char guard_buf[sizeof(struct pivot_key) + INDEX_GUARD_SIZE + sizeof(struct pivot_pointer)] = { 0 };
	struct pivot_key *guard = (struct pivot_key *)guard_buf;
	guard->size = INDEX_GUARD_SIZE;
	struct pivot_pointer *guard_pointer = index_get_pivot_pointer(guard);
	guard_pointer->child_offt = child_node_dev_offt;

	char *pivot_addr = &((char *)node)[INDEX_NODE_SIZE - PIVOT_SIZE(guard)];
	memcpy(pivot_addr, guard, PIVOT_SIZE(guard));
	assert(node->header.key_log_size == INDEX_NODE_SIZE);
	node->header.key_log_size -= PIVOT_SIZE(guard);
	node->header.num_entries = 1;
	struct index_slot_array_entry *slot_array = index_get_slot_array(node);
	slot_array[0].pivot = node->header.key_log_size;
}

bool index_is_empty(const struct index_node *node)
{
	return node->header.num_entries == 0;
}

void index_init_node(enum add_guard_option option, struct index_node *node, nodeType_t type)
{
	if (option != ADD_GUARD && option != DO_NOT_ADD_GUARD) {
		log_fatal("Unknown guard option");
		BUG_ON();
	}

	node->header.type = type;
	node->header.num_entries = 0;

	node->header.height = -1;
	node->header.fragmentation = 0;

	/*private key log for index nodes, these are unnecessary now will be deleted*/
	node->header.key_log_size = INDEX_NODE_SIZE;
	if (ADD_GUARD == option)
		index_add_guard(node, UINT64_MAX);
}

static uint32_t index_get_remaining_space(struct index_node *node)
{
	/*Is there enough space?*/
	uint64_t left_border_dev_offt =
		sizeof(struct node_header) + (node->header.num_entries * sizeof(struct index_slot_array_entry));
	/*What is the value of the right border if we append the pivot?*/
	uint64_t right_border_dev_offt = node->header.key_log_size;
	assert(right_border_dev_offt >= left_border_dev_offt);

	return right_border_dev_offt - left_border_dev_offt;
}

static uint32_t index_get_next_pivot_offt_in_node(struct index_node *node, struct pivot_key *key)
{
	uint32_t remaining_space = index_get_remaining_space(node);
	uint32_t size_needed = PIVOT_SIZE(key) + sizeof(struct index_slot_array_entry);
	//log_debug("Remaining space %u pivot_size: %lu", remaining_space, PIVOT_SIZE(key));
	return remaining_space <= size_needed ? 0 : node->header.key_log_size - PIVOT_SIZE(key);
}

bool index_is_split_needed(struct index_node *node, uint32_t max_pivot_size)
{
	max_pivot_size +=
		sizeof(struct pivot_key) + sizeof(struct pivot_pointer) + sizeof(struct index_slot_array_entry);
	return index_get_remaining_space(node) < max_pivot_size;
}

/**
 * Returns the position in the node header children offt array which we need to follow based on the lookup_key.
 * The actual offset is at node->children_offt[position]
 */
static int32_t index_search_get_pos(struct index_node *node, void *lookup_key, enum KV_type lookup_key_format,
				    bool *exact_match)
{
	*exact_match = false;

	int comparison_return_value = 0;
	int32_t start = 0;
	int32_t end = node->header.num_entries - 1;

	int32_t middle = 0;
	struct index_slot_array_entry *slot_array = index_get_slot_array(node);

	while (start <= end) {
		middle = (start + end) / 2;

		struct pivot_key *p_key = (struct pivot_key *)INDEX_PIVOT_ADDRESS(node, slot_array[middle].pivot);

		/*At zero position we have a guard or -oo*/
		comparison_return_value = index_key_cmp(p_key, (char *)lookup_key, lookup_key_format);
		if (0 == comparison_return_value) {
			*exact_match = true;
			return middle;
		}

		if (comparison_return_value > 0)
			end = middle - 1;
		else
			start = middle + 1;
	}

	return comparison_return_value > 0 ? middle - 1 : middle;
}

bool index_set_type(struct index_node *node, const nodeType_t node_type)
{
	if (!node)
		return false;

	if (node_type != internalNode && node_type != rootNode)
		return false;
	node->header.type = node_type;
	return true;
}

void index_set_height(struct index_node *node, int32_t height)
{
	if (!node)
		BUG_ON();
	node->header.height = height;
}

struct pivot_key *index_remove_last_pivot_key(struct index_node *node)
{
	if (!node)
		return NULL;
	if (0 == node->header.num_entries)
		return NULL;
	int32_t position = node->header.num_entries - 1;
	struct index_slot_array_entry *slot_array = index_get_slot_array(node);
	struct pivot_key *pivot = (struct pivot_key *)INDEX_PIVOT_ADDRESS(node, slot_array[position].pivot);

	struct pivot_key *pivot_copy = calloc(1, PIVOT_SIZE(pivot));
	memcpy(pivot_copy, pivot, PIVOT_SIZE(pivot));
	--node->header.num_entries;
	return pivot_copy;
}

static struct pivot_key *index_search_get_full_pivot(struct index_node *node, void *lookup_key,
						     enum KV_type lookup_key_format)
{
	bool unused = false; // Created here to call the function
	int32_t position = index_search_get_pos(node, lookup_key, lookup_key_format, &unused);

	struct index_slot_array_entry *slot_array = index_get_slot_array(node);
	struct pivot_key *pivot = (struct pivot_key *)INDEX_PIVOT_ADDRESS(node, slot_array[position].pivot);

	return pivot;
}

struct pivot_pointer *index_search_get_pivot(struct index_node *node, void *lookup_key, enum KV_type lookup_key_format)
{
	struct pivot_key *pivot = index_search_get_full_pivot(node, lookup_key, lookup_key_format);
	return index_get_pivot_pointer(pivot);
}

uint64_t index_binary_search(struct index_node *node, void *lookup_key, enum KV_type lookup_key_format)
{
	struct pivot_key *pivot = index_search_get_full_pivot(node, lookup_key, lookup_key_format);
	struct pivot_pointer *piv_pointer = index_get_pivot_pointer(pivot);
	return piv_pointer->child_offt;
}

static bool index_internal_insert_pivot(struct insert_pivot_req *ins_pivot_req, bool is_append)
{
	uint64_t pivot_offt_in_node = index_get_next_pivot_offt_in_node(ins_pivot_req->node, ins_pivot_req->key);

	if (!pivot_offt_in_node)
		return false;
	int32_t position = ins_pivot_req->node->header.num_entries - 1;

	struct index_slot_array_entry *slot_array = index_get_slot_array(ins_pivot_req->node);
	if (!is_append) {
		bool exact_match = false;
		position = index_search_get_pos(ins_pivot_req->node, (void *)ins_pivot_req->key, INDEX_KEY_TYPE,
						&exact_match);
		assert(position >= 0);

		//TODO refactor this and move it inside index_search_get_pos
		//On the other call sites of index_search_get_pos exact match is not an error.
		//so we should move the error reporting inside the function.
		if (exact_match) {
			log_fatal("Key size %u data: %s already present in index node", ins_pivot_req->key->size,
				  ins_pivot_req->key->data);
			BUG_ON();
		}

		/*Create room for the now entry in the slot array*/
		memmove(&slot_array[position + 2], &slot_array[position + 1],
			(ins_pivot_req->node->header.num_entries - (position + 1)) *
				sizeof(struct index_slot_array_entry));

		//log_debug("Position is %u", position);
		/*Update in-place the left_child. This is ok because we call this function for L0 which is in memory*/
		struct pivot_key *left_pivot_key =
			(struct pivot_key *)INDEX_PIVOT_ADDRESS(ins_pivot_req->node, slot_array[position].pivot);
		struct pivot_pointer *left = index_get_pivot_pointer(left_pivot_key);
		*left = *ins_pivot_req->left_child;
	}

	/*append the actual pivot --> <key_size><key><pivot>*/
	char *pivot_address = (char *)ins_pivot_req->node;
	memcpy(&pivot_address[pivot_offt_in_node], ins_pivot_req->key, PIVOT_KEY_SIZE(ins_pivot_req->key));
	memcpy(&pivot_address[pivot_offt_in_node + PIVOT_KEY_SIZE(ins_pivot_req->key)], ins_pivot_req->right_child,
	       sizeof(*ins_pivot_req->right_child));
	ins_pivot_req->node->header.key_log_size -= PIVOT_SIZE(ins_pivot_req->key);

	slot_array[position + 1].pivot = ins_pivot_req->node->header.key_log_size;

	++ins_pivot_req->node->header.num_entries;

	return true;
}

bool index_append_pivot(struct insert_pivot_req *ins_pivot_req)
{
	ins_pivot_req->left_child = NULL;
	return index_internal_insert_pivot(ins_pivot_req, 1);
}

bool index_insert_pivot(struct insert_pivot_req *ins_pivot_req)
{
	//log_debug("New pivot is %u %.*s", ins_pivot_req->key->size, ins_pivot_req->key->size, ins_pivot_req->key->data);
	return index_internal_insert_pivot(ins_pivot_req, 0);
}

static void index_internal_iterator_init(struct index_node *node, struct index_node_iterator *iterator,
					 struct pivot_key *key)
{
	iterator->node = node;

	iterator->num_entries = node->header.num_entries;

	if (node->header.num_entries <= 0) {
		iterator->key = NULL;
		return;
	}

	iterator->key = NULL;

	iterator->position = 0;
	if (!key)
		return;

	bool unused_match = false;
	// TODO: (@geostyl) @gesalous you should definetly review this
	// We take a pivot_key as key so we should compare it like an index_key_type (?)
	iterator->position = index_search_get_pos(node, key, INDEX_KEY_TYPE, &unused_match);
}

void index_iterator_init_with_key(struct index_node *node, struct index_node_iterator *iterator, struct pivot_key *key)
{
	index_internal_iterator_init(node, iterator, key);
}

void index_iterator_init(struct index_node *node, struct index_node_iterator *iterator)
{
	index_internal_iterator_init(node, iterator, NULL);
}

uint8_t index_iterator_is_valid(struct index_node_iterator *iterator)
{
	return iterator->position < iterator->num_entries;
}

struct pivot_pointer *index_iterator_get_pivot_pointer(struct index_node_iterator *iterator)
{
	struct pivot_key *piv_key = index_iterator_get_pivot_key(iterator);
	struct pivot_pointer *piv_pointer = index_get_pivot_pointer(piv_key);
	return piv_pointer;
}

struct pivot_key *index_iterator_get_pivot_key(struct index_node_iterator *iterator)
{
	if (!iterator)
		BUG_ON();

	if (!index_iterator_is_valid(iterator))
		return NULL;

	struct index_slot_array_entry *slot_array = index_get_slot_array(iterator->node);
	iterator->key = (struct pivot_key *)INDEX_PIVOT_ADDRESS(iterator->node, slot_array[iterator->position].pivot);
	++iterator->position;

	return iterator->key;
}

struct bt_rebalance_result index_split_node(struct index_node *node, bt_insert_req *ins_req)
{
	struct bt_rebalance_result result = { 0 };

	result.left_child = (struct node_header *)seg_get_index_node(
		ins_req->metadata.handle->db_desc, ins_req->metadata.level_id, ins_req->metadata.tree_id, 0);

	struct index_node_iterator iterator = { 0 };
	index_iterator_init(node, &iterator);
	struct pivot_key *piv_key = index_iterator_get_pivot_key(&iterator);
	index_init_node(DO_NOT_ADD_GUARD, (struct index_node *)result.left_child, internalNode);

	int32_t curr_entry = 0;

	while (index_iterator_is_valid(&iterator) && curr_entry < node->header.num_entries / 2) {
		struct insert_pivot_req ins_pivot_req = { .node = (struct index_node *)result.left_child,
							  .key = piv_key,
							  .right_child = index_get_pivot_pointer(piv_key) };

		if (!index_append_pivot(&ins_pivot_req)) {
			log_fatal("Could not append to index node");
			BUG_ON();
		}
		++curr_entry;
		piv_key = index_iterator_get_pivot_key(&iterator);
	}

	struct index_slot_array_entry *slot_array = index_get_slot_array(node);
	struct pivot_key *middle_key = (struct pivot_key *)INDEX_PIVOT_ADDRESS(node, slot_array[curr_entry].pivot);
	memcpy(&result.middle_key, middle_key, PIVOT_KEY_SIZE(middle_key));

	result.right_child = (node_header *)seg_get_index_node(
		ins_req->metadata.handle->db_desc, ins_req->metadata.level_id, ins_req->metadata.tree_id, 0);

	index_init_node(DO_NOT_ADD_GUARD, (struct index_node *)result.right_child, internalNode);
	struct pivot_pointer *pivotp = index_get_pivot_pointer(middle_key);
	index_add_guard((struct index_node *)result.right_child, pivotp->child_offt);

	++curr_entry;
	while (index_iterator_is_valid(&iterator) && curr_entry < node->header.num_entries) {
		piv_key = index_iterator_get_pivot_key(&iterator);

		struct insert_pivot_req ins_pivot_req = { .node = (struct index_node *)result.right_child,
							  .key = piv_key,
							  .right_child = index_get_pivot_pointer(piv_key) };

		if (!index_append_pivot(&ins_pivot_req)) {
			log_fatal("Could not append to index node");
			BUG_ON();
		}
		++curr_entry;
	}
	assert(curr_entry == node->header.num_entries);

	/*set node heights*/
	result.left_child->height = node->header.height;
	result.right_child->height = node->header.height;
	result.stat = INDEX_NODE_SPLITTED;
	return result;
}

int index_key_cmp(struct pivot_key *index_key, char *lookup_key, enum KV_type lookup_key_format)
{
	uint32_t size = 0;
	int ret = 0;

	if (lookup_key_format == KV_FORMAT) {
		struct splice *key = (struct splice *)lookup_key;
		size = index_key->size <= get_key_size(key) ? index_key->size : get_key_size(key);
		ret = memcmp(index_key->data, get_key_offset_in_kv(key), size);
		if (ret != 0)
			return ret;
		return index_key->size - get_key_size(key);
	}
	assert(lookup_key_format != KV_PREFIX);
	/* lookup_key is INDEX_KEY_TYPE
	 * this should only(!) happend when we are inserting and new key into an index node (after a split) */
	struct pivot_key *p_key = (struct pivot_key *)(lookup_key);
	size = index_key->size <= p_key->size ? index_key->size : p_key->size;
	ret = memcmp(index_key->data, p_key->data, size);
	if (ret != 0)
		return ret;
	return index_key->size - p_key->size;
}

uint32_t get_pivot_key_size(struct pivot_key *pivot)
{
	return pivot->size;
}

char *get_offset_of_pivot_key(struct pivot_key *pivot)
{
	return pivot->data;
}

void set_pivot_key_size(struct pivot_key *pivot, uint32_t key_size)
{
	pivot->size = key_size;
}

void set_pivot_key(struct pivot_key *pivot, void *key, uint32_t key_size)
{
	memcpy(pivot->data, key, key_size);
}
void fill_smallest_possible_pivot(char *buffer, int size)
{
       if (size < (int)sizeof(struct pivot_pointer) + INDEX_GUARD_SIZE) {
               log_fatal("Buffer too small cannot respresent the -oo pivot key");
               _exit(EXIT_FAILURE);
       }

       memset(buffer, 0x00, size);
       struct pivot_key *minus_infinity = (struct pivot_key *)buffer;
       minus_infinity->size = INDEX_GUARD_SIZE;
}


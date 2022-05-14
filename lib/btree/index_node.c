#include "index_node.h"
#include "segment_allocator.h"
#include <assert.h>
#include <log.h>
#include <signal.h>
#include <string.h>

#define NEW_INDEX_GUARD_SIZE 1
#define PIVOT_KEY_SIZE(X) ((X)->size + sizeof(*X))
#define PIVOT_SIZE(X) (PIVOT_KEY_SIZE(X) + sizeof(struct pivot_pointer))
#define NEW_INDEX_PIVOT_ADDRESS(X, Y) ((uint64_t)(X) + (Y))

static struct new_index_slot_array_entry *new_index_get_slot_array(struct new_index_node *node)
{
	char *node_array = (char *)node;
	return (struct new_index_slot_array_entry *)&node_array[sizeof(struct node_header)];
}

void new_index_add_guard(struct new_index_node *node, uint64_t child_node_dev_offt)
{
	//log_debug("Adding guard");
	char guard_buf[sizeof(struct pivot_key) + NEW_INDEX_GUARD_SIZE + sizeof(struct pivot_pointer)];
	struct pivot_key *guard = (struct pivot_key *)&guard_buf[0];
	guard->size = 1;
	guard->data[0] = 0x00;
	struct pivot_pointer *guard_pointer = (struct pivot_pointer *)&((char *)guard)[PIVOT_KEY_SIZE(guard)];
	guard_pointer->child_offt = child_node_dev_offt;

	char *pivot_addr = &((char *)node)[NEW_INDEX_NODE_SIZE - PIVOT_SIZE(guard)];
	memcpy(pivot_addr, guard, PIVOT_SIZE(guard));
	node->header.key_log_size -= PIVOT_SIZE(guard);
	node->header.num_entries = 1;
	struct new_index_slot_array_entry *slot_array = new_index_get_slot_array(node);
	slot_array[0].pivot = node->header.key_log_size;
}

int new_index_is_empty(struct new_index_node *node)
{
	return !node->header.num_entries;
}

void new_index_init_node(enum add_guard_option_t option, struct new_index_node *node, nodeType_t type)
{
	switch (option) {
	case ADD_GUARD:
	case DO_NOT_ADD_GUARD:
		break;
	default:
		log_fatal("Unknown guard option");
		BUG_ON();
	}

	node->header.type = type;
	node->header.num_entries = 0;

	node->header.height = -1;
	node->header.fragmentation = 0;

	/*private key log for index nodes, these are unnecessary now will be deleted*/
	node->header.first_IN_log_header = NULL;
	node->header.last_IN_log_header = NULL;
	node->header.key_log_size = NEW_INDEX_NODE_SIZE;
	if (ADD_GUARD == option)
		new_index_add_guard(node, UINT64_MAX);
}

static uint32_t new_index_get_remaining_space(struct new_index_node *node)
{
	/*Is there enough space?*/
	uint64_t left_border_dev_offt = (uint64_t)sizeof(struct node_header) +
					(node->header.num_entries * sizeof(struct new_index_slot_array_entry));
	/*What is the value of the right border if we append the pivot?*/
	uint64_t right_border_dev_offt = node->header.key_log_size;
	assert(right_border_dev_offt >= left_border_dev_offt);

	return right_border_dev_offt - left_border_dev_offt;
}

static uint32_t new_index_get_next_pivot_offt_in_node(struct new_index_node *node, struct pivot_key *key)
{
	uint32_t remaining_space = new_index_get_remaining_space(node);
	if (remaining_space <= PIVOT_SIZE(key) + sizeof(struct pivot_pointer))
		return 0;
	return node->header.key_log_size - PIVOT_SIZE(key);
}

int new_index_is_split_needed(struct new_index_node *node, uint32_t max_pivot_size)
{
	uint32_t remaining_space = new_index_get_remaining_space(node);
	if (remaining_space < max_pivot_size)
		return 1;
	return 0;
}

/*
 * Returns the position in the node header children offt array which we need to follow based on the lookup_key.
 * The actual offset is at node->children_offt[position]
*/
static int32_t new_index_search_get_pos(struct new_index_node *node, void *lookup_key, enum KV_type lookup_key_format,
					uint8_t *exact_match)
{
	*exact_match = 0;

	int64_t comparison_return_value = 0;
	int32_t start = 0;
	int32_t end = node->header.num_entries - 1;

	int32_t middle = 0;

	struct new_index_slot_array_entry *slot_array = new_index_get_slot_array(node);

	while (start <= end) {
		middle = (start + end) / 2;

		struct key_compare pivot_cmp = { 0 };
		struct key_compare lookup_key_cmp = { 0 };
		struct pivot_key *p_key = (struct pivot_key *)NEW_INDEX_PIVOT_ADDRESS(node, slot_array[middle].pivot);

		init_key_cmp(&pivot_cmp, p_key, KV_FORMAT);
		init_key_cmp(&lookup_key_cmp, lookup_key, lookup_key_format);
		comparison_return_value = key_cmp(&pivot_cmp, &lookup_key_cmp);

		if (0 == comparison_return_value) {
			*exact_match = 1;
			return middle;
		}

		if (comparison_return_value > 0)
			end = middle - 1;
		else
			start = middle + 1;
	}

	if (comparison_return_value > 0)
		return middle - 1;
	return middle;
}

int new_index_set_type(struct new_index_node *node, nodeType_t node_type)
{
	if (!node)
		return -1;

	switch (node_type) {
	case internalNode:
	case rootNode:
		break;
	default:
		return -1;
	}
	node->header.type = node_type;
	return 0;
}

void new_index_set_height(struct new_index_node *node, int32_t height)
{
	if (!node)
		return;
	node->header.height = height;
}

struct pivot_key *new_index_remove_last_pivot_key(struct new_index_node *node)
{
	if (!node)
		return NULL;
	if (0 == node->header.num_entries)
		return NULL;
	int32_t position = node->header.num_entries - 1;
	struct new_index_slot_array_entry *slot_array = new_index_get_slot_array(node);
	struct pivot_key *pivot = (struct pivot_key *)NEW_INDEX_PIVOT_ADDRESS(node, slot_array[position].pivot);

	struct pivot_key *pivot_copy = calloc(1, PIVOT_SIZE(pivot));
	memcpy(pivot_copy, pivot, PIVOT_SIZE(pivot));
	--node->header.num_entries;
	return pivot_copy;
}

static struct pivot_key *new_index_search_get_full_pivot(struct new_index_node *node, void *lookup_key,
							 enum KV_type lookup_key_format)
{
	//log_debug("<search>");
	uint8_t exact_match = 0;
	int32_t position = new_index_search_get_pos(node, lookup_key, lookup_key_format, &exact_match);

	struct new_index_slot_array_entry *slot_array = new_index_get_slot_array(node);
	struct pivot_key *pivot = (struct pivot_key *)NEW_INDEX_PIVOT_ADDRESS(node, slot_array[position].pivot);
	//log_debug("Position is %d exact match %u pivot: %.*s lookup key %.*s node height %d", position, exact_match,
	//	  pivot->size, pivot->data, *(uint32_t *)lookup_key, &((char *)lookup_key)[4], node->header.height);
	//log_debug("</search>");

	return pivot;
}

struct pivot_pointer *new_index_search_get_pivot_from_pos(struct new_index_node *node, int32_t position)
{
	if (position >= node->header.num_entries)
		return NULL;

	struct new_index_slot_array_entry *slot_array = new_index_get_slot_array(node);
	struct pivot_key *pivot = (struct pivot_key *)NEW_INDEX_PIVOT_ADDRESS(node, slot_array[position].pivot);
	return (struct pivot_pointer *)&((char *)pivot)[PIVOT_SIZE(pivot)];
}

struct pivot_pointer *new_index_search_get_pivot(struct new_index_node *node, void *lookup_key,
						 enum KV_type lookup_key_format)
{
	struct pivot_key *pivot = new_index_search_get_full_pivot(node, lookup_key, lookup_key_format);
	uint32_t pivot_size = PIVOT_KEY_SIZE(pivot);
	struct pivot_pointer *pivot_p = (struct pivot_pointer *)&((char *)pivot)[pivot_size];
	return pivot_p;
}

uint64_t new_index_binary_search(struct new_index_node *node, void *lookup_key, enum KV_type lookup_key_format)
{
	struct pivot_key *pivot = new_index_search_get_full_pivot(node, lookup_key, lookup_key_format);
	uint64_t *child_offt = (uint64_t *)&((char *)pivot)[PIVOT_KEY_SIZE(pivot)];
	return *child_offt;
}

static int new_index_internal_insert_pivot(struct new_index_node *node, struct pivot_pointer *left_child,
					   struct pivot_key *key, struct pivot_pointer *right_child, uint8_t is_append)
{
	uint64_t pivot_offt_in_node = new_index_get_next_pivot_offt_in_node(node, key);

	if (!pivot_offt_in_node)
		return -1;
	int32_t position = node->header.num_entries - 1;

	struct new_index_slot_array_entry *slot_array = new_index_get_slot_array(node);
	if (!is_append) {
		uint8_t exact_match = 0;
		position = new_index_search_get_pos(node, (void *)key, KV_FORMAT, &exact_match);
		assert(position >= 0);

		if (exact_match) {
			log_fatal("Key size %u data: %s already present in index node", key->size, key->data);
			assert(0);
			BUG_ON();
		}

		/*Create room for the now entry in the slot array*/
		memmove(&slot_array[position + 2], &slot_array[position + 1],
			(node->header.num_entries - (position + 1)) * sizeof(struct new_index_slot_array_entry));

		//log_debug("Position is %u", position);
		/*Update in-place the left_child. This is ok because we call this function for L0 which is in memory*/
		struct pivot_key *left_pivot_key =
			(struct pivot_key *)NEW_INDEX_PIVOT_ADDRESS(node, slot_array[position].pivot);
		struct pivot_pointer *left =
			(struct pivot_pointer *)&((char *)left_pivot_key)[PIVOT_KEY_SIZE(left_pivot_key)];
		*left = *left_child;
	}

	/*append the actual pivot --> <key_size><key><pivot>*/
	char *pivot_address = (char *)node;
	memcpy(&pivot_address[pivot_offt_in_node], key, PIVOT_KEY_SIZE(key));
	memcpy(&pivot_address[pivot_offt_in_node + PIVOT_KEY_SIZE(key)], right_child, sizeof(*right_child));
	node->header.key_log_size -= PIVOT_SIZE(key);

	slot_array[position + 1].pivot = node->header.key_log_size;

	++node->header.num_entries;

	return 0;
}

int new_index_append_pivot(struct new_index_node *node, struct pivot_key *key, struct pivot_pointer *right_child)
{
	//log_debug("Appending pivot %.*s child_offt %lu", key->size, key->data, right_child->child_offt);
	return new_index_internal_insert_pivot(node, NULL, key, right_child, 1);
}

int new_index_insert_pivot(struct new_index_node *node, struct pivot_pointer *left_child, struct pivot_key *key,
			   struct pivot_pointer *right_child)
{
	//log_debug("Insert pivot %.*s", key->size, key->data);
	return new_index_internal_insert_pivot(node, left_child, key, right_child, 0);
}

static void new_index_internal_iterator_init(struct new_index_node *node, struct new_index_node_iterator *iterator,
					     struct pivot_key *key)
{
	iterator->node = node;

	iterator->num_entries = node->header.num_entries;

	if (node->header.num_entries <= 0) {
		iterator->is_valid = 0;
		iterator->key = NULL;
		return;
	}

	iterator->is_valid = 1;
	iterator->key = NULL;

	iterator->position = 0;
	if (key) {
		uint8_t exact_match = 0;
		iterator->position = new_index_search_get_pos(node, key, KV_FORMAT, &exact_match);
	}
}

void new_index_iterator_init_with_key(struct new_index_node *node, struct new_index_node_iterator *iterator,
				      struct pivot_key *key)
{
	new_index_internal_iterator_init(node, iterator, key);
}

void new_index_iterator_init(struct new_index_node *node, struct new_index_node_iterator *iterator)
{
	new_index_internal_iterator_init(node, iterator, NULL);
}

uint8_t new_index_iterator_is_valid(struct new_index_node_iterator *iterator)
{
	if (iterator->position >= iterator->num_entries)
		iterator->is_valid = 0;

	return iterator->is_valid;
}

struct pivot_pointer *new_index_iterator_get_pivot_pointer(struct new_index_node_iterator *iterator)
{
	struct pivot_key *piv_key = new_index_iterator_get_pivot_key(iterator);
	struct pivot_pointer *piv_pointer = (struct pivot_pointer *)&((char *)piv_key)[PIVOT_KEY_SIZE(piv_key)];
	return piv_pointer;
}

struct pivot_key *new_index_iterator_get_pivot_key(struct new_index_node_iterator *iterator)
{
	if (iterator->position >= iterator->num_entries)
		return NULL;

	struct new_index_slot_array_entry *slot_array = new_index_get_slot_array(iterator->node);
	iterator->key =
		(struct pivot_key *)NEW_INDEX_PIVOT_ADDRESS(iterator->node, slot_array[iterator->position].pivot);
	++iterator->position;

	return iterator->key;
}

struct bt_rebalance_result new_index_split_node(struct new_index_node *node, bt_insert_req *ins_req)
{
	struct bt_rebalance_result result = { 0 };
	struct new_index_node_iterator iterator;

	result.left_child = (struct node_header *)seg_get_index_node(
		ins_req->metadata.handle->db_desc, ins_req->metadata.level_id, ins_req->metadata.tree_id, 0);

	new_index_iterator_init(node, &iterator);
	struct pivot_key *piv_key = new_index_iterator_get_pivot_key(&iterator);
	new_index_init_node(DO_NOT_ADD_GUARD, (struct new_index_node *)result.left_child, internalNode);
	//struct pivot_pointer *pivot_p = (struct pivot_pointer *)&((char *)piv_key)[PIVOT_KEY_SIZE(piv_key)];
	//new_index_add_guard((struct new_index_node *)result.left_child, pivot_p->child_offt);

	int32_t curr_entry = 0;

	//log_debug("First .Iterator: pivot key is %.*s", piv_key->size, piv_key->data);

	while (new_index_iterator_is_valid(&iterator) && curr_entry < node->header.num_entries / 2) {
		int ret = new_index_append_pivot((struct new_index_node *)result.left_child, piv_key,
						 (struct pivot_pointer *)&((char *)piv_key)[PIVOT_KEY_SIZE(piv_key)]);
		if (ret) {
			log_fatal("Could not append to index node");
			assert(0);
			BUG_ON();
		}
		++curr_entry;
		piv_key = new_index_iterator_get_pivot_key(&iterator);
		//log_debug("Iterator: pivot key is %.*s", piv_key->size, piv_key->data);
	}

	struct new_index_slot_array_entry *slot_array = new_index_get_slot_array(node);
	struct pivot_key *middle_key = (struct pivot_key *)NEW_INDEX_PIVOT_ADDRESS(node, slot_array[curr_entry].pivot);
	memcpy(&result.middle_key, middle_key, PIVOT_KEY_SIZE(middle_key));
	//log_debug("Middle key is: pivot key is %.*s", piv_key->size, piv_key->data);

	result.right_child = (node_header *)seg_get_index_node(
		ins_req->metadata.handle->db_desc, ins_req->metadata.level_id, ins_req->metadata.tree_id, 0);

	new_index_init_node(DO_NOT_ADD_GUARD, (struct new_index_node *)result.right_child, internalNode);
	struct pivot_pointer *pivotp = (struct pivot_pointer *)&((char *)middle_key)[PIVOT_KEY_SIZE(middle_key)];
	new_index_add_guard((struct new_index_node *)result.right_child, pivotp->child_offt);

	++curr_entry;
	while (new_index_iterator_is_valid(&iterator) && curr_entry < node->header.num_entries) {
		piv_key = new_index_iterator_get_pivot_key(&iterator);
		if (new_index_append_pivot((struct new_index_node *)result.right_child, piv_key,
					   (struct pivot_pointer *)&((char *)piv_key)[PIVOT_KEY_SIZE(piv_key)])) {
			log_fatal("Could not append to index node");
			BUG_ON();
		}
		++curr_entry;
	}

	/*set node heights*/
	result.left_child->height = node->header.height;
	result.right_child->height = node->header.height;
	result.stat = INDEX_NODE_SPLITTED;
	return result;
}

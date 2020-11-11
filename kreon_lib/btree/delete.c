#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "../scanner/scanner.h"
#include <log.h>
#include "conf.h"
#include "segment_allocator.h"
#include "delete.h"
#include "static_leaf.h"

extern int32_t index_order;

int8_t __delete_key(bt_delete_request *req)
{
	volume_descriptor *volume_desc;
	node_header *node_copy;
	pr_system_catalogue *mem_catalogue;
	void *next_addr;
	db_descriptor *db_desc;
	node_header *parent;
	node_header *son;
	node_header *flag = NULL;
	uint32_t order;
	int8_t ret;
	db_desc = req->metadata.handle->db_desc;
	volume_desc = req->metadata.handle->volume_desc;
	mem_catalogue = req->metadata.handle->volume_desc->mem_catalogue;

retry:

	parent = flag = NULL;

	son = db_desc->levels[req->metadata.level_id].root_w[req->metadata.tree_id];

	if (son->height != 0) {
		while (1) {
			if (son->type == leafNode || son->type == leafRootNode)
				order = (db_desc->levels[req->metadata.level_id].leaf_offsets.kv_entries / 2) + 1;
			else
				order = (index_order / 2) + 1;

			if (son->numberOfEntriesInNode < order && son->type != rootNode) {
				son->v1++;
				rotate_data siblings = {
					.left = NULL, .right = NULL, .pivot = NULL, .pos_left = -1, .pos_right = -1
				};
				__find_position_in_index((index_node *)parent, (struct splice *)req->key_buf,
							 &siblings);
				__find_left_and_right_siblings((index_node *)parent, req->key_buf, &siblings);
				ret = transfer_node_to_neighbor_index_node((index_node *)son, (index_node *)parent,
									   &siblings, req);

				if (ret == ROTATE_IMPOSSIBLE_TRY_TO_MERGE)
					merge_with_index_neighbor((index_node *)son, (index_node *)parent, &siblings,
								  req);

				son->v2++;
				goto retry;

			} else if (son->epoch <= volume_desc->dev_catalogue->epoch) {
				if (son->height > 0) {
					node_copy = (node_header *)seg_get_index_node_header(
						volume_desc, &db_desc->levels[req->metadata.level_id],
						req->metadata.tree_id, COW_FOR_INDEX);

					memcpy(node_copy, son, INDEX_NODE_SIZE);
					seg_free_index_node_header(volume_desc,
								   &db_desc->levels[req->metadata.level_id],
								   req->metadata.tree_id, son);

				} else {
					node_copy = (node_header *)seg_get_leaf_node_header(
						volume_desc, &db_desc->levels[req->metadata.level_id],
						req->metadata.tree_id, COW_FOR_LEAF);
					memcpy(node_copy, son, LEAF_NODE_SIZE);
					seg_free_leaf_node(volume_desc, &db_desc->levels[req->metadata.level_id],
							   req->metadata.tree_id, (leaf_node *)son);
				}
				node_copy->epoch = mem_catalogue->epoch;
				son = node_copy;
				/*Update father's pointer*/
				if (parent != NULL) {
					parent->v1++; /*lamport counter*/
					*(uint64_t *)next_addr = (uint64_t)node_copy - MAPPED;
					parent->v2++; /*lamport counter*/
				} else { /*We COWED the root*/
					db_desc->levels[req->metadata.level_id].root_w[req->metadata.tree_id] =
						node_copy;
				}

				goto retry;
			} else if (son->numberOfEntriesInNode < order && son->type != rootNode) {
				rotate_data siblings = {
					.left = NULL, .right = NULL, .pivot = NULL, .pos_left = -1, .pos_right = -1
				};
				__find_position_in_index((index_node *)parent, (struct splice *)req->key_buf,
							 &siblings);
				__find_left_and_right_siblings((index_node *)parent, req->key_buf, &siblings);
				parent->v1++;
				son->v1++;
				if (siblings.left)
					siblings.left->v1++;

				if (siblings.right)
					siblings.right->v1++;

				ret = transfer_node_to_neighbor_index_node((index_node *)son, (index_node *)parent,
									   &siblings, req);

				if (ret == 3) {
					merge_with_index_neighbor((index_node *)son, (index_node *)parent, &siblings,
								  req);
				}
				if (siblings.left)
					siblings.left->v2++;

				if (siblings.right)
					siblings.right->v2++;

				son->v2++;
				parent->v2++;
				goto retry;
			}

			next_addr =
				_index_node_binary_search((index_node *)son, req->key_buf, req->metadata.key_format);
			parent = son;

			son = (node_header *)REAL_ADDRESS(*(uint64_t *)next_addr);

			if (son->height == 0)
				break;
		}
	}
	assert(!son->height);
	if (parent)
		parent->v1++;
	son->v1++; /*lamport counter*/
	ret = delete_key_value_from_leaf(req, (index_node *)parent, (leaf_node *)son, (struct splice *)req->key_buf);
	son->v2++; /*lamport counter*/
	if (parent)
		parent->v2++;
	return ret;
}

uint8_t delete_key_value_from_leaf(bt_delete_request *req, index_node *parent, leaf_node *leaf, struct splice *key)
{
	/* We need these variables to find the neighboring nodes
	   in case we delete a kv pair from the first or the last node.  */

	rotate_data siblings = { .left = NULL, .right = NULL, .pivot = NULL };
	struct sl_bsearch_result result = { .middle = 0, .status = INSERT, .op = STATIC_LEAF_FIND };
	level_descriptor *level = &req->metadata.handle->db_desc->levels[leaf->header.level_id];
	int pos;
	int8_t ret;

	if (parent)
		__find_left_and_right_siblings(parent, key, &siblings);

	if (siblings.left != NULL) {
		assert(siblings.left->type == leafNode);
		siblings.left->v1++;
	}

	if (siblings.right != NULL) {
		assert(siblings.right->type == leafNode);
		siblings.right->v1++;
	}

	switch (level->node_layout) {
	case STATIC_LEAF:
		binary_search_static_leaf((struct bt_static_leaf_node *)leaf, level, key, &result);
		break;
	case DYNAMIC_LEAF:
		break;
	}

	if (result.status == FOUND) {
		pos = result.middle;

		if (req->metadata.level_id == 0) {
			log_operation append_op = { .metadata = &req->metadata,
						    .optype_tolog = deleteOp,
						    .del_req = req };
			append_key_value_to_log(&append_op);
		}

		switch (level->node_layout) {
		case STATIC_LEAF:
			delete_key_value_from_static_leaf((struct bt_static_leaf_node *)leaf, level, pos);
			break;
		case DYNAMIC_LEAF:
			log_fatal("NOT IMPLEMENTED");
			break;
		}

		req->metadata.handle->db_desc->dirty = 1;

		if (leaf->header.type == leafRootNode)
			return SUCCESS;

		ret = check_for_underflow_in_leaf(leaf, &siblings, req);

		if (ret == ROTATE_IMPOSSIBLE_TRY_TO_MERGE) {
			/* We could not borrow anything from the left and right neighbors.
				   We will try to merge with one of them.
				   If we cannot merge that's a fatal error!
				*/
			merge_with_leaf_neighbor(leaf, &siblings, req);
		}

		if (siblings.left != NULL) {
			siblings.left->v2++;
		}

		if (siblings.right != NULL) {
			siblings.right->v2++;
		}

		return SUCCESS;
	}

	return FAILED;
}

void __update_index_pivot_in_place(bt_delete_request *del_req, node_header *node, void *node_index_addr, void *key_buf)
{
	void *key_addr;

	IN_log_header *d_header = NULL;
	IN_log_header *last_d_header = NULL;
	struct db_handle *handle = del_req->metadata.handle;
	int32_t avail_space;
	int32_t req_space;
	int32_t allocated_space;
	int level_id = del_req->metadata.level_id;
	int tree_id = del_req->metadata.tree_id;

	int key_len = *(uint32_t *)key_buf;
	if (node->type == leafNode || node->type == leafRootNode) {
		log_fatal("We should not access leafNode as there are no pivots in leaves.");
		assert(0);
	}

	if (node->key_log_size % KEY_BLOCK_SIZE == 0)
		avail_space = 0;
	else
		avail_space = (int32_t)KEY_BLOCK_SIZE - (node->key_log_size % (int32_t)KEY_BLOCK_SIZE);

	req_space = (key_len + sizeof(int32_t));
	if (avail_space < req_space) { /*room not sufficient*/
		/*get new block*/
		allocated_space = (req_space + sizeof(node_header)) / KEY_BLOCK_SIZE;

		if ((req_space + sizeof(node_header)) % KEY_BLOCK_SIZE != 0)
			allocated_space++;

		allocated_space *= KEY_BLOCK_SIZE;
		d_header = seg_get_IN_log_block(handle->volume_desc, &handle->db_desc->levels[level_id], tree_id,
						KEY_LOG_EXPANSION);

		d_header->next = NULL;
		last_d_header = (IN_log_header *)(MAPPED + (uint64_t)node->last_IN_log_header);
		last_d_header->next = (void *)((uint64_t)d_header - MAPPED);
		node->last_IN_log_header = last_d_header->next;
		node->key_log_size +=
			(avail_space + sizeof(IN_log_header)); /* position the log to the newly added block */
	}

	/* put the KV now */
	key_addr =
		(void *)MAPPED + (uint64_t)node->last_IN_log_header + (uint64_t)(node->key_log_size % KEY_BLOCK_SIZE);
	memcpy(key_addr, key_buf, sizeof(int32_t) + key_len); /*key length */
	*(uint64_t *)node_index_addr = (uint64_t)key_addr - MAPPED;
	node->key_log_size += sizeof(int32_t) + key_len;
}

void *_index_node_binary_search_posret(index_node *node, void *key_buf, char query_key_format,
				       struct siblings_index_entries *neighbor)
{
	void *addr = NULL;
	void *index_key_buf;
	int64_t ret;
	int32_t middle = 0;
	int32_t start_idx = 0;
	int32_t end_idx = node->header.numberOfEntriesInNode - 1;
	int32_t numberOfEntriesInNode = node->header.numberOfEntriesInNode;

	while (numberOfEntriesInNode > 0) {
		middle = (start_idx + end_idx) / 2;

		if (numberOfEntriesInNode > index_order || middle < 0 || middle >= numberOfEntriesInNode)
			return NULL;

		addr = &(node->p[middle].pivot);
		index_key_buf = REAL_ADDRESS(*(uint64_t *)addr);
		ret = _tucana_key_cmp(index_key_buf, key_buf, KV_FORMAT, query_key_format);
		if (ret == 0) {
			addr = &(node->p[middle].right[0]);
			neighbor->right_pos = neighbor->left_pos = middle;
			neighbor->left_entry = &node->p[middle];
			if ((middle + 1) < numberOfEntriesInNode) {
				neighbor->right_entry = &node->p[middle + 1];
			}
			break;
		} else if (ret > 0) {
			end_idx = middle - 1;
			if (start_idx > end_idx) {
				addr = &(node->p[middle].left[0]);

				if ((middle - 1) > 0) {
					neighbor->left_entry = &node->p[middle - 1];
					neighbor->left_pos = middle - 1;
				}
				neighbor->right_pos = middle;
				neighbor->right_entry = &node->p[middle];

				middle--;
				break;
			}
		} else { /* ret < 0 */
			start_idx = middle + 1;
			if (start_idx > end_idx) {
				neighbor->right_entry = NULL;
				neighbor->left_entry = &node->p[middle];
				neighbor->left_pos = neighbor->right_pos = middle;

				if ((middle + 1) < numberOfEntriesInNode) {
					neighbor->right_entry = &node->p[middle + 1];
					neighbor->right_pos = middle + 1;
				}
				addr = &(node->p[middle].right[0]);
				middle++;
				break;
			}
		}
	}

	if (middle < 0) {
		addr = &(node->p[0].left[0]);
		neighbor->left_entry = NULL;
		neighbor->right_entry = &node->p[0];
		neighbor->right_pos = 0;
	} else if (middle >= numberOfEntriesInNode) {
		addr = &(node->p[node->header.numberOfEntriesInNode - 1].right[0]);
		neighbor->left_entry = &node->p[node->header.numberOfEntriesInNode - 1];
		neighbor->left_pos = node->header.numberOfEntriesInNode - 1;
		neighbor->right_entry = NULL;
	}
	return addr;
}

void underflow_borrow_from_right_neighbor(leaf_node *curr, leaf_node *right, bt_delete_request *req)
{
	struct siblings_index_entries neighbor_metadata = { .left_entry = NULL, .right_entry = NULL };
	node_header *parent = (node_header *)req->parent;
	void *key_addr;
	/* raise(SIGINT); */

	/* First steal the kv pointer + prefix */
	curr->pointer[curr->header.numberOfEntriesInNode] = right->pointer[0];
	memcpy(curr->prefix[curr->header.numberOfEntriesInNode], right->prefix[0], PREFIX_SIZE);
	++curr->header.numberOfEntriesInNode;

	/* Fix the pointers and prefixes of the right neighbor */
	memmove(&right->pointer[0], &right->pointer[1], (right->header.numberOfEntriesInNode - 1) * sizeof(uint64_t));

	memmove(right->prefix[0], right->prefix[1], PREFIX_SIZE * (right->header.numberOfEntriesInNode - 1));

	--right->header.numberOfEntriesInNode;

	key_addr = (void *)(MAPPED + right->pointer[0]);
	assert(parent->type != leafNode);

	_index_node_binary_search_posret(req->parent, req->key_buf, KV_FORMAT, &neighbor_metadata);

	if (neighbor_metadata.right_entry == NULL) {
		log_fatal("We are the rightmost node so we cannot borrow from the right leaf");
		assert(0);
	}

	/* Fix the pivot in the parent node */
	__update_index_pivot_in_place(req, parent, (&neighbor_metadata.right_entry->pivot), key_addr);
}

void underflow_borrow_from_left_neighbor(leaf_node *curr, leaf_node *left, bt_delete_request *req)
{
	struct siblings_index_entries neighbor_metadata = { .left_entry = NULL, .right_entry = NULL };
	void *key_addr;

	memmove(curr->prefix[1], curr->prefix[0], PREFIX_SIZE * curr->header.numberOfEntriesInNode);

	memmove(&curr->pointer[1], &curr->pointer[0], sizeof(uint64_t) * curr->header.numberOfEntriesInNode);

	/* Move the leftmost KV pair */

	curr->pointer[0] = left->pointer[left->header.numberOfEntriesInNode - 1];
	memcpy(curr->prefix[0], left->prefix[left->header.numberOfEntriesInNode - 1], PREFIX_SIZE);
	++curr->header.numberOfEntriesInNode;
	--left->header.numberOfEntriesInNode;
	/* NOTE in this case we don't have to move anything as it is the last KV pair. */
	key_addr = (void *)(MAPPED + curr->pointer[0]);
	_index_node_binary_search_posret(req->parent, req->key_buf, KV_FORMAT, &neighbor_metadata);

	assert(neighbor_metadata.left_entry);

	/* A pivot change should happen in the parent index node */
	__update_index_pivot_in_place(req, &neighbor_metadata.left_entry->pivot, key_addr, req->metadata.level_id);
}

void merge_with_right_neighbor(leaf_node *curr, leaf_node *right, bt_delete_request *req)
{
	struct siblings_index_entries parent_metadata = {
		.left_entry = NULL, .right_entry = NULL, .left_pos = 0, .right_pos = 0
	};
	index_node *parent = req->parent;

	memcpy(&curr->pointer[curr->header.numberOfEntriesInNode], &right->pointer[0],
	       right->header.numberOfEntriesInNode * sizeof(uint64_t));

	memcpy(curr->prefix[curr->header.numberOfEntriesInNode], right->prefix[0],
	       right->header.numberOfEntriesInNode * PREFIX_SIZE);

	curr->header.numberOfEntriesInNode += right->header.numberOfEntriesInNode;

	_index_node_binary_search_posret(parent, req->key_buf, KV_FORMAT, &parent_metadata);

	assert(right == ((leaf_node *)(MAPPED + parent->p[parent_metadata.right_pos + 1].left[0])));

	if (parent->header.numberOfEntriesInNode == 1) {
		if (parent->header.type == rootNode) {
			curr->header.type = leafRootNode;
			curr->header.height = 0;
			//req->metadata.handle->db_desc->levels[req->metadata.level_id].root_w[req->metadata.active_tree] =
			req->metadata.handle->db_desc->levels[req->metadata.level_id].root_w[req->metadata.tree_id] =
				(node_header *)curr;
			return;
		}
		assert(0);
	}

	uint32_t remaining_bytes = (parent->header.numberOfEntriesInNode * sizeof(index_entry)) + sizeof(uint64_t) -
				   (parent_metadata.right_pos * sizeof(index_entry));
	parent->p[parent_metadata.right_pos].pivot = parent->p[parent_metadata.right_pos + 1].pivot;
	memmove(&parent->p[parent_metadata.right_pos + 1], &parent->p[parent_metadata.right_pos + 2], remaining_bytes);
	--parent->header.numberOfEntriesInNode;
	assert(parent->header.numberOfEntriesInNode >= 1);
	//In this case we do not have to change anything to the right neighbor
	//nor to change the pivots in our parent.Reclaim the node space here.
}

void merge_with_left_neighbor(leaf_node *curr, leaf_node *left, bt_delete_request *req)
{
	struct siblings_index_entries parent_metadata = {
		.left_entry = NULL, .right_entry = NULL, .left_pos = 0, .right_pos = 0
	};
	index_node *parent = req->parent;
	/* First move the kv pointers + prefixes to make space
       for the kv pointers + prefixes of the left leaf */
	memmove(&curr->prefix[left->header.numberOfEntriesInNode], &curr->prefix[0],
		PREFIX_SIZE * curr->header.numberOfEntriesInNode);

	memmove(&curr->pointer[left->header.numberOfEntriesInNode], &curr->pointer[0],
		sizeof(uint64_t) * curr->header.numberOfEntriesInNode);

	/* copy the kv pointers + prefixes from the left leaf */

	memcpy(&curr->prefix[0], &left->prefix[0], PREFIX_SIZE * left->header.numberOfEntriesInNode);

	memcpy(&curr->pointer[0], &left->pointer[0], sizeof(uint64_t) * left->header.numberOfEntriesInNode);

	/* Shift every index entry of the parent to the left
       to remove the left leaf node from the index*/
	curr->header.numberOfEntriesInNode += left->header.numberOfEntriesInNode;
	_index_node_binary_search_posret(parent, req->key_buf, KV_FORMAT, &parent_metadata);

	if (parent->header.numberOfEntriesInNode == 1) {
		if (parent->header.type == rootNode) {
			curr->header.type = leafRootNode;
			//req->metadata.handle->db_desc->levels[req->metadata.level_id].root_w[req->metadata.active_tree] =
			req->metadata.handle->db_desc->levels[req->metadata.level_id].root_w[req->metadata.tree_id] =
				(node_header *)curr;
			return;
		}
		assert(0);
	}

	memmove(&parent->p[parent_metadata.left_pos], &parent->p[parent_metadata.left_pos + 1],
		(sizeof(index_entry) * (parent->header.numberOfEntriesInNode - (parent_metadata.left_pos + 1))) +
			sizeof(uint64_t));

	--parent->header.numberOfEntriesInNode;
	assert(parent->header.numberOfEntriesInNode >= 1);
	/* Free the left leaf node */
}

int8_t merge_with_leaf_neighbor(leaf_node *leaf, rotate_data *siblings, bt_delete_request *req)
{
	leaf_node *left = (leaf_node *)siblings->left;
	leaf_node *right = (leaf_node *)siblings->right;
	level_descriptor *level = &req->metadata.handle->db_desc->levels[leaf->header.level_id];
	uint64_t merged_with_left_num_entries = 0, merged_with_right_num_entries = 0;
	uint64_t max_len = req->metadata.handle->db_desc->levels[leaf->header.level_id].leaf_offsets.kv_entries;
	int8_t ret = NO_REBALANCE_NEEDED;

	if (left)
		merged_with_left_num_entries = leaf->header.numberOfEntriesInNode + left->header.numberOfEntriesInNode;

	if (right)
		merged_with_right_num_entries =
			leaf->header.numberOfEntriesInNode + right->header.numberOfEntriesInNode;

	if (merged_with_left_num_entries && merged_with_left_num_entries < max_len) {
		/* We can merge with the right neighbor */
		ret = MERGE_WITH_LEFT;
		left->header.v1++;
		switch (level->node_layout) {
		case STATIC_LEAF:
			merge_with_left_static_leaf_neighbor((struct bt_static_leaf_node *)leaf,
							     (struct bt_static_leaf_node *)left, level, req);
			break;
		case DYNAMIC_LEAF:
			log_fatal("NOT IMPLEMENTED");
			break;
		}
		left->header.v2++;
	} else if (merged_with_right_num_entries && merged_with_right_num_entries < max_len) {
		/* We can merge with the left neighbor */
		ret = MERGE_WITH_RIGHT;
		right->header.v1++;
		switch (level->node_layout) {
		case STATIC_LEAF:
			merge_with_right_static_leaf_neighbor((struct bt_static_leaf_node *)leaf,
							      (struct bt_static_leaf_node *)right, level, req);
			break;
		case DYNAMIC_LEAF:
			log_fatal("NOT IMPLEMENTED");
			break;
		}
		right->header.v2++;
	} else {
		ret = MERGE_IMPOSSIBLE_FATAL;
		log_fatal(
			"If we reached this case then we cannot borrow a key from the left or right neighbor nor we can merge with them");
		exit(EXIT_FAILURE);
	}
	return ret;
}

int8_t check_for_underflow_in_leaf(leaf_node *leaf, rotate_data *siblings, bt_delete_request *req)
{
	leaf_node *left = (leaf_node *)siblings->left;
	leaf_node *right = (leaf_node *)siblings->right;
	level_descriptor *level = &req->metadata.handle->db_desc->levels[leaf->header.level_id];
	uint64_t kv_entries = req->metadata.handle->db_desc->levels[leaf->header.level_id].leaf_offsets.kv_entries;
	uint64_t underflow_threshold = kv_entries / 2, borrow_threshold = underflow_threshold + 1;
	int8_t ret = NO_REBALANCE_NEEDED;

	/* If underflow is detected pivots have to change also. */

	if (leaf->header.numberOfEntriesInNode < underflow_threshold) {
		if (left && (left->header.numberOfEntriesInNode >= borrow_threshold)) {
			/* Steal the rightmost KV pair from the left sibling */
			ret = ROTATE_WITH_LEFT;
			left->header.v1++;
			switch (level->node_layout) {
			case STATIC_LEAF:
				underflow_borrow_from_left_static_leaf_neighbor((struct bt_static_leaf_node *)leaf,
										(struct bt_static_leaf_node *)left,
										level, req);
				break;
			case DYNAMIC_LEAF:
				log_fatal("NOT IMPLEMENTED");
				break;
			}
			left->header.v2++;
		} else if (right && (right->header.numberOfEntriesInNode >= borrow_threshold)) {
			/* Steal the leftmost KV pair from the right sibling */
			ret = ROTATE_WITH_RIGHT;
			right->header.v1++;
			switch (level->node_layout) {
			case STATIC_LEAF:
				underflow_borrow_from_right_static_leaf_neighbor((struct bt_static_leaf_node *)leaf,
										 (struct bt_static_leaf_node *)right,
										 level, req);
				break;
			case DYNAMIC_LEAF:
				log_fatal("NOT IMPLEMENTED");
				break;
			}
			right->header.v2++;
		} else {
			/* We could not borrow a KV pair from the siblings
			   a merge should be triggered now. */
			ret = ROTATE_IMPOSSIBLE_TRY_TO_MERGE;
		}
	}
	return ret;
}

void __find_left_and_right_siblings(index_node *parent, void *key, rotate_data *siblings)
{
	void *addr = NULL;
	void *index_key_buf;
	int64_t ret;
	int32_t middle = 0;
	int32_t start_idx = 0;
	int32_t end_idx = parent->header.numberOfEntriesInNode - 1;
	int32_t numberOfEntriesInNode = parent->header.numberOfEntriesInNode;

	while (numberOfEntriesInNode > 0) {
		middle = (start_idx + end_idx) / 2;

		if (numberOfEntriesInNode > index_order || middle < 0 || middle >= numberOfEntriesInNode)
			return;

		addr = &(parent->p[middle].pivot);
		index_key_buf = REAL_ADDRESS(*(uint64_t *)addr);
		ret = _tucana_key_cmp(index_key_buf, key, KV_FORMAT, KV_FORMAT);
		if (ret == 0) {
			siblings->pivot = index_key_buf; //Saving the pivot in case we need to replace it.
			addr = &(parent->p[middle].right[0]);
			siblings->left = (node_header *)REAL_ADDRESS(parent->p[middle].left[0]);

			if ((middle + 1) < (numberOfEntriesInNode - 1))
				siblings->right = (node_header *)REAL_ADDRESS(parent->p[middle + 1].right[0]);
			break;
		} else if (ret > 0) {
			end_idx = middle - 1;
			if (start_idx > end_idx) {
				addr = &(parent->p[middle].left[0]);
				middle--;

				if ((middle) > 0)
					siblings->left = (node_header *)REAL_ADDRESS(parent->p[middle].left[0]);

				if ((middle + 1) < numberOfEntriesInNode)
					siblings->right = (node_header *)REAL_ADDRESS(parent->p[middle + 1].right[0]);
				break;
			}
		} else { /* ret < 0 */
			start_idx = middle + 1;
			if (start_idx > end_idx) {
				addr = &(parent->p[middle].right[0]);
				siblings->left = (node_header *)REAL_ADDRESS(parent->p[middle].left[0]);
				middle++;

				if ((middle) < numberOfEntriesInNode)
					siblings->right = (node_header *)REAL_ADDRESS(parent->p[middle].right[0]);
				break;
			}
		}
	}

	if (middle < 0) {
		addr = &(parent->p[0].left[0]);
		siblings->right = (node_header *)REAL_ADDRESS(parent->p[0].right[0]);
	} else if (middle >= numberOfEntriesInNode) {
		addr = &(parent->p[parent->header.numberOfEntriesInNode - 1].right[0]);
		siblings->left =
			(node_header *)REAL_ADDRESS(parent->p[parent->header.numberOfEntriesInNode - 1].left[0]);
	}
}

void __find_position_in_index(index_node *node, struct splice *key, rotate_data *siblings)
{
	void *addr = NULL;
	void *index_key_buf;
	int64_t ret;
	int32_t middle = 0;
	int32_t start_idx = 0;
	int32_t end_idx = node->header.numberOfEntriesInNode - 1;
	int32_t numberOfEntriesInNode = node->header.numberOfEntriesInNode;

	while (numberOfEntriesInNode > 0) {
		middle = (start_idx + end_idx) / 2;

		if (numberOfEntriesInNode > index_order || middle < 0 || middle >= numberOfEntriesInNode)
			return;

		addr = &(node->p[middle].pivot);
		index_key_buf = REAL_ADDRESS(*(uint64_t *)addr);
		ret = _tucana_key_cmp(index_key_buf, key, KV_FORMAT, KV_FORMAT);
		if (ret == 0) {
			addr = &(node->p[middle].right[0]);
			siblings->pos_left = middle;
			siblings->pos_right = middle + 1;
			break;
		} else if (ret > 0) {
			end_idx = middle - 1;
			if (start_idx > end_idx) {
				addr = &(node->p[middle].left[0]);

				if ((middle - 1) > 0)
					siblings->pos_left = middle - 1;

				siblings->pos_right = middle;
				middle--;

				break;
			}
		} else { /* ret < 0 */
			start_idx = middle + 1;
			if (start_idx > end_idx) {
				addr = &(node->p[middle].right[0]);
				siblings->pos_left = middle;

				if ((middle + 1) < numberOfEntriesInNode)
					siblings->pos_right = middle + 1;

				middle++;
				break;
			}
		}
	}

	if (middle < 0) {
		addr = &(node->p[0].left[0]);
		siblings->pos_right = 0;
	} else if (middle >= numberOfEntriesInNode) {
		addr = &(node->p[numberOfEntriesInNode - 1].right[0]);
		siblings->pos_left = numberOfEntriesInNode - 1;
	}

	return;
}

int8_t delete_key(db_handle *handle, void *key, uint32_t size)
{
	char __tmp[KV_MAX_SIZE];
	bt_delete_request req;
	int i;
	int8_t ret, final_ret = FAILED;

	if (size + sizeof(uint32_t) > KV_MAX_SIZE) {
		log_fatal("Key Buffer overflow");
		exit(EXIT_FAILURE);
	}

	req.key_buf = __tmp;
	SERIALIZE_KEY(req.key_buf, key, size);
	req.metadata.handle = handle;
	req.metadata.key_format = KV_FORMAT;

	for (i = 0; i < MAX_LEVELS; ++i) {
		RWLOCK_WRLOCK(&handle->db_desc->levels[i].guard_of_level.rx_lock);
		spin_loop(&handle->db_desc->levels[i].active_writers, 0);
		req.metadata.level_id = i;
		req.metadata.tree_id = 0;

		if (handle->db_desc->levels[i].root_w[handle->db_desc->levels[i].active_tree] == NULL) {
			if (handle->db_desc->levels[i].root_r[handle->db_desc->levels[i].active_tree] != NULL) {
				if (handle->db_desc->levels[i].root_r[handle->db_desc->levels[i].active_tree]->type ==
				    rootNode) {
					index_node *t = seg_get_index_node_header(
						handle->volume_desc, &handle->db_desc->levels[i], 0, NEW_ROOT);
					memcpy(t,
					       handle->db_desc->levels[i].root_r[handle->db_desc->levels[i].active_tree],
					       INDEX_NODE_SIZE);
					t->header.epoch = handle->volume_desc->mem_catalogue->epoch;
					handle->db_desc->levels[i].root_w[handle->db_desc->levels[i].active_tree] =
						(node_header *)t;
				} else {
					/*Tree too small consists only of 1 leafRootNode*/
					leaf_node *t = seg_get_leaf_node_header(
						handle->volume_desc, &handle->db_desc->levels[i], 0, COW_FOR_LEAF);
					memcpy(t,
					       handle->db_desc->levels[i].root_r[handle->db_desc->levels[i].active_tree],
					       LEAF_NODE_SIZE);
					t->header.epoch = handle->volume_desc->mem_catalogue->epoch;
					handle->db_desc->levels[i].root_w[handle->db_desc->levels[i].active_tree] =
						(node_header *)t;
				}
			} else {
				/*we are allocating a new tree*/

				/* log_info("Allocating new active tree %d for level id %d epoch is at %llu", active_tree, */
				/* 	 i, (LLU)mem_catalogue->epoch); */

				leaf_node *t = seg_get_leaf_node(handle->volume_desc, &handle->db_desc->levels[i], 0,
								 NEW_ROOT);

				t->header.type = leafRootNode;
				t->header.epoch = handle->volume_desc->mem_catalogue->epoch;
				handle->db_desc->levels[i].root_w[handle->db_desc->levels[i].active_tree] =
					(node_header *)t;
			}
		}

		ret = __delete_key(&req);
		if (ret == SUCCESS)
			final_ret = SUCCESS;

		RWLOCK_UNLOCK(&handle->db_desc->levels[i].guard_of_level.rx_lock);
		break;
	}

	return final_ret;
}

void transfer_node_from_right_neighbor(index_node *curr, index_node *right, index_node *parent, bt_delete_request *req,
				       int pos)
{
	void *key_addr = (void *)(MAPPED + parent->p[pos].pivot);
	void *pivot = &curr->p[curr->header.numberOfEntriesInNode].pivot;

	/* Take the pivot of the parent and place
       it as the last pivot in the current node.
       Also take the leftmost node from the right neighbor
       and place it as the last node in the current node.*/

	__update_index_pivot_in_place(req, (node_header *)curr, pivot, key_addr);
	curr->p[curr->header.numberOfEntriesInNode].right[0] = right->p[0].left[0];
	++curr->header.numberOfEntriesInNode;

	/* Update the pivot of the parent node
       with the leftmost pivot of the right neighbor. */
	key_addr = (void *)(MAPPED + right->p[0].pivot);
	pivot = &parent->p[pos].pivot;
	__update_index_pivot_in_place(req, (node_header *)parent, pivot, key_addr);

	/* Finally shift every entry of the right neighbor to the left
	   to delete the transferred node from it.*/
	memmove(&right->p[0], &right->p[1],
		(sizeof(index_entry) * (right->header.numberOfEntriesInNode - 1)) + sizeof(uint64_t));
	--right->header.numberOfEntriesInNode;
}

void transfer_node_from_left_neighbor(index_node *curr, index_node *left, index_node *parent, bt_delete_request *req,
				      int pos)
{
	assert(pos != -1);
	void *key_addr = (void *)(MAPPED + parent->p[pos].pivot);
	void *pivot;

	/* Take the leftmost pivot of the parent and place
       it as the last pivot in the current node.
       Also take the leftmost node from the right neighbor
       and place it as the last node in the current node.*/
	memmove(&curr->p[1], &curr->p[0],
		(sizeof(index_entry) * curr->header.numberOfEntriesInNode) + sizeof(uint64_t));
	pivot = &curr->p[0].pivot;

	__update_index_pivot_in_place(req, (node_header *)curr, pivot, key_addr);
	curr->p[0].left[0] = left->p[left->header.numberOfEntriesInNode - 1].right[0];
	++curr->header.numberOfEntriesInNode;

	/* Update the pivot of the parent node
       with the leftmost pivot of the right neighbor. */
	key_addr = (void *)(MAPPED + left->p[left->header.numberOfEntriesInNode - 1].pivot);
	pivot = &parent->p[pos].pivot;
	__update_index_pivot_in_place(req, (node_header *)parent, pivot, key_addr);

	/* finally remove the entry that was moved to the left.*/
	--left->header.numberOfEntriesInNode;
}

uint8_t transfer_node_to_neighbor_index_node(index_node *curr, index_node *parent, rotate_data *siblings,
					     bt_delete_request *req)
{
	index_node *left = (index_node *)siblings->left;
	index_node *right = (index_node *)siblings->right;
	uint64_t borrow_threshold = (index_order / 2) + 1;
	int8_t ret = 0;

	parent->header.v1++;

	if (right && (right->header.numberOfEntriesInNode >= borrow_threshold)) {
		ret = ROTATE_WITH_RIGHT;
		right->header.v1++;
		transfer_node_from_right_neighbor(curr, right, parent, req, siblings->pos_right);
		right->header.v2++;
	} else if (left && (left->header.numberOfEntriesInNode >= borrow_threshold)) {
		ret = ROTATE_WITH_LEFT;
		left->header.v1++;
		transfer_node_from_left_neighbor(curr, left, parent, req, siblings->pos_left);
		left->header.v2++;
	} else
		ret = ROTATE_IMPOSSIBLE_TRY_TO_MERGE;

	parent->header.v2++;
	return ret;
}

void merge_with_right_index_node(index_node *curr, index_node *right, index_node *parent, bt_delete_request *req,
				 int pos)
{
	void *key_addr = (void *)(MAPPED + parent->p[pos].pivot);
	void *pivot = &curr->p[curr->header.numberOfEntriesInNode].pivot;
	int i, j, right_num_entries = right->header.numberOfEntriesInNode;

	assert(((index_node *)(MAPPED + parent->p[pos].left[0])) == curr);
	/* Take the pivot of the parent node
       and place it as the rightmost pivot
       in the current node. */
	__update_index_pivot_in_place(req, (node_header *)curr, pivot, key_addr);
	++curr->header.numberOfEntriesInNode;
	/* Copy the nodes of the right neighbor to the current node. */
	for (i = curr->header.numberOfEntriesInNode, j = 0; j < right_num_entries; ++i, ++j) {
		curr->p[i].left[0] = right->p[j].left[0];
		pivot = &curr->p[i].pivot;
		key_addr = (void *)(MAPPED + right->p[j].pivot);
		__update_index_pivot_in_place(req, (node_header *)curr, pivot, key_addr);
	}

	curr->header.numberOfEntriesInNode += right->header.numberOfEntriesInNode;
	curr->p[curr->header.numberOfEntriesInNode - 1].right[0] =
		right->p[right->header.numberOfEntriesInNode - 1].right[0];

	if (parent->header.numberOfEntriesInNode == 1) {
		if (parent->header.type == rootNode) {
			curr->header.type = rootNode;
			//req->metadata.handle->db_desc->levels[req->metadata.level_id].root_w[req->metadata.active_tree] =
			req->metadata.handle->db_desc->levels[req->metadata.level_id].root_w[req->metadata.tree_id] =
				(node_header *)curr;
			return;
		}
		assert(0);
	}

	/* Shift every entry of the parent node to the left
       to remove the right node and free it.*/

	parent->p[pos].right[0] = parent->p[pos].left[0];
	memmove(&parent->p[pos], &parent->p[pos + 1],
		sizeof(index_entry) * (parent->header.numberOfEntriesInNode - (pos + 1)) + sizeof(uint64_t));

	assert(((index_node *)(MAPPED + parent->p[pos].left[0])) == curr);
	--parent->header.numberOfEntriesInNode;
	assert(parent->header.numberOfEntriesInNode >= 1);
}

void merge_with_left_index_node(index_node *curr, index_node *left, index_node *parent, bt_delete_request *req, int pos)
{
	void *key_addr = (void *)(MAPPED + parent->p[pos].pivot);
	void *pivot = &left->p[left->header.numberOfEntriesInNode].pivot;
	int i, j, curr_num_entries = curr->header.numberOfEntriesInNode;

	assert(((index_node *)(MAPPED + parent->p[pos + 1].left[0])) == curr);
	assert(((index_node *)(MAPPED + parent->p[pos].left[0])) == left);

	/* Take the pivot of the parent node
       and place it as the rightmost pivot
       in the left node. */
	__update_index_pivot_in_place(req, (node_header *)left, pivot, key_addr);
	++left->header.numberOfEntriesInNode;

	/* Copy the nodes of the current node to the left neighbor. */
	for (i = left->header.numberOfEntriesInNode, j = 0; j < curr_num_entries; ++i, ++j) {
		left->p[i].left[0] = curr->p[j].left[0];
		pivot = &left->p[i].pivot;
		key_addr = (void *)(MAPPED + curr->p[j].pivot);
		__update_index_pivot_in_place(req, (node_header *)left, pivot, key_addr);
	}
	left->header.numberOfEntriesInNode += curr->header.numberOfEntriesInNode;
	left->p[left->header.numberOfEntriesInNode - 1].right[0] =
		curr->p[curr->header.numberOfEntriesInNode - 1].right[0];

	/* Shift every entry of the parent node to the left
       to remove the right node and free it.*/
	if (parent->header.numberOfEntriesInNode == 1) {
		if (parent->header.type == rootNode) {
			left->header.type = rootNode;
			//req->metadata.handle->db_desc->levels[req->metadata.level_id].root_w[req->metadata.active_tree] =
			req->metadata.handle->db_desc->levels[req->metadata.level_id].root_w[req->metadata.tree_id] =
				(node_header *)left;
			return;
		}
		assert(0);
	}

	parent->p[pos + 1].left[0] = parent->p[pos].left[0];
	memmove(&parent->p[pos], &parent->p[pos + 1],
		sizeof(index_entry) * (parent->header.numberOfEntriesInNode - (pos + 1)) + sizeof(uint64_t));

	assert(((index_node *)(MAPPED + parent->p[pos].left[0])) == left);
	--parent->header.numberOfEntriesInNode;
	assert(parent->header.numberOfEntriesInNode >= 1);
}

int8_t merge_with_index_neighbor(index_node *curr, index_node *parent, rotate_data *siblings, bt_delete_request *req)
{
	index_node *left = (index_node *)siblings->left;
	index_node *right = (index_node *)siblings->right;
	uint64_t overflow_threshold = index_order, merge_with_left = 0, merge_with_right = 0;
	int8_t ret = 0;

	assert(left != curr);
	assert(right != curr);

	if (left)
		merge_with_left = curr->header.numberOfEntriesInNode + left->header.numberOfEntriesInNode;

	parent->header.v1++;
	if (right)
		merge_with_right = curr->header.numberOfEntriesInNode + right->header.numberOfEntriesInNode;

	if (merge_with_right && merge_with_right < overflow_threshold) {
		ret = MERGE_WITH_RIGHT;
		right->header.v1++;
		merge_with_right_index_node(curr, right, parent, req, siblings->pos_right);
		right->header.v2++;
	} else if (merge_with_left && merge_with_left < overflow_threshold) {
		ret = MERGE_WITH_LEFT;
		left->header.v1++;
		merge_with_left_index_node(curr, left, parent, req, siblings->pos_left);
		left->header.v2++;
	} else {
		ret = MERGE_IMPOSSIBLE_FATAL;
		log_fatal("We should either transfer a node or merge.");
		assert(0);
	}
	parent->header.v2++;

	return ret;
}

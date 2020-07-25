#pragma once
#include "btree.h"
#include "delete.h"
#include "segment_allocator.h"

enum bt_static_leaf_operation { STATIC_LEAF_INSERT = 0, STATIC_LEAF_FIND = 1 };

struct bt_static_leaf_structs {
	struct bt_leaf_entry_bitmap *bitmap;
	struct bt_static_leaf_slot_array *slot_array;
	struct bt_leaf_entry *kv_entries;
};

struct bsearch_result {
	int middle;
	enum bsearch_status status;
	enum bt_static_leaf_operation op;
};

void init_static_leaf_metadata(struct bt_static_leaf_node *leaf, level_descriptor *level);
int8_t insert_in_static_leaf(struct bt_static_leaf_node *leaf, bt_insert_req *req, level_descriptor *level);
void *find_key_in_static_leaf(const struct bt_static_leaf_node *leaf, level_descriptor *level, void *key,
			      uint32_t key_size);
void binary_search_static_leaf(struct bt_static_leaf_node const *leaf, level_descriptor *level, struct splice *key_buf,
			       struct bsearch_result *result);
int check_static_leaf_split(const struct bt_static_leaf_node *leaf, uint64_t node_capacity);
/* Rebalance Operations */
struct bt_rebalance_result split_static_leaf(struct bt_static_leaf_node *leaf, bt_insert_req *req);
void delete_key_value_from_static_leaf(struct bt_static_leaf_node *leaf, level_descriptor *level, uint32_t pos);
void underflow_borrow_from_left_static_leaf_neighbor(struct bt_static_leaf_node *curr, struct bt_static_leaf_node *left,
						     level_descriptor *level, bt_delete_request *req);
void underflow_borrow_from_right_static_leaf_neighbor(struct bt_static_leaf_node *curr,
						      struct bt_static_leaf_node *right, level_descriptor *level,
						      bt_delete_request *req);
void merge_with_right_static_leaf_neighbor(struct bt_static_leaf_node *curr, struct bt_static_leaf_node *right,
					   level_descriptor *level, bt_delete_request *req);
void merge_with_left_static_leaf_neighbor(struct bt_static_leaf_node *curr, struct bt_static_leaf_node *left,
					  level_descriptor *level, bt_delete_request *req);

#pragma once
#include "btree.h"

void *__find_key_addr_in_leaf(leaf_node *leaf, struct splice *key);

int8_t __delete_key(bt_delete_request *req);

void mark_deleted_key(db_handle *handle, void *deleted_key_addr);

int8_t merge_with_leaf_neighbor(leaf_node *leaf, rotate_data *siblings, bt_delete_request *req);

uint8_t delete_key_value_from_leaf(bt_delete_request *req, index_node *parent, leaf_node *leaf, struct splice *key);

void delete_key_value(leaf_node *leaf, int pos);

uint8_t transfer_node_to_neighbor_index_node(index_node *curr, index_node *parent, rotate_data *siblings,
					     bt_delete_request *req);

void __find_left_and_right_siblings(index_node *parent, void *key, rotate_data *siblings);

int __find_position_in_leaf(leaf_node *leaf, struct splice *key);

void __find_position_in_index(index_node *node, struct splice *key, rotate_data *siblings);

int8_t check_for_underflow_in_leaf(leaf_node *leaf, rotate_data *siblings, bt_delete_request *req);

int8_t merge_with_index_neighbor(index_node *curr, index_node *parent, rotate_data *siblings, bt_delete_request *req);

void *_index_node_binary_search_posret(index_node *node, void *key_buf, char query_key_format,
				       struct siblings_index_entries *neighbor);

void __update_index_pivot_in_place(db_handle *handle, node_header *node, void *node_index_addr, void *key_buf,
				   int level_id);

#pragma once
#include <stdint.h>
#include "btree.h"

enum bt_dynamic_leaf_operation { DYNAMIC_LEAF_INSERT = 0, DYNAMIC_LEAF_FIND = 1 };

enum kv_entry_location { UNKNOWN_CATEGORY = -1, KV_INPLACE = 0, KV_INLOG = 1 };

struct find_result {
	char *kv;
	enum kv_entry_location key_type;
};

struct dl_bsearch_result {
	int middle;
	enum bsearch_status status;
	enum bt_dynamic_leaf_operation op;
};

struct prefix {
	char *prefix;
	uint32_t len;
};

struct write_dynamic_leaf_args {
	struct bt_dynamic_leaf_node *leaf;
	char *dest;
	char *key_value_buf;
	uint64_t kv_dev_offt;
	uint32_t key_value_size;
	uint32_t middle;
	int level_id;
	int kv_format;
	enum log_category cat;
};

char *get_leaf_log_offset(const struct bt_dynamic_leaf_node *leaf, const uint32_t leaf_size);
void write_data_in_dynamic_leaf(struct write_dynamic_leaf_args *args);

char *fill_keybuf(char *key_loc, enum kv_entry_location key_type);
void fill_prefix(struct prefix *key, char *key_loc, enum kv_entry_location key_type);

int8_t insert_in_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, bt_insert_req *req, level_descriptor *level);
struct find_result find_key_in_dynamic_leaf(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size, void *key,
					    uint32_t key_size, int level_id);
void binary_search_dynamic_leaf(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size, bt_insert_req *req,
				struct dl_bsearch_result *result);

int check_dynamic_leaf_split(struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size, uint32_t kv_size, int level_id,
			     enum kv_entry_location key_type, enum log_category cat);

void print_slot_array(struct bt_dynamic_leaf_slot_array *slot_array, int i);

struct bt_rebalance_result split_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size,
					      bt_insert_req *req);

struct bt_rebalance_result special_split_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size,
						      bt_insert_req *req);

int reorganize_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size, bt_insert_req *req);
struct bt_rebalance_result blsm_split_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size,
						   bt_insert_req *req);
struct bt_dynamic_leaf_slot_array *get_slot_array_offset(const struct bt_dynamic_leaf_node *leaf);
char *get_kv_offset(const struct bt_dynamic_leaf_node *leaf, const uint32_t leaf_size, const uint32_t kv_offset);

typedef struct bt_rebalance_result split_dl(struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size, bt_insert_req *req);

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

#ifndef DYNAMIC_LEAF_H
#define DYNAMIC_LEAF_H
#include "btree.h"
#include "parallax/structures.h"
#include <stdint.h>

enum bt_dynamic_leaf_operation { DYNAMIC_LEAF_INSERT = 0, DYNAMIC_LEAF_FIND = 1 };

enum kv_entry_location { UNKNOWN_CATEGORY = -1, KV_INPLACE = 0, KV_INLOG = 1 };

struct find_result {
	char *kv;
	enum kv_entry_location key_type;
	enum kv_category kv_category;
	uint8_t tombstone : 1;
};

struct dl_bsearch_result {
	int middle;
	enum bsearch_status status;
	enum bt_dynamic_leaf_operation op;
	uint32_t tombstone : 1;
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
	uint32_t tombstone : 1;
	unsigned int level_id;
	unsigned int level_medium_inplace;
	int kv_format;
	enum kv_category cat;
};

struct split_level_leaf {
	struct bt_dynamic_leaf_node *leaf;
	uint32_t leaf_size;
	uint32_t kv_size;
	unsigned int level_id;
	unsigned int level_medium_inplace;
	enum kv_entry_location key_type;
	enum kv_category cat;
};

char *get_leaf_log_offset(const struct bt_dynamic_leaf_node *leaf, const uint32_t leaf_size);
void write_data_in_dynamic_leaf(struct write_dynamic_leaf_args *args);

char *fill_keybuf(char *key_loc, enum kv_entry_location key_type);
void fill_prefix(struct prefix *key, char *key_loc, enum kv_entry_location key_type);

int8_t insert_in_dynamic_leaf(struct bt_dynamic_leaf_node *leaf, bt_insert_req *req, level_descriptor *level);
struct find_result find_key_in_dynamic_leaf(const struct bt_dynamic_leaf_node *leaf, db_descriptor *db_desc, void *key,
					    uint32_t key_size, int level_id);
void binary_search_dynamic_leaf(const struct bt_dynamic_leaf_node *leaf, uint32_t leaf_size, bt_insert_req *req,
				struct dl_bsearch_result *result);

int is_dynamic_leaf_full(struct split_level_leaf split_metadata);

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

enum kv_entry_location get_kv_format(enum kv_category kv_category);
#endif

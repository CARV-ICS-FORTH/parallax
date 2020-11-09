#include "btree.h"
#include "delete.h"
#include "segment_allocator.h"

enum bsearch_status { INSERT = 0, FOUND = 1, ERROR = 2 };

struct bsearch_result {
	int middle;
	enum bsearch_status status;
};

#define LESS_THAN_ZERO -1
#define GREATER_THAN_ZERO 1
#define EQUAL_TO_ZERO 0

struct bt_static_leaf_structs {
	struct bt_leaf_entry_bitmap *bitmap;
	bt_leaf_slot_array *slot_array;
	bt_leaf_entry *kv_entries;
};

void init_static_leaf_metadata(struct bt_static_leaf_node *leaf, level_descriptor *level);
int8_t insert_in_static_leaf(struct bt_static_leaf_node *leaf, bt_insert_req *req, level_descriptor *level);
void *find_key_in_static_leaf(const struct bt_static_leaf_node *leaf, level_descriptor *level, void *key,
			      uint32_t key_size);
struct bt_rebalance_result split_static_leaf(struct bt_static_leaf_node *leaf, bt_insert_req *req);

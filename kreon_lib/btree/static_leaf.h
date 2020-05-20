#include "btree.h"
enum bsearch_status { INSERT, UPDATE, ERROR };

struct bsearch_result {
	int middle;
	enum bsearch_status status;
};

#define LESS_THAN_ZERO -1
#define GREATER_THAN_ZERO 1
#define EQUAL_TO_ZERO 0

struct bt_static_leaf_structs {
	bt_leaf_bitmap *bitmap;
	bt_leaf_slot_array *slot_array;
	bt_leaf_entry *kv_entries;
};

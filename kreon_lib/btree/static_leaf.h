#include "btree.h"
/* The FOUND status value should always match the UPDATE value.*/
enum bsearch_status { INSERT = 0, UPDATE = 1, ERROR = 2 };
enum bsearch_find_status {FOUND = 1, NOT_FOUND = 2};

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

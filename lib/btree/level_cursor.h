#ifndef LEVEL_CURSOR_H
#define LEVEL_CURSOR_H
#include "dynamic_leaf.h"
#include "kv_pairs.h"
struct comp_parallax_key {
	enum kv_category kv_category;
	enum kv_entry_location kv_type;
	uint8_t tombstone;
	union {
		struct kv_seperation_splice *kv_inlog;
		struct kv_splice *kv_in_place;
	};
};
#endif

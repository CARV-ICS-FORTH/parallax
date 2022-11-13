#ifndef LEVEL_CURSOR_H
#define LEVEL_CURSOR_H
#include "dynamic_leaf.h"
struct comp_parallax_key {
	union {
		struct kv_seperation_splice *kv_inlog;
		char *kv_inplace;
	};
	struct kv_seperation_splice kv_sep;
	enum kv_category kv_category;
	enum kv_entry_location kv_type;
	uint8_t tombstone : 1;
};
#endif

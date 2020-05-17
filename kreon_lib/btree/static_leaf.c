#include <stdint.h>
#include <limits.h>
#include "btree.h"
#include "conf.h"

extern uint32_t leaf_size_per_level[MAX_LEVELS];
extern level_offsets_todata leaf_node_offsets[MAX_LEVELS];

void init_static_leaf_metadata(bt_static_leaf_node *leaf, uint8_t level_id)
{
	char *leaf_base_address = (char *)leaf;
	char *bitmap_address = leaf_base_address + leaf_node_offsets[level_id].bitmap_offset;
	char *slot_array_address = leaf_base_address + leaf_node_offsets[level_id].slot_array_offset;
	char *kv_entries_address = leaf_base_address + leaf_node_offsets[level_id].kv_entries_offset;
	memset(bitmap_address, UCHAR_MAX, sizeof(bt_leaf_bitmap) * leaf_node_offsets[level_id].bitmap_entries);
	memset(slot_array_address, 0, sizeof(bt_leaf_slot_array) * leaf_node_offsets[level_id].slot_array_entries);
	memset(kv_entries_address, 0, sizeof(bt_leaf_entry) * leaf_node_offsets[level_id].kv_entries);
}

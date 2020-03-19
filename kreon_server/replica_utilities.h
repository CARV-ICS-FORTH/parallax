#pragma once
#include <stdint.h>
#include "server_regions.h"

#include "../kreon_lib/btree/btree.h"
int flush_replica_log_buffer(db_handle *handle, segment_header *master_log_segment, void *buffer, uint64_t end_of_log,
			     uint64_t bytes_to_pad, uint64_t segment_id);

void _calculate_btree_index_nodes(_tucana_region_S *region, uint64_t num_of_keys);

void append_entry_to_leaf_node(_tucana_region_S *region, void *pointer_to_kv_pair, void *prefix, int32_t tree_id);


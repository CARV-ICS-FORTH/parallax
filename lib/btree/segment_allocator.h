#pragma once
#include "../allocator/volume_manager.h"
#include "btree.h"
#include <stdint.h>

/*functions for index nodes*/
index_node *seg_get_index_node(volume_descriptor *volume_desc, level_descriptor *level_desc, uint8_t tree_id,
			       char reason);

index_node *seg_get_index_node_header(volume_descriptor *volume_desc, level_descriptor *level_desc, uint8_t tree_id);

IN_log_header *seg_get_IN_log_block(volume_descriptor *volume_desc, level_descriptor *level_desc, uint8_t tree_id);

void seg_free_index_node_header(volume_descriptor *volume_desc, level_descriptor *level_desc, uint8_t tree_id,
				node_header *node);

void seg_free_index_node(volume_descriptor *volume_desc, level_descriptor *level_desc, uint8_t tree_id,
			 index_node *inode);

/*function for leaf nodes*/
leaf_node *seg_get_leaf_node(volume_descriptor *volume_desc, level_descriptor *level_desc, uint8_t tree_id);

leaf_node *seg_get_leaf_node_header(volume_descriptor *volume_desc, level_descriptor *level_desc, uint8_t tree_id);

void seg_free_leaf_node(volume_descriptor *volume_desc, level_descriptor *level_desc, uint8_t tree_id, leaf_node *leaf);

/* struct bt_static_leaf_node *seg_get_static_leaf_node(volume_descriptor *volume_desc, level_descriptor *level_desc); */

/* struct bt_static_leaf_node *seg_get_static_leaf_node(volume_descriptor *volume_desc, level_descriptor *level_desc, */
/* 						     char reason); */

struct bt_dynamic_leaf_node *seg_get_dynamic_leaf_node(volume_descriptor *volume_desc, level_descriptor *level_desc,
						       uint8_t tree_id);
/*log related*/
segment_header *seg_get_raw_log_segment(volume_descriptor *volume_desc);
void free_raw_segment(volume_descriptor *volume_desc, segment_header *segment);

struct segment_header *get_segment_for_explicit_IO(volume_descriptor *volume_desc, level_descriptor *level_desc,
						   uint8_t tree_id);

void *get_space_for_system(volume_descriptor *volume_desc, uint32_t size, int lock);

void seg_free_level(db_handle *handle, uint8_t level_id, uint8_t tree_id);

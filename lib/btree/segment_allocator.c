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

#include "segment_allocator.h"
#include "../allocator/device_structures.h"
#include "../allocator/log_structures.h"
#include "../allocator/redo_undo_log.h"
#include "../allocator/volume_manager.h"
#include "conf.h"
#include <assert.h>
#include <log.h>
#include <signal.h>
#include <stdlib.h>

extern uint64_t MAPPED;

struct link_segments_metadata {
	level_descriptor *level_desc;
	segment_header *new_segment;
	uint64_t segment_id;
	uint64_t available_space;
	uint64_t tree_id;
	int in_mem;
};

static uint64_t seg_allocate_segment(struct db_descriptor *db_desc, uint64_t txn_id)
{
	struct rul_log_entry log_entry;
	log_entry.dev_offt = mem_allocate(db_desc->db_volume, SEGMENT_SIZE);
	log_entry.txn_id = txn_id;
	log_entry.op_type = RUL_ALLOCATE;
	log_entry.size = SEGMENT_SIZE;
	rul_add_entry_in_txn_buf(db_desc, &log_entry);
	return log_entry.dev_offt;
}

static void seg_free_segment(struct db_descriptor *db_desc, uint64_t txn_id, uint64_t seg_offt)
{
	struct rul_log_entry log_entry;
	log_entry.dev_offt = seg_offt;
	log_entry.txn_id = txn_id;
	log_entry.op_type = RUL_FREE;
	log_entry.size = SEGMENT_SIZE;
	rul_add_entry_in_txn_buf(db_desc, &log_entry);
}

static uint64_t link_memory_segments(struct link_segments_metadata *req)
{
	level_descriptor *level_desc = req->level_desc;
	segment_header *new_segment = req->new_segment;
	segment_header *prev_segment;
	uint64_t available_space = req->available_space;
	uint64_t segment_id = req->segment_id;
	uint8_t tree_id = req->tree_id;

	(void)prev_segment;
	if (req->level_desc->offset[req->tree_id] != 0) {
		/*chain segments*/
		prev_segment = level_desc->last_segment[tree_id];
		new_segment->next_segment = NULL;
		new_segment->prev_segment = (segment_header *)ABSOLUTE_ADDRESS(level_desc->last_segment[tree_id]);
		level_desc->last_segment[tree_id]->next_segment = (segment_header *)ABSOLUTE_ADDRESS(new_segment);
		prev_segment = level_desc->last_segment[tree_id];
		level_desc->last_segment[tree_id] = new_segment;
		level_desc->last_segment[tree_id]->segment_id = segment_id + 1;
		level_desc->offset[tree_id] += (available_space + sizeof(segment_header));
	} else {
		/*special case for the first segment for this level*/
		new_segment->next_segment = NULL;
		new_segment->prev_segment = NULL;
		level_desc->first_segment[tree_id] = new_segment;
		level_desc->last_segment[tree_id] = new_segment;
		level_desc->last_segment[tree_id]->segment_id = 1;
		level_desc->offset[tree_id] = sizeof(segment_header);
		prev_segment = NULL;
	}

	return level_desc->offset[tree_id] % SEGMENT_SIZE;
}

static void set_link_segments_metadata(struct link_segments_metadata *req, segment_header *new_segment,
				       uint64_t segment_id, uint64_t available_space)
{
	req->new_segment = new_segment;
	req->segment_id = segment_id;
	req->available_space = available_space;
}

static void *get_space(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id, uint32_t size)
{
	struct level_descriptor *level_desc = &db_desc->levels[level_id];

	struct link_segments_metadata req = { .level_desc = level_desc, .tree_id = tree_id };
	segment_header *new_segment = NULL;
	node_header *node = NULL;
	uint32_t available_space;
	uint64_t offset_in_segment = 0;
	uint64_t segment_id;

	MUTEX_LOCK(&level_desc->level_allocation_lock);

	/*check if we have enough space to satisfy the request*/
	if (level_desc->offset[tree_id] % SEGMENT_SIZE == 0) {
		available_space = 0;
		segment_id = 0;
	} else {
		available_space = SEGMENT_SIZE - (level_desc->offset[tree_id] % SEGMENT_SIZE);
		offset_in_segment = level_desc->offset[tree_id] % SEGMENT_SIZE;
		segment_id = level_desc->last_segment[tree_id]->segment_id;
	}
	if (available_space < size) {
		//Characterize remaining empty space if any as paddedSpace
		if (available_space > 0) {
			int *pad = (int *)((uint64_t)level_desc->last_segment[tree_id] +
					   (level_desc->offset[tree_id] % SEGMENT_SIZE));
			*pad = paddedSpace;
		}
		/*we need to go to the actual allocator to get space*/
		if (level_desc->level_id != 0) {
			new_segment = (segment_header *)REAL_ADDRESS(
				seg_allocate_segment(db_desc, db_desc->levels[level_id].allocation_txn_id[tree_id]));
			req.in_mem = 0;
		} else {
			if (posix_memalign((void **)&new_segment, ALIGNMENT, SEGMENT_SIZE) != 0) {
				log_fatal("MEMALIGN FAILED");
				exit(EXIT_FAILURE);
			}
			req.in_mem = 1;
		}

		assert(new_segment);
		set_link_segments_metadata(&req, new_segment, segment_id, available_space);
		offset_in_segment = link_memory_segments(&req);
	}

	node = (node_header *)((uint64_t)level_desc->last_segment[tree_id] + offset_in_segment);
	assert(node);
	level_desc->offset[tree_id] += size;
	MUTEX_UNLOCK(&level_desc->level_allocation_lock);
	return node;
}

/*
 * We use this function to allocate space only for the lsm levels during compaction
*/
struct segment_header *get_segment_for_lsm_level_IO(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	struct level_descriptor *level_desc = &db_desc->levels[level_id];

	if (level_desc->level_id == 0) {
		log_warn("Not allowed this kind of allocations for L0!");
		return NULL;
	}
	uint64_t seg_offt = seg_allocate_segment(db_desc, db_desc->levels[level_id].allocation_txn_id[tree_id]);
	//log_info("Allocated level segment %llu", seg_offt);
	struct segment_header *new_segment = (struct segment_header *)REAL_ADDRESS(seg_offt);
	if (!new_segment) {
		log_fatal("Failed to allocate space for new segment level");
		exit(EXIT_FAILURE);
	}

	if (level_desc->offset[tree_id])
		level_desc->offset[tree_id] += SEGMENT_SIZE;
	else {
		level_desc->offset[tree_id] = SEGMENT_SIZE;
		level_desc->first_segment[tree_id] = new_segment;
		level_desc->last_segment[tree_id] = NULL;
	}

	return new_segment;
}

index_node *seg_get_index_node(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id, char reason)
{
	index_node *ptr;
	IN_log_header *bh;

	ptr = (index_node *)get_space(db_desc, level_id, tree_id, INDEX_NODE_SIZE + KEY_BLOCK_SIZE);

	if (reason == NEW_ROOT)
		ptr->header.type = rootNode;
	else
		ptr->header.type = internalNode;

	ptr->header.num_entries = 0;
	ptr->header.fragmentation = 0;

	/*private key log for index nodes*/
	bh = (IN_log_header *)((uint64_t)ptr + INDEX_NODE_SIZE);
	bh->next = (void *)NULL;
	bh->type = keyBlockHeader;
	ptr->header.first_IN_log_header = (IN_log_header *)ABSOLUTE_ADDRESS(bh);
	ptr->header.last_IN_log_header = ptr->header.first_IN_log_header;
	ptr->header.key_log_size = sizeof(IN_log_header);

	return ptr;
}

index_node *seg_get_index_node_header(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	return (index_node *)get_space(db_desc, level_id, tree_id, INDEX_NODE_SIZE);
}

IN_log_header *seg_get_IN_log_block(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	return (IN_log_header *)get_space(db_desc, level_id, tree_id, KEY_BLOCK_SIZE);
}

void seg_free_index_node_header(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id, node_header *node)
{
	return;
	//leave for future use
	(void)db_desc;
	(void)level_id;
	(void)tree_id;
	(void)node;
	//free_block(volume_desc, node, INDEX_NODE_SIZE);
}

void seg_free_index_node(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id, index_node *inode)
{
	//leave for future use
	(void)db_desc;
	(void)level_id;
	(void)tree_id;
	(void)inode;
#if 0
	struct volume_descriptor *volume_desc = db_desc->my_volume;


	if (inode->header.type == leafNode || inode->header.type == leafRootNode) {
		log_fatal("Faulty type of node!");
		exit(EXIT_FAILURE);
	}

	/*for IN, BIN, root nodes free the key log as well*/
	if (inode->header.first_IN_log_header == NULL) {
		log_fatal("NULL log for index?");
		exit(EXIT_FAILURE);
	}
	IN_log_header *curr = (IN_log_header *)REAL_ADDRESS(inode->header.first_IN_log_header);
	IN_log_header *last = (IN_log_header *)REAL_ADDRESS(inode->header.last_IN_log_header);
	IN_log_header *to_free;
	while ((uint64_t)curr != (uint64_t)last) {
		to_free = curr;
		curr = (IN_log_header *)REAL_ADDRESS(curr->next);
		free_block(volume_desc, to_free, KEY_BLOCK_SIZE);
	}
	free_block(volume_desc, last, KEY_BLOCK_SIZE);
	/*finally node_header*/
	free_block(volume_desc, inode, INDEX_NODE_SIZE);
#endif
}

leaf_node *seg_get_leaf_node(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	struct level_descriptor *level_desc = &db_desc->levels[level_id];
	leaf_node *leaf = (leaf_node *)get_space(db_desc, level_id, tree_id, level_desc->leaf_size);

	leaf->header.type = leafNode;
	leaf->header.num_entries = 0;
	leaf->header.fragmentation = 0;

	leaf->header.first_IN_log_header = NULL; /*unused field in leaves*/
	leaf->header.last_IN_log_header = NULL; /*unused field in leaves*/
	leaf->header.key_log_size = 0; /*unused also*/
	leaf->header.height = 0;

	return leaf;
}

struct bt_dynamic_leaf_node *init_leaf_node(struct bt_dynamic_leaf_node *leaf)
{
	leaf->header.type = leafNode;
	leaf->header.num_entries = 0;
	leaf->header.fragmentation = 0;

	leaf->header.first_IN_log_header = NULL; /*unused field in leaves*/
	leaf->header.last_IN_log_header = NULL; /*unused field in leaves*/
	leaf->header.leaf_log_size = 0;
	leaf->header.height = 0;
	return leaf;
}

struct bt_dynamic_leaf_node *seg_get_dynamic_leaf_node(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	struct level_descriptor *level_desc = &db_desc->levels[level_id];
	return init_leaf_node(get_space(db_desc, level_id, tree_id, level_desc->leaf_size));
}

leaf_node *seg_get_leaf_node_header(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	struct level_descriptor *level_desc = &db_desc->levels[level_id];
	return (leaf_node *)init_leaf_node(get_space(db_desc, level_id, tree_id, level_desc->leaf_size));
}

void seg_free_leaf_node(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id, leaf_node *leaf)
{
	//leave for future use
	(void)db_desc;
	(void)level_id;
	(void)tree_id;
	(void)leaf;
#if 0
	struct level_descriptor *level_desc = &db_desc->levels[level_id];
	free_block(db_desc->my_volume, leaf, level_desc->leaf_size);
#endif
}

segment_header *seg_get_raw_log_segment(struct db_descriptor *db_desc, enum log_type log_type, uint8_t level_id,
					uint8_t tree_id)
{
	enum rul_op_type op_type;
	switch (log_type) {
	case BIG_LOG:
		op_type = RUL_LARGE_LOG_ALLOCATE;
		break;
	case MEDIUM_LOG:
		op_type = RUL_MEDIUM_LOG_ALLOCATE;
		break;
	case SMALL_LOG:
		op_type = RUL_SMALL_LOG_ALLOCATE;
		break;
	default:
		log_fatal("Unknown log type");
		exit(EXIT_FAILURE);
	}
	struct rul_log_entry log_entry;
	log_entry.dev_offt = mem_allocate(db_desc->db_volume, SEGMENT_SIZE);
	log_entry.txn_id = db_desc->levels[level_id].allocation_txn_id[tree_id];
	log_entry.op_type = op_type;
	log_entry.size = SEGMENT_SIZE;
	rul_add_entry_in_txn_buf(db_desc, &log_entry);
	segment_header *sg = (segment_header *)REAL_ADDRESS(log_entry.dev_offt);
	return sg;
}

/*deprecated*/
void *get_space_for_system(volume_descriptor *volume_desc, uint32_t size, int lock)
{
	void *addr;
	if (size % 4096 != 0) {
		log_fatal("faulty size %lu not a multiple of 4KB", size);
		raise(SIGINT);
		exit(EXIT_FAILURE);
	}

	segment_header *new_segment = NULL;
	segment_header *first_sys_segment;
	segment_header *last_sys_segment;
	uint64_t available_space;
	uint64_t offset_in_segment = 0;
	uint64_t segment_id;

	if (lock)
		MUTEX_LOCK(&volume_desc->bitmap_lock);

	first_sys_segment = (segment_header *)REAL_ADDRESS(volume_desc->mem_catalogue->first_system_segment);
	last_sys_segment = (segment_header *)REAL_ADDRESS(volume_desc->mem_catalogue->last_system_segment);
	/*check if we have enough space to satisfy the request*/

	if (volume_desc->mem_catalogue->offset == 0) {
		available_space = 0;
		segment_id = 0;
	} else if (volume_desc->mem_catalogue->offset % SEGMENT_SIZE != 0) {
		offset_in_segment = volume_desc->mem_catalogue->offset % SEGMENT_SIZE;
		available_space = SEGMENT_SIZE - offset_in_segment;
		segment_id = last_sys_segment->segment_id;
	} else {
		available_space = 0;
		segment_id = last_sys_segment->segment_id;
	}
	//log_info("available %llu volume offset %llu", available_space, volume_desc->mem_catalogue->offset);
	if (available_space < size) {
		/*we need to go to the actual allocator to get space*/

		new_segment = (segment_header *)REAL_ADDRESS(mem_allocate(volume_desc, SEGMENT_SIZE));

		if (segment_id) {
			/*chain segments*/
			new_segment->next_segment = NULL;
			new_segment->prev_segment = (segment_header *)ABSOLUTE_ADDRESS(last_sys_segment);
			last_sys_segment->next_segment = (segment_header *)ABSOLUTE_ADDRESS(new_segment);
			last_sys_segment = new_segment;
			last_sys_segment->segment_id = segment_id + 1;
			volume_desc->mem_catalogue->offset += (available_space + sizeof(segment_header));
		} else {
			/*special case for the first segment for this level*/
			new_segment->next_segment = NULL;
			new_segment->prev_segment = NULL;
			first_sys_segment = new_segment;
			last_sys_segment = new_segment;
			last_sys_segment->segment_id = 1;
			volume_desc->mem_catalogue->offset = sizeof(segment_header);
		}
		offset_in_segment = volume_desc->mem_catalogue->offset % SEGMENT_SIZE;
		/*serialize the updated info of first, last system segments*/
		volume_desc->mem_catalogue->first_system_segment = ABSOLUTE_ADDRESS(first_sys_segment);
		volume_desc->mem_catalogue->last_system_segment = ABSOLUTE_ADDRESS(last_sys_segment);
	}

	addr = (void *)(uint64_t)last_sys_segment + offset_in_segment;
	volume_desc->mem_catalogue->offset += size;

	if (lock)
		MUTEX_UNLOCK(&volume_desc->bitmap_lock);
	return addr;
}

uint64_t seg_free_level(struct db_descriptor *db_desc, uint64_t txn_id, uint8_t level_id, uint8_t tree_id)
{
	segment_header *curr_segment = db_desc->levels[level_id].first_segment[tree_id];
	segment_header *temp_segment;
	uint64_t space_freed = 0;

	if (!curr_segment) {
		log_warn("Cannot free an empty level");
		return 0;
	}

	log_info("Freeing up level %u for db %s", level_id, db_desc->db_superblock->db_name);

	if (level_id != 0) {
		while (1) {
			//log_info("Freeing level segment %llu", ABSOLUTE_ADDRESS(curr_segment));
			seg_free_segment(db_desc, txn_id, ABSOLUTE_ADDRESS(curr_segment));
			space_freed += SEGMENT_SIZE;
			if (NULL == curr_segment->next_segment)
				break;
			curr_segment = REAL_ADDRESS(curr_segment->next_segment);
		}
		assert(space_freed == db_desc->levels[level_id].offset[0]);

	} else {
		/*Finally L0 index in memory*/
		curr_segment = db_desc->levels[level_id].first_segment[tree_id];

		if (!curr_segment) {
			log_warn("Nothing to do for level[%u][%u] because it is empty", level_id, tree_id);
			return 0;
		}

		temp_segment = REAL_ADDRESS(curr_segment->next_segment);
		int flag = 0;
		/* log_info("Level id to free %d %d", level_id,curr_segment->in_mem); */

		if (curr_segment->next_segment) {
			while (curr_segment != NULL) {
				/* log_info("COUNT  %d %llu", curr_segment->segment_id, curr_segment->next_segment); */
				free(curr_segment);
				curr_segment = temp_segment;

				if (temp_segment->next_segment == NULL) {
					flag = 1;
					break;
				}
				temp_segment = REAL_ADDRESS(temp_segment->next_segment);
				space_freed += SEGMENT_SIZE;
			}
		} else
			free(curr_segment);

		if (flag) {
			/* log_info("COUNT %d %llu", curr_segment->segment_id, curr_segment->next_segment); */
			free(temp_segment);
		}
	}
	return space_freed;
}

void seg_zero_level(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	db_desc->levels[level_id].level_size[tree_id] = 0;
	db_desc->levels[level_id].first_segment[tree_id] = NULL;
	db_desc->levels[level_id].last_segment[tree_id] = NULL;
	db_desc->levels[level_id].offset[tree_id] = 0;
	db_desc->levels[level_id].root_r[tree_id] = NULL;
	db_desc->levels[level_id].root_w[tree_id] = NULL;
}

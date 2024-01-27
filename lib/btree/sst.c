#include "sst.h"
#include "../allocator/redo_undo_log.h"
#include "../allocator/volume_manager.h"
#include "../common/common.h"
#include "btree.h"
#include "btree_node.h"
#include "conf.h"
#include "device_level.h"
#include "index_node.h"
#include "key_splice.h"
#include "kv_pairs.h"
#include <assert.h>
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define SST_METADATA_SIZE 4096UL

struct sst_meta {
	uint64_t root_offt;
	uint64_t sst_dev_offt;
	uint32_t sst_size;
	uint16_t first_guard_size;
	uint16_t last_guard_size;
	uint8_t level_id;
} __attribute__((packed));

struct sst {
	struct node_header *last_node[MAX_HEIGHT];
	db_handle *db_handle;
	char *IO_buffer;
	struct sst_meta *meta;
	struct medium_log_LRU_cache *medium_log_LRU_cache;
	struct level_leaf_api *leaf_api;
	struct level_index_api *index_api;
	uint32_t last_leaf_offt;
	uint32_t last_index_offt;
	uint64_t txn_id;
	uint32_t tree_id;
};

inline uint32_t sst_meta_get_level_id(struct sst_meta *sst)
{
	return sst->level_id;
}

uint32_t sst_meta_get_first_leaf_relative_offt(struct sst_meta *sst)
{
	(void)sst;
	return SST_METADATA_SIZE;
}

static uint64_t sst_allocate_space(struct sst *sst)
{
	struct rul_log_entry log_entry = { .dev_offt = mem_allocate(sst->db_handle->db_desc->db_volume, SST_SIZE),
					   .txn_id = sst->txn_id,
					   .op_type = RUL_ALLOCATE_SST,
					   .size = SST_SIZE };
	rul_add_entry_in_txn_buf(sst->db_handle->db_desc, &log_entry);
	return log_entry.dev_offt;
}

bool sst_meta_get_next_relative_leaf_offt(uint32_t *offt, char *sst_buffer)
{
	*offt += LEAF_NODE_SIZE;
	struct node_header *node = (struct node_header *)&sst_buffer[*offt];
	return node->type == leafNode || node->type == leafRootNode ? true : false;
}

inline uint64_t sst_meta_get_dev_offt(struct sst_meta *sst)
{
	return sst->sst_dev_offt;
}

uint64_t sst_meta_get_root_offt(struct sst_meta *sst)
{
	return sst->root_offt;
}

inline uint64_t sst_meta_get_first_leaf_offt(struct sst_meta *sst)
{
	return sst->sst_dev_offt + SST_METADATA_SIZE;
}

struct key_splice *sst_meta_get_first_guard(struct sst_meta *sst)
{
	if (0 == sst->first_guard_size) {
		log_debug("First guard has not been set, what are you trying to read?");
		BUG_ON();
		_exit(EXIT_FAILURE);
		return NULL;
	}
	char *sst_meta_buf = (char *)sst;
	struct key_splice *first_splice = (struct key_splice *)&sst_meta_buf[sizeof(struct sst_meta)];
	return first_splice;
}

struct key_splice *sst_meta_get_last_guard(struct sst_meta *sst)
{
	if (!sst->last_guard_size)
		return NULL;
	char *sst_meta_buf = (char *)sst;
	struct key_splice *first_splice = sst_meta_get_first_guard(sst);
	return (struct key_splice *)&sst_meta_buf[sizeof(struct sst_meta) + key_splice_get_metadata_size() +
						  key_splice_get_key_size(first_splice)];
}

size_t sst_meta_get_size(struct sst_meta *sst)
{
	return sizeof(struct sst_meta) + sst->first_guard_size + sst->last_guard_size;
}

static bool sst_set_first_guard(struct sst *sst, struct kv_splice_base *kv_pair)
{
	if (sst->meta->first_guard_size) {
		log_debug("First guard has been set, what are you doing?");
		return false;
	}
	sst->meta->first_guard_size = key_splice_get_metadata_size() + kv_splice_base_get_key_size(kv_pair);
	// Extend the structure using realloc
	uint32_t new_size = sizeof(struct sst_meta) + sst->meta->first_guard_size;
	struct sst_meta *extended_meta = (struct sst_meta *)realloc(sst->meta, new_size);

	if (extended_meta == NULL) {
		log_fatal("Memory reallocation failed");
		free(extended_meta);
		_exit(EXIT_FAILURE);
	}
	sst->meta = extended_meta;
	char *meta_buf = (char *)sst->meta;
	bool malloced = false;
	key_splice_create(kv_splice_base_get_key_buf(kv_pair), kv_splice_base_get_key_size(kv_pair),
			  &meta_buf[sizeof(struct sst_meta)], sst->meta->first_guard_size, &malloced);
	assert(malloced == false);
	return true;
}

static bool sst_set_last_guard(struct sst *sst, struct kv_splice_base *kv_pair)
{
	if (!sst->meta->first_guard_size) {
		log_debug("First guard has not been set, what are you doing?");
		return false;
	}

	if (sst->meta->last_guard_size) {
		log_debug("Last guard has been set, what are you doing?");
		return false;
	}

	sst->meta->last_guard_size = key_splice_get_metadata_size() + kv_splice_base_get_key_size(kv_pair);
	// Extend the structure using realloc
	uint32_t new_size = sizeof(struct sst_meta) + sst->meta->first_guard_size + sst->meta->last_guard_size;
	struct sst_meta *extended_meta = (struct sst_meta *)realloc(sst->meta, new_size);

	if (extended_meta == NULL) {
		log_fatal("Memory reallocation failed");
		free(extended_meta);
		_exit(EXIT_FAILURE);
	}
	sst->meta = extended_meta;
	char *meta_buf = (char *)sst->meta;
	bool malloced = false;
	key_splice_create(kv_splice_base_get_key_buf(kv_pair), kv_splice_base_get_key_size(kv_pair),
			  &meta_buf[sizeof(struct sst_meta) + sst->meta->first_guard_size], sst->meta->last_guard_size,
			  &malloced);
	assert(malloced == false);
	return true;
}

static inline uint32_t sst_get_remaining_space(struct sst *sst)
{
	return sst->last_index_offt - sst->last_leaf_offt;
}

static char *sst_get_space(struct sst *sst, size_t size, bool is_leaf)
{
	assert(size == LEAF_NODE_SIZE || size == INDEX_NODE_SIZE);

	uint32_t remaining_space = sst_get_remaining_space(sst);

	if (remaining_space < size)
		return NULL;

	if (is_leaf) {
		// log_debug("Returing leaf offt: %u",sst->meta->last_leaf_offt);
		char *node = &sst->IO_buffer[sst->last_leaf_offt];
		memset(node, 0x00, size);
		sst->last_leaf_offt += size;
		return node;
	}

	sst->last_index_offt -= size;
	// log_debug("Allocating an index node at offt: %u of size: %lu", sst->meta->last_index_offt, size);
	return &sst->IO_buffer[sst->last_index_offt];
}

struct sst *sst_create(uint32_t sst_size, uint64_t txn_id, db_handle *handle, uint32_t level_id)
{
	struct sst *sst = calloc(1UL, sizeof(struct sst));
	sst->meta = calloc(1UL, sizeof(struct sst_meta));

	// log_debug("Allocating an I/O sst buffer of size: %u",sst_size);
	if (posix_memalign((void **)&sst->IO_buffer, ALIGNMENT, sst_size) != 0) {
		log_fatal("Posix memalign failed");
		perror("Reason: ");
		_exit(EXIT_FAILURE);
	}
	memset(sst->IO_buffer, 0x00, sst_size);
	sst->db_handle = handle;
	sst->txn_id = txn_id;

	sst->meta->level_id = level_id;
	sst->last_index_offt = sst_size;
	sst->last_leaf_offt = SST_METADATA_SIZE;
	sst->meta->level_id = level_id;
	sst->meta->sst_dev_offt = sst_allocate_space(sst);
	sst->meta->sst_size = sst_size;

	sst->leaf_api = level_get_leaf_api(handle->db_desc->dev_levels[level_id]);
	sst->index_api = level_get_index_api(handle->db_desc->dev_levels[level_id]);
	for (int i = 0; i < MAX_HEIGHT; i++) {
		sst->last_node[i] = (struct node_header *)(i == 0 ? sst_get_space(sst, LEAF_NODE_SIZE, true) :
								    sst_get_space(sst, INDEX_NODE_SIZE, false));

		if (i == 0)
			(*sst->leaf_api->leaf_init)((struct leaf_node *)sst->last_node[i], LEAF_NODE_SIZE);
		else
			(*sst->index_api->index_init_node)(DO_NOT_ADD_GUARD, (struct index_node *)sst->last_node[i],
							   internalNode);
	}

	return sst;
}

static struct key_splice *sst_create_pivot(struct kv_splice_base *last_splice, struct kv_splice_base *new_splice)
{
	int32_t key_left_len = kv_splice_base_get_key_size(last_splice);
	const char *key_left = kv_splice_base_get_key_buf(last_splice);
	int32_t key_right_len = kv_splice_base_get_key_size(new_splice);
	const char *key_right = kv_splice_base_get_key_buf(new_splice);
	int32_t min_len = key_left_len < key_right_len ? key_left_len : key_right_len;

	// Find the common prefix length
	int32_t idx = 0;
	for (; idx < min_len && key_left[idx] == key_right[idx]; ++idx)
		;

	if (idx == key_left_len || idx == key_right_len) {
		//just use the new_splice as pivot do not bother
		bool malloced = false;
		struct key_splice *pivot = key_splice_create(kv_splice_base_get_key_buf(new_splice),
							     kv_splice_base_get_key_size(new_splice), NULL, 0,
							     &malloced);
		// log_debug("Just returning the last splice: %.*s no room for optimization ok!",
		// 	  key_splice_get_key_size(pivot), key_splice_get_key_offset(pivot));
		return pivot;
	}

	char pivot_buf[MAX_KEY_SIZE] = { 0 };
	memcpy(pivot_buf, key_left, idx);
	// Add an extra character

	pivot_buf[idx] = (key_left[idx] + 1 < key_right[idx]) ? key_left[idx] + 1 : key_right[idx];
	bool malloced = false;
	struct key_splice *pivot = key_splice_create(pivot_buf, idx + 1, NULL, 0, &malloced);
	// log_debug("Created optimized pivot %.*s optimization ok! last_splice is: %.*s and new_splice: %.*s",
	// 	  key_splice_get_key_size(pivot), key_splice_get_key_offset(pivot),
	// 	  kv_splice_base_get_key_size(last_splice), kv_splice_base_get_key_buf(last_splice),
	// 	  kv_splice_base_get_key_size(new_splice), kv_splice_base_get_key_buf(new_splice));

	return pivot;
}

static uint32_t sst_calc_offt(struct sst *sst, char *addr)
{
	uint64_t start = (uint64_t)sst->IO_buffer;
	uint64_t end = (uint64_t)addr;

	if (end < start) {
		log_fatal("End should be greater than start!");
		BUG_ON();
	}
	return end - start;
}

static bool sst_append_pivot_to_index(int32_t height, struct sst *sst, uint64_t left_node_offt,
				      struct key_splice *pivot, uint64_t right_node_offt)
{
	//log_debug("Append pivot %.*s left child offt %lu right child offt %lu", pivot->size, pivot->data,
	//	  left_node_offt, right_node_offt);
	struct index_node *node = (struct index_node *)sst->last_node[height];

	if (sst->index_api->index_is_empty(node)) {
		sst->index_api->index_add_guard(node, left_node_offt);
		sst->index_api->index_set_height(node, height);
	}

	struct pivot_pointer right = { .child_offt = right_node_offt };

	struct insert_pivot_req ins_pivot_req = { .node = node, .key_splice = pivot, .right_child = &right };
	while (!sst->index_api->index_append_pivot(&ins_pivot_req)) {
		struct node_header *new_node =
			(struct node_header *)sst_get_space(sst, sst->index_api->index_get_node_size(), false);

		if (new_node == NULL) {
			log_debug("Sorry no more space for index node for height: %u", height);
			return false;
		}

		uint32_t offt_l = sst_calc_offt(sst, (char *)sst->last_node[height]);
		uint64_t left_index_offt = sst->meta->sst_dev_offt + offt_l;

		struct key_splice *pivot_copy_splice = sst->index_api->index_remove_last_key(node);
		struct pivot_pointer *piv_pointer = sst->index_api->index_get_pivot(pivot_copy_splice);
		struct node_header *backup = sst->last_node[height];
		sst->last_node[height] = new_node;

		(*sst->index_api->index_init_node)(DO_NOT_ADD_GUARD, (struct index_node *)sst->last_node[height],
						   internalNode);
		ins_pivot_req.node = (struct index_node *)sst->last_node[height];
		(*sst->index_api->index_add_guard)(ins_pivot_req.node, piv_pointer->child_offt);
		(*sst->index_api->index_set_height)(ins_pivot_req.node, height);

		/*last node updated*/
		uint32_t offt_r = sst_calc_offt(sst, (char *)sst->last_node[height]);
		uint64_t right_index_offt = sst->meta->sst_dev_offt + offt_r;
		if (false ==
		    sst_append_pivot_to_index(height + 1, sst, left_index_offt, pivot_copy_splice, right_index_offt)) {
			log_debug("Append pivot in higher tree level failed, rolling back");
			sst->last_node[height] = backup;
			struct insert_pivot_req restore = { .node = (struct index_node *)sst->last_node[height],
							    .right_child = piv_pointer,
							    .key_splice = pivot_copy_splice };
			(*sst->index_api->index_append_pivot)(&restore);

			free(pivot_copy_splice);
			return false;
		}
		free(pivot_copy_splice);
	}
	return true;
}

bool sst_append_splice(struct sst *sst, struct kv_splice_base *splice)
{
	uint64_t left_leaf_offt = 0;
	uint64_t right_leaf_offt = 0;

	// struct kv_splice_base new_splice = *splice;
	// bool append_to_medium = false;

	// 	char kv_sep_buf[KV_SEP2_MAX_SIZE];

	// 	if (sst->meta->level_id == 1 && splice->kv_cat == MEDIUM_INPLACE){
	// 		*splice = sst_append_medium_L1(sst, splice, kv_sep_buf, KV_SEP2_MAX_SIZE);
	//   }

	// 	if (splice->kv_cat == MEDIUM_INLOG && sst->meta->level_id == sst->db_handle->db_desc->level_medium_inplace) {
	// 		splice->kv_cat = MEDIUM_INPLACE;
	// 		splice->kv_type = KV_FORMAT;
	// 		splice->kv_splice = (struct kv_splice *)mlog_cache_fetch_kv_from_LRU(
	// 			sst->medium_log_LRU_cache, kv_sep2_get_value_offt(splice->kv_sep2));
	// 		assert(kv_splice_base_get_key_size(splice) <= MAX_KEY_SIZE);
	// 		assert(kv_splice_base_get_key_size(splice) > 0);
	// 		// append_to_medium = true;
	// #if MEASURE_MEDIUM_INPLACE
	// 		__sync_fetch_and_add(&cursor->handle->db_desc->count_medium_inplace, 1);
	// #endif
	// 	}
	bool new_leaf = false;
	struct node_header *last_node_backup = NULL;
	struct key_splice *pivot = NULL;
	if ((*sst->leaf_api->leaf_is_full)((struct leaf_node *)sst->last_node[0], kv_splice_base_get_size(splice))) {
		struct node_header *new_node = (struct node_header *)sst_get_space(sst, LEAF_NODE_SIZE, true);
		if (NULL == new_node) {
			// if (append_to_medium)
			// 	*splice = new_splice;
			log_debug("Oops no more space for leaf nodes");
			return false; //abort no more space
		}

		struct kv_splice_base last = (*sst->leaf_api->leaf_get_last)((struct leaf_node *)sst->last_node[0]);

		pivot = sst_create_pivot(&last, splice);

		uint32_t offt_l = sst_calc_offt(sst, (char *)sst->last_node[0]);
		left_leaf_offt = sst->meta->sst_dev_offt + offt_l;

		//1. keep the offt of the previous leaf
		// struct leaf_node *semilast_leaf = (struct leaf_node *)sst->last_node[0];
		uint64_t next_leaf_offt = sst->meta->sst_dev_offt + sst_calc_offt(sst, (char *)new_node);

		(*sst->leaf_api->leaf_set_next_offt)((struct leaf_node *)sst->last_node[0], next_leaf_offt);
		// log_debug("Set next leaf offt to: %lu",next_leaf_offt);

		last_node_backup = sst->last_node[0];
		sst->last_node[0] = new_node;
		uint32_t offt_r = sst_calc_offt(sst, (char *)sst->last_node[0]);
		right_leaf_offt = sst->meta->sst_dev_offt + offt_r;
		//2. done set the next leaf offt, so now we have a B-link tree!
		(*sst->leaf_api->leaf_init)((struct leaf_node *)sst->last_node[0], LEAF_NODE_SIZE);
		(*sst->leaf_api->leaf_set_next_offt)((struct leaf_node *)sst->last_node[0], 0);
		new_leaf = true;
	}

	if (!(*sst->leaf_api->leaf_append)((struct leaf_node *)sst->last_node[0], splice, splice->is_tombstone)) {
		log_fatal("Append in leaf failed (It shouldn't at this point)");
		_exit(EXIT_FAILURE);
	}

	if (0 == sst->meta->first_guard_size)
		sst_set_first_guard(sst, splice);

	if (!new_leaf)
		return true;
	bool ret = sst_append_pivot_to_index(1, sst, left_leaf_offt, pivot, right_leaf_offt);
	if (false == ret) { //rollback logic
		sst->last_node[0] = last_node_backup;
		log_debug("Ooops failed to append in pivot no more space in SST");
	}
	free(pivot);

	return ret;
}

bool sst_append_KV_pair(struct sst *sst, struct kv_splice_base *splice)
{
	return sst_append_splice(sst, splice);
}

bool sst_flush(struct sst *sst)
{
	struct leaf_node *last_leaf = (struct leaf_node *)sst->last_node[0];
	struct kv_splice_base last_splice = (*sst->leaf_api->leaf_get_last)(last_leaf);
	sst_set_last_guard(sst, &last_splice);

	sst->last_leaf_offt -= LEAF_NODE_SIZE;
	int height = MAX_HEIGHT - 1;
	for (; height >= 0; height--) {
		if (0 == sst->last_node[height]->num_entries)
			continue;
		break;
	}
	log_debug("B+tree in SST has height of: %d num entries: %u", height, sst->last_node[height]->num_entries);
	sst->meta->root_offt = sst->meta->sst_dev_offt + sst_calc_offt(sst, (char *)sst->last_node[height]);
	sst->last_node[height]->type = height == 0 ? leafRootNode : rootNode;
	memcpy(sst->IO_buffer, sst->meta, sst_meta_get_size(sst->meta));

	ssize_t total_bytes_written = 0;
	while (total_bytes_written < sst->meta->sst_size) {
		ssize_t bytes_written = pwrite(sst->db_handle->db_desc->db_volume->vol_fd,
					       &sst->IO_buffer[total_bytes_written],
					       sst->meta->sst_size - total_bytes_written,
					       sst->meta->sst_dev_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to writed segment for leaf nodes reason follows");
			perror("Reason");
			BUG_ON();
		}
		total_bytes_written += bytes_written;
	}
	return true;
}

bool sst_close(struct sst *sst)
{
	free(sst->IO_buffer);
	free(sst);
	return true;
}

struct leaf_node *level_get_leaf(struct sst *sst, struct key_splice *key_splice)
{
	struct node_header *son_node = NULL;
	struct node_header *curr_node = REAL_ADDRESS(sst->meta->root_offt);

	if (NULL == curr_node) //empty level
		return NULL;

	while (curr_node->type != leafNode && curr_node->type != leafRootNode) {
		//No locking needed for the device levels >= 1
		uint64_t child_offset = (*sst->index_api->index_search)((struct index_node *)curr_node,
									key_splice_get_key_offset(key_splice),
									key_splice_get_key_size(key_splice));

		son_node = (void *)REAL_ADDRESS(child_offset);

		curr_node = son_node;
	}
	return (struct leaf_node *)curr_node;
}

struct sst_meta *sst_get_meta(struct sst *sst)
{
	return sst->meta;
}

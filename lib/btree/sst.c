#include "sst.h"
#include "btree.h"
#include "conf.h"
#include "device_level.h"
#include "kv_pairs.h"
#include "medium_log_LRU_cache.h"
#include "segment_allocator.h"
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
	uint32_t level_id;
	char *kv_splice;
} __attribute__((packed));

struct sst {
	struct node_header *last_node[MAX_HEIGHT];
	db_handle *db_handle;
	char *sst_buf;
	struct sst_meta *meta;
	struct medium_log_LRU_cache *medium_log_LRU_cache;
	struct level_leaf_api *leaf_api;
	struct level_index_api *index_api;
	uint64_t txn_id;
	uint32_t level_id;
	uint32_t tree_id;
	uint32_t tree_height;
	uint64_t sst_dev_offt;
	uint32_t sst_size;
	uint32_t last_leaf_offt;
	uint32_t last_index_offt;
};

static char *sst_get_space(struct sst *sst, size_t size, bool is_leaf)
{
	assert(0 == SEGMENT_SIZE % size);

	uint32_t remaining_space = sst->last_index_offt - sst->last_leaf_offt;

	if (remaining_space < size)
		return NULL;

	char *node = NULL;
	if (is_leaf) {
		node = &sst->sst_buf[sst->last_leaf_offt];
		sst->last_leaf_offt += LEAF_NODE_SIZE;
		return node;
	}
	node = &sst->sst_buf[sst->last_index_offt - INDEX_NODE_SIZE];
	sst->last_index_offt -= INDEX_NODE_SIZE;
	return node;
}

struct sst *sst_create(uint32_t size, uint64_t txn_id, db_handle *handle, uint32_t level_id,
		       struct medium_log_LRU_cache *medium_log_LRU_cache)
{
	struct sst *sst = calloc(1UL, sizeof(struct sst));
	sst->db_handle = handle;
	if (posix_memalign((void **)&sst->sst_buf, ALIGNMENT, size != 0)) {
		log_fatal("Posix memalign failed");
		perror("Reason: ");
		_exit(EXIT_FAILURE);
	}
	sst->last_leaf_offt = SST_METADATA_SIZE;
	sst->last_index_offt = size;
	sst->meta = (struct sst_meta *)sst->sst_buf;
	sst->level_id = sst->level_id;
	sst->meta->level_id = level_id;
	sst->txn_id = txn_id;

	sst->medium_log_LRU_cache = medium_log_LRU_cache;
	sst->sst_dev_offt = seg_allocate_segment(sst->db_handle->db_desc, sst->txn_id);
	sst->leaf_api = level_get_leaf_api(handle->db_desc->dev_levels[level_id]);
	sst->index_api = level_get_index_api(handle->db_desc->dev_levels[level_id]);
	for (int i = 0; i < MAX_HEIGHT; i++)
		sst->last_node[i] = (struct node_header *)(i == 0 ? sst_get_space(sst, LEAF_NODE_SIZE, true) :
								    sst_get_space(sst, INDEX_NODE_SIZE, false));

	return sst;
}

static struct kv_splice_base sst_append_medium_L1(struct sst *sst, struct kv_splice_base *splice_base, char *kv_sep_buf,
						  int32_t kv_sep_buf_size)

{
	if (sst->level_id != 1 || splice_base->kv_cat != MEDIUM_INPLACE)
		return *splice_base;

	struct bt_insert_req ins_req;
	ins_req.metadata.handle = sst->db_handle;
	ins_req.metadata.log_offset = 0;

	ins_req.metadata.cat = MEDIUM_INLOG;
	ins_req.metadata.level_id = sst->level_id;
	ins_req.metadata.tree_id = 1;
	ins_req.metadata.append_to_log = 1;
	ins_req.metadata.gc_request = 0;
	ins_req.metadata.key_format = KV_FORMAT;
	ins_req.metadata.tombstone = 0;
	ins_req.splice_base = splice_base;
	/*For Tebis-parallax currently*/
	// ins_req.metadata.segment_full_event = 0;
	ins_req.metadata.log_segment_addr = 0;
	ins_req.metadata.log_offset_full_event = 0;
	ins_req.metadata.segment_id = 0;
	ins_req.metadata.end_of_log = 0;
	ins_req.metadata.log_padding = 0;

	struct log_operation log_op = { .metadata = &ins_req.metadata,
					.optype_tolog = insertOp,
					.ins_req = &ins_req,
					.is_medium_log_append = true,
					.txn_id = sst->txn_id };

	char *log_location = append_key_value_to_log(&log_op);

	struct kv_splice_base kv_sep = { .kv_cat = MEDIUM_INLOG,
					 .kv_type = KV_PREFIX,
					 .kv_sep2 = kv_sep2_create(kv_splice_base_get_key_size(splice_base),
								   kv_splice_base_get_key_buf(splice_base),
								   ABSOLUTE_ADDRESS(log_location), kv_sep_buf,
								   kv_sep_buf_size) };
	return kv_sep;
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
	uint64_t start = (uint64_t)sst->sst_buf;
	uint64_t end = (uint64_t)addr;
	// log_debug("start is %lu end is %lu", start, end);

	if (end < start) {
		log_fatal("End should be greater than start!");
		assert(0);
		BUG_ON();
	}
	assert(end - start < SEGMENT_SIZE);

	return (end - start) % SEGMENT_SIZE;
}

static uint64_t sst_get_next_leaf_offt(struct sst *sst, size_t size)
{
	uint32_t remaining_space = sst->last_index_offt - sst->last_leaf_offt;

	if (remaining_space >= size) {
		uint32_t leaf_offt = sst->sst_dev_offt + sst->last_leaf_offt;
		return leaf_offt;
	}
	return UINT64_MAX;
}

static void sst_append_pivot_to_index(int32_t height, struct sst *sst, uint64_t left_node_offt,
				      struct key_splice *pivot, uint64_t right_node_offt)
{
	//log_debug("Append pivot %.*s left child offt %lu right child offt %lu", pivot->size, pivot->data,
	//	  left_node_offt, right_node_offt);

	if (sst->tree_height < height)
		sst->tree_height = height;

	struct index_node *node = (struct index_node *)sst->last_node[height];

	if (sst->index_api->index_is_empty(node)) {
		sst->index_api->index_add_guard(node, left_node_offt);
		sst->index_api->index_set_height(node, height);
	}

	struct pivot_pointer right = { .child_offt = right_node_offt };

	struct insert_pivot_req ins_pivot_req = { .node = node, .key_splice = pivot, .right_child = &right };
	while (!sst->index_api->index_append_pivot(&ins_pivot_req)) {
		uint32_t offt_l = sst_calc_offt(sst, (char *)sst->last_node[height]);
		uint64_t left_index_offt = sst->sst_dev_offt + offt_l;

		struct key_splice *pivot_copy_splice = sst->index_api->index_remove_last_key(node);
		struct pivot_pointer *piv_pointer = sst->index_api->index_get_pivot(pivot_copy_splice);
		sst->last_node[height] =
			(struct node_header *)sst_get_space(sst, sst->index_api->index_get_node_size(), false);

		(*sst->index_api->index_init_node)(DO_NOT_ADD_GUARD, (struct index_node *)sst->last_node[height],
						   internalNode);
		ins_pivot_req.node = (struct index_node *)sst->last_node[height];
		(*sst->index_api->index_add_guard)(ins_pivot_req.node, piv_pointer->child_offt);
		(*sst->index_api->index_set_height)(ins_pivot_req.node, height);

		/*last leaf updated*/
		uint32_t offt_r = sst_calc_offt(sst, (char *)sst->last_node[height]);
		uint64_t right_index_offt = sst->sst_dev_offt + offt_r;
		sst_append_pivot_to_index(height + 1, sst, left_index_offt, pivot_copy_splice, right_index_offt);
		free(pivot_copy_splice);
	}
}

bool sst_append_splice(struct sst *sst, struct kv_splice_base *splice)
{
	uint64_t left_leaf_offt = 0;
	uint64_t right_leaf_offt = 0;

	struct kv_splice_base new_splice = *splice;

	char kv_sep_buf[KV_SEP2_MAX_SIZE];

	if (sst->level_id == 1 && splice->kv_cat == MEDIUM_INPLACE)
		new_splice = sst_append_medium_L1(sst, splice, kv_sep_buf, KV_SEP2_MAX_SIZE);

	if (new_splice.kv_cat == MEDIUM_INLOG && sst->level_id == sst->db_handle->db_desc->level_medium_inplace) {
		new_splice.kv_cat = MEDIUM_INPLACE;
		new_splice.kv_type = KV_FORMAT;
		new_splice.kv_splice = (struct kv_splice *)mlog_cache_fetch_kv_from_LRU(
			sst->medium_log_LRU_cache, kv_sep2_get_value_offt(new_splice.kv_sep2));
		assert(kv_splice_base_get_key_size(&new_splice) <= MAX_KEY_SIZE);
		assert(kv_splice_base_get_key_size(&new_splice) > 0);

#if MEASURE_MEDIUM_INPLACE
		__sync_fetch_and_add(&cursor->handle->db_desc->count_medium_inplace, 1);
#endif
	}
	bool new_leaf = false;
	struct key_splice *pivot = NULL;
	if ((*sst->leaf_api->leaf_is_full)((struct leaf_node *)sst->last_node[0],
					   kv_splice_base_get_size(&new_splice))) {
		struct kv_splice_base last = (*sst->leaf_api->leaf_get_last)((struct leaf_node *)sst->last_node[0]);

		pivot = sst_create_pivot(&last, &new_splice);

		uint32_t offt_l = sst_calc_offt(sst, (char *)sst->last_node[0]);
		left_leaf_offt = sst->sst_dev_offt + offt_l;

		//1. keep the offt of the previous leaf
		struct leaf_node *semilast_leaf = (struct leaf_node *)sst->last_node[0];
		uint64_t next_leaf_offt = sst_get_next_leaf_offt(sst, LEAF_NODE_SIZE);
		(*sst->leaf_api->leaf_set_next_offt)(semilast_leaf, next_leaf_offt);
		// log_debug("Set next leaf offt to: %lu",next_leaf_offt);

		sst->last_node[0] = (struct node_header *)sst_get_space(sst, LEAF_NODE_SIZE, true);
		uint32_t offt_r = sst_calc_offt(sst, (char *)sst->last_node[0]);
		right_leaf_offt = sst->sst_dev_offt + offt_r;
		//2. done set the next leaf offt, so now we have a B-link tree!
		(*sst->leaf_api->leaf_init)((struct leaf_node *)sst->last_node[0], LEAF_NODE_SIZE);
		(*sst->leaf_api->leaf_set_next_offt)((struct leaf_node *)sst->last_node[0], 0);
		new_leaf = true;
	}

	if (!(*sst->leaf_api->leaf_append)((struct leaf_node *)sst->last_node[0], &new_splice,
					   new_splice.is_tombstone)) {
		log_fatal("Append in leaf failed (It shouldn't at this point)");
		_exit(EXIT_FAILURE);
	}

	level_increase_size(sst->db_handle->db_desc->dev_levels[sst->level_id], kv_splice_base_get_size(&new_splice),
			    1);
	// level_add_key_to_bf(w_cursor->handle->db_desc->dev_levels[w_cursor->level_id], w_cursor->tree_id,
	// 		    kv_splice_base_get_key_buf(&new_splice), kv_splice_base_get_key_size(&new_splice));

	level_inc_num_keys(sst->db_handle->db_desc->dev_levels[sst->level_id], sst->tree_id, 1);

	if (!new_leaf)
		return true;

	// bool malloced = false;
	// struct key_splice *new_pivot = key_splice_create(kv_splice_base_get_key_buf(&pivot),
	// 						 kv_splice_base_get_key_size(&new_splice), NULL, 0, &malloced);

	// assert(malloced);
	sst_append_pivot_to_index(1, sst, left_leaf_offt, pivot, right_leaf_offt);
	free(pivot);
	return true;
}

bool sst_append_KV_pair(struct sst *sst, struct kv_splice_base *splice)
{
	return sst_append_splice(sst, splice);
}

bool sst_flush(struct sst *sst)
{
	for (int height = MAX_HEIGHT - 1; height >= 0; height--) {
		if (0 == sst->last_node[height]->num_entries)
			continue;
		sst->meta->root_offt = sst->sst_dev_offt + sst_calc_offt(sst, (char *)sst->last_node[height]);
		break;
	}
	ssize_t total_bytes_written = sst->sst_size;
	while (total_bytes_written < sst->sst_size) {
		ssize_t bytes_written = pwrite(sst->db_handle->db_desc->db_volume->vol_fd,
					       &sst->sst_buf[total_bytes_written], sst->sst_size - total_bytes_written,
					       sst->sst_dev_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to writed segment for leaf nodes reason follows");
			perror("Reason");
			BUG_ON();
		}
		total_bytes_written += bytes_written;
	}
	return true;
}

bool sst_remove(struct sst *sst, uint64_t txn_id)
{
	seg_free_segment(sst->db_handle->db_desc, txn_id, sst->sst_dev_offt);
	free(sst->sst_buf);
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

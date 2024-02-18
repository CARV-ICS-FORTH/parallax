// Copyright [2023] [FORTH-ICS]
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

#define _GNU_SOURCE
#include "compaction_worker.h"
#include "../allocator/persistent_operations.h"
#include "../allocator/redo_undo_log.h"
#include "../allocator/volume_manager.h"
#include "../common/common.h"
#include "../lib/allocator/device_structures.h"
#include "../parallax_callbacks/parallax_callbacks.h"
#include "../scanner/L0_scanner.h"
#include "../scanner/min_max_heap.h"
#include "../utilities/dups_list.h"
#include "../utilities/spin_loop.h"
#include "btree.h"
#include "compaction_daemon.h"
#include "conf.h"
#include "device_level.h"
#include "gc.h"
#include "key_splice.h"
#include "kv_pairs.h"
#include "medium_log_LRU_cache.h"
#include "parallax/structures.h"
#include "segment_allocator.h"
#include "sst.h"
#include <assert.h>
#include <log.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
struct medium_log_LRU_cache;
struct device_level;
struct node_header;
#if COMPACTION_STATS
#include <sys/time.h>
#endif
#include <unistd.h>
#include <uthash.h>
// IWYU pragma: no_forward_declare pbf_desc
// IWYU pragma: no_forward_declare wcursor_level_write_cursor
struct compaction_request {
	db_descriptor *db_desc;
	par_db_options *db_options;
	// struct rcursor_level_read_cursor *dst_rcursor;
	union {
		struct L0_scanner *L0_scanner;
		struct level_compaction_scanner *src_scanner;
	};
	struct level_compaction_scanner *dst_scanner;
	struct sst *curr_sst;
	// struct wcursor_level_write_cursor *wcursor;
	uint64_t txn_id;
	uint64_t l0_start;
	uint64_t l0_end;
	uint8_t src_level;
	uint8_t src_tree;
	uint8_t dst_level;
	uint8_t dst_tree;
};

struct compaction_request *compaction_create_req(db_descriptor *db_desc, par_db_options *db_options, uint64_t l0_start,
						 uint64_t l0_end, uint8_t src_level, uint8_t src_tree,
						 uint8_t dst_level, uint8_t dst_tree)
{
	struct compaction_request *compaction_req = calloc(1UL, sizeof(struct compaction_request));
	compaction_req->db_desc = db_desc;
	compaction_req->db_options = db_options;
	compaction_req->l0_start = l0_start;
	compaction_req->l0_end = l0_end;
	compaction_req->src_level = src_level;
	compaction_req->src_tree = src_tree;
	compaction_req->dst_level = dst_level;
	compaction_req->dst_tree = dst_tree;
	compaction_req->txn_id = rul_start_txn(db_desc);
	return compaction_req;
}

uint8_t compaction_get_dst_level(struct compaction_request *comp_req)
{
	assert(comp_req);
	return comp_req->dst_level;
}

void compaction_set_dst_tree(struct compaction_request *comp_req, uint8_t tree_id)
{
	assert(comp_req);
	comp_req->dst_tree = tree_id;
}

uint8_t compaction_get_src_level(struct compaction_request *comp_req)
{
	assert(comp_req);
	return comp_req->src_level;
}

uint8_t compaction_get_src_tree(struct compaction_request *comp_req)
{
	assert(comp_req);
	return comp_req->src_tree;
}

// cppcheck-suppress unusedFunction
void compaction_destroy_req(struct compaction_request *comp_req)
{
	assert(comp_req);
	free(comp_req);
}

struct volume_descriptor *compaction_get_volume_desc(struct compaction_request *comp_req)
{
	assert(comp_req);
	return comp_req->db_desc->db_volume;
}

struct db_descriptor *compaction_get_db_desc(struct compaction_request *comp_req)
{
	assert(comp_req);
	return comp_req->db_desc;
}

#if 0
static void print_heap_node_key(struct sh_heap_node *h_node)
{
	switch (h_node->cat) {
	case SMALL_INPLACE:
	case MEDIUM_INPLACE:;
		struct kv_splice *kv = (struct kv_splice *)h_node->KV;
		log_debug("In place Key is %u:%s", get_key_size(kv), get_key_offset_in_kv(kv));
		break;
	case BIG_INLOG:
	case MEDIUM_INLOG:;
		struct kv_splice *full_key = (struct kv_splice *)((struct kv_seperation_splice *)h_node->KV)->dev_offt;

		log_debug("In log Key prefix is %.*s full key size: %u  full key data %.*s", PREFIX_SIZE,
			  (char *)h_node->KV, get_key_size(full_key), get_key_size(full_key),
			  get_key_offset_in_kv(full_key));
		break;
	default:
		log_fatal("Unhandle/Unknown category");
		BUG_ON();
	}
}
#endif

static void mark_segment_space(db_handle *handle, struct dups_list *list, uint64_t txn_id)
{
	struct dups_node *list_iter;
	struct dups_list *calculate_diffs;
	struct large_log_segment_gc_entry *temp_segment_entry;
	uint64_t segment_dev_offt;
	calculate_diffs = init_dups_list();

	MUTEX_LOCK(&handle->db_desc->segment_ht_lock);

	for (list_iter = list->head; list_iter; list_iter = list_iter->next) {
		segment_dev_offt = ABSOLUTE_ADDRESS(list_iter->dev_offt);

		struct large_log_segment_gc_entry *search_segment = NULL;
		HASH_FIND(hh, handle->db_desc->segment_ht, &segment_dev_offt, sizeof(segment_dev_offt), search_segment);

		assert(list_iter->kv_size > 0);
		if (search_segment) {
			// If the segment is already in the hash table just increase the garbage bytes.
			search_segment->garbage_bytes += list_iter->kv_size;
			assert(search_segment->garbage_bytes < SEGMENT_SIZE);
		} else {
			// This is the first time we detect garbage bytes in this segment,
			// allocate a node and insert it in the hash table.
			temp_segment_entry = calloc(1, sizeof(struct large_log_segment_gc_entry));
			temp_segment_entry->segment_dev_offt = segment_dev_offt;
			temp_segment_entry->garbage_bytes = list_iter->kv_size;
			temp_segment_entry->segment_moved = 0;
			HASH_ADD(hh, handle->db_desc->segment_ht, segment_dev_offt,
				 sizeof(temp_segment_entry->segment_dev_offt), temp_segment_entry);
		}

		struct dups_node *node = find_element(calculate_diffs, segment_dev_offt);

		if (node)
			node->kv_size += list_iter->kv_size;
		else
			append_node(calculate_diffs, segment_dev_offt, list_iter->kv_size);
	}

	MUTEX_UNLOCK(&handle->db_desc->segment_ht_lock);

	for (struct dups_node *persist_blob_metadata = calculate_diffs->head; persist_blob_metadata;
	     persist_blob_metadata = persist_blob_metadata->next) {
		struct rul_log_entry entry = { .dev_offt = persist_blob_metadata->dev_offt,
					       .txn_id = txn_id,
					       .op_type = BLOB_GARBAGE_BYTES,
					       .blob_garbage_bytes = persist_blob_metadata->kv_size };
		rul_add_entry_in_txn_buf(handle->db_desc, &entry);
	}
}

static void comp_medium_log_set_max_segment_id(struct medium_log_LRU_cache *mlog_cache, struct db_descriptor *db_desc,
					       uint32_t level_id)
{
	if (NULL == mlog_cache)
		return;
	// uint64_t max_segment_id = 0;
	// uint64_t max_segment_offt = 0;

	// struct medium_log_segment_map *current_entry = NULL;
	// struct medium_log_segment_map *tmp = NULL;
	// HASH_ITER(hh, c->medium_log_segment_map, current_entry, tmp)
	// {
	// 	/* Suprresses possible null pointer dereference of cppcheck*/
	// 	assert(current_entry);
	// 	uint64_t segment_id = current_entry->id;
	// 	if (UINT64_MAX == segment_id) {
	// 		struct segment_header *segment = REAL_ADDRESS(current_entry->dev_offt);
	// 		segment_id = segment->segment_id;
	// 	}

	// 	// cppcheck-suppress unsignedPositive
	// 	if (segment_id >= max_segment_id) {
	// 		max_segment_id = segment_id;
	// 		max_segment_offt = current_entry->dev_offt;
	// 	}
	// 	HASH_DEL(c->medium_log_segment_map, current_entry);
	// 	free(current_entry);
	// }
	struct mlog_cache_max_segment_info max_segment = mlog_cache_find_max_segment_info(mlog_cache);
	struct device_level *level = db_desc->dev_levels[level_id];
	level_set_medium_in_place_seg_id(level, max_segment.max_segment_id);
	level_set_medium_in_place_seg_offt(level, max_segment.max_segment_offt);
	log_debug("Max segment id touched during medium transfer to in place is %lu and corresponding offt: %lu",
		  max_segment.max_segment_id, max_segment.max_segment_offt);
}

static void lock_to_update_levels_after_compaction(struct compaction_request *comp_req)
{
	if (0 == comp_req->src_level) {
		if (RWLOCK_WRLOCK(&(comp_req->db_desc->L0.guard_of_level.rx_lock))) {
			log_fatal("Failed to acquire guard lock");
			BUG_ON();
		}
		spin_loop(&comp_req->db_desc->L0.active_operations, 0);
	} else
		level_enter_as_writer(comp_req->db_desc->dev_levels[comp_req->src_level]);
	level_enter_as_writer(comp_req->db_desc->dev_levels[comp_req->dst_level]);

	MUTEX_LOCK(&comp_req->db_desc->flush_L0_lock);
}

static void unlock_to_update_levels_after_compaction(struct compaction_request *comp_req)
{
	if (0 == comp_req->src_level) {
		if (RWLOCK_UNLOCK(&(comp_req->db_desc->L0.guard_of_level.rx_lock))) {
			log_fatal("Failed to acquire guard lock");
			BUG_ON();
		}
	} else
		level_leave_as_writer(comp_req->db_desc->dev_levels[comp_req->src_level]);

	level_leave_as_writer(comp_req->db_desc->dev_levels[comp_req->dst_level]);
	MUTEX_UNLOCK(&comp_req->db_desc->flush_L0_lock);
}

static void comp_zero_level(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	if (0 == level_id) {
		db_desc->L0.level_size[tree_id] = 0;
		db_desc->L0.first_segment[tree_id] = NULL;
		db_desc->L0.last_segment[tree_id] = NULL;
		db_desc->L0.offset[tree_id] = 0;
		db_desc->L0.root[tree_id] = NULL;
		db_desc->L0.num_level_keys[tree_id] = 0;
	} else
		level_zero(db_desc->dev_levels[level_id], tree_id);
}

static bool comp_fill_src_heap_node(struct compaction_request *comp_req, struct sh_heap_node *heap_node)
{
	// heap_node->db_desc = comp_req->db_desc;
	heap_node->level_id = comp_req->src_level;
	heap_node->active_tree = comp_req->src_level == 0 ? comp_req->src_tree : 0;
	if (0 == comp_req->src_level)
		heap_node->splice = comp_req->L0_scanner->splice;
	else
		level_comp_scanner_get_curr(comp_req->src_scanner, &heap_node->splice);

	return true;
}

static void comp_fill_dst_heap_node(struct compaction_request *comp_req, struct sh_heap_node *heap_node)
{
	// heap_node->db_desc = comp_req->db_desc;
	heap_node->level_id = comp_req->dst_level;
	heap_node->active_tree = comp_req->dst_tree;
	level_comp_scanner_get_curr(comp_req->dst_scanner, &heap_node->splice);
}

#define COMP_MAGIC_SMALL_KV_SIZE (33)
static int64_t comp_calculate_level_keys(struct db_descriptor *db_desc, uint8_t level_id)
{
	assert(level_id > 0);
	uint8_t tree_id = 0; /*Always caclulate the immutable aka 0 tree of the level*/
	int64_t total_keys = level_get_num_KV_pairs(db_desc->dev_levels[level_id], tree_id);

	if (0 == total_keys && 1 == level_id) {
		total_keys = db_desc->L0.max_level_size / COMP_MAGIC_SMALL_KV_SIZE;
	}

	if (level_id > 1) {
		total_keys += level_get_num_KV_pairs(db_desc->dev_levels[level_id - 1], tree_id);
	}
	assert(total_keys);
	return total_keys;
}

static struct kv_splice_base comp_append_medium_L1(db_handle *handle, struct kv_splice_base *splice_base,
						   char *kv_sep_buf, uint32_t kv_sep_buf_size, uint64_t txn_id)

{
	// if (sst->meta->level_id != 1 || splice_base->kv_cat != MEDIUM_INPLACE)
	// 	return *splice_base;

	struct bt_insert_req ins_req;
	ins_req.metadata.handle = handle;
	ins_req.metadata.log_offset = 0;

	ins_req.metadata.cat = MEDIUM_INLOG;
	ins_req.metadata.level_id = 1;
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

	struct log_operation log_op = {
		.optype_tolog = insertOp, .ins_req = &ins_req, .is_medium_log_append = true, .txn_id = txn_id
	};

	char *log_location = append_key_value_to_log(&log_op);

	struct kv_splice_base kv_sep = { .kv_cat = MEDIUM_INLOG,
					 .kv_type = KV_PREFIX,
					 .kv_sep2 = kv_sep2_create(kv_splice_base_get_key_size(splice_base),
								   kv_splice_base_get_key_buf(splice_base),
								   ABSOLUTE_ADDRESS(log_location), kv_sep_buf,
								   kv_sep_buf_size),
					 .is_tombstone = 0 };
	return kv_sep;
}

static void compact_level_direct_IO(struct db_handle *handle, struct compaction_request *comp_req)
{
	bool is_src_L0 = comp_req->src_level == 0;
	if (is_src_L0) {
		RWLOCK_WRLOCK(&handle->db_desc->L0.guard_of_level.rx_lock);
		spin_loop(&handle->db_desc->L0.active_operations, 0);
		pr_flush_log_tail(comp_req->db_desc, &comp_req->db_desc->big_log);
		comp_req->L0_scanner =
			L0_scanner_init_compaction_scanner(handle, comp_req->src_level, comp_req->src_tree);
		RWLOCK_UNLOCK(&handle->db_desc->L0.guard_of_level.rx_lock);
	} else

		comp_req->src_scanner = level_comp_scanner_init(handle->db_desc->dev_levels[comp_req->src_level],
								comp_req->src_tree, SST_SIZE,
								handle->db_desc->db_volume->vol_fd);

	comp_req->dst_scanner = level_is_empty(handle->db_desc->dev_levels[comp_req->dst_level], 0) ?
					NULL :
					level_comp_scanner_init(handle->db_desc->dev_levels[comp_req->dst_level], 0,
								SST_SIZE, handle->db_desc->db_volume->vol_fd);

	//TODO: geostyl callback
	//  parallax_callbacks_t par_callbacks = comp_req->db_desc->parallax_callbacks;
	//  if (are_parallax_callbacks_set(par_callbacks)) {
	// 	struct parallax_callback_funcs par_cb = parallax_get_callbacks(par_callbacks);
	// 	void *context = parallax_get_context(par_callbacks);
	// 	uint64_t small_log_tail_dev_offt = UINT64_MAX;
	// 	uint64_t big_log_tail_dev_offt = UINT64_MAX;
	// 	if (!compaction_get_src_level(comp_req)) {
	// 		small_log_tail_dev_offt = handle->db_desc->small_log.tail_dev_offt;
	// 		big_log_tail_dev_offt = handle->db_desc->big_log.tail_dev_offt;
	// 	}
	// 	if (par_cb.compaction_started_cb)
	// 		par_cb.compaction_started_cb(context, small_log_tail_dev_offt, big_log_tail_dev_offt,
	// 					     compaction_get_src_level(comp_req),
	// 					     compaction_get_src_tree(comp_req), comp_req->wcursor);
	// }

	//initialize LRU cache for storing chunks of segments when medium log goes in place
	//old school
	// if (wcursor_get_level_id(comp_req->wcursor) == handle->db_desc->level_medium_inplace)
	// 	wcursor_set_LRU_cache(comp_req->wcursor, mlog_cache_init_LRU(handle));

	level_create_bf(handle->db_desc->dev_levels[comp_req->dst_level], comp_req->dst_tree,
			comp_calculate_level_keys(handle->db_desc, comp_req->dst_level), handle);
	struct medium_log_LRU_cache *mlog_cache =
		comp_req->dst_level == handle->db_desc->level_medium_inplace ? mlog_cache_init_LRU(handle) : NULL;

	log_debug("Src [%u][%u] size = %lu", compaction_get_src_level(comp_req), compaction_get_src_tree(comp_req),
		  0 == comp_req->src_level ? handle->db_desc->L0.level_size[compaction_get_src_tree(comp_req)] :
					     level_get_size(handle->db_desc->dev_levels[comp_req->src_level],
							    compaction_get_src_tree(comp_req)));

	if (level_is_empty(handle->db_desc->dev_levels[comp_req->dst_level], comp_req->dst_tree))
		log_debug("Empty dst [%u]", comp_req->dst_level);
	else
		log_debug("Dst [%u][%u] size = %lu", comp_req->dst_level, 0,
			  level_get_size(comp_req->db_desc->dev_levels[comp_req->dst_level], 0));

#if COMPACTION_STATS
	struct timeval start, end;
	gettimeofday(&start, NULL);
	uint64_t num_keys = 0;
#endif

	// initialize and fill min_heap properly
	struct sh_heap *m_heap = sh_alloc_heap();
	sh_init_heap(m_heap, comp_req->src_level, MIN_HEAP, comp_req->db_desc);
	struct sh_heap_node src_heap_node = { 0 };
	struct sh_heap_node dst_heap_node = { 0 };
	struct sh_heap_node min_heap_node = { 0 };
	// init Li cursor
	comp_fill_src_heap_node(comp_req, &src_heap_node);
	sh_insert_heap_node(m_heap, &src_heap_node);

	// init Li+1 cursor (if any)
	if (comp_req->dst_scanner) {
		comp_fill_dst_heap_node(comp_req, &dst_heap_node);
		sh_insert_heap_node(m_heap, &dst_heap_node);
	}

	comp_req->curr_sst = sst_create(SST_SIZE, comp_req->txn_id, handle, comp_req->dst_level);
	char kv_sep_buf[KV_SEP2_MAX_SIZE];

	while (sh_remove_top(m_heap, &min_heap_node)) {
#if COMPACTION_STATS
		num_keys++;
#endif
		if (min_heap_node.duplicate)
			goto refill;

		struct kv_splice_base splice =
			(min_heap_node.level_id == 0 && min_heap_node.splice.kv_cat == MEDIUM_INPLACE) ?
				comp_append_medium_L1(handle, &min_heap_node.splice, kv_sep_buf, sizeof(kv_sep_buf),
						      comp_req->txn_id) :
				min_heap_node.splice;

		assert(splice.kv_sep2);
		if (comp_req->dst_level == handle->db_desc->level_medium_inplace && splice.kv_cat == MEDIUM_INLOG) {
			struct kv_splice *m_kv = (struct kv_splice *)mlog_cache_fetch_kv_from_LRU(
				mlog_cache, kv_sep2_get_value_offt(splice.kv_sep2));
			assert(kv_splice_base_get_key_size(&splice) <= MAX_KEY_SIZE);
			assert(kv_splice_base_get_key_size(&splice) > 0);
			if (memcmp(kv_splice_base_get_key_buf(&splice), kv_splice_get_key_offset_in_kv(m_kv),
				   kv_splice_get_key_size(m_kv)) != 0) {
				log_fatal(
					"Mismatch: splice in_log key is: %.*s fetched from cache: %.*s offt in device: %lu",
					kv_splice_base_get_key_size(&splice), kv_splice_base_get_key_buf(&splice),
					kv_splice_get_key_size(m_kv), kv_splice_get_key_offset_in_kv(m_kv),
					kv_sep2_get_value_offt(splice.kv_sep2));
				assert(0);
			}
			splice.kv_cat = MEDIUM_INPLACE;
			splice.kv_type = KV_FORMAT;
			splice.kv_splice = m_kv;
		}

		while (false == sst_append_KV_pair(comp_req->curr_sst, &splice)) {
			sst_flush(comp_req->curr_sst);
			struct sst_meta *meta = sst_get_meta(comp_req->curr_sst);
			level_add_ssts(handle->db_desc->dev_levels[comp_req->dst_level], 1, &meta, comp_req->dst_tree);
			sst_close(comp_req->curr_sst);
			comp_req->curr_sst = sst_create(SST_SIZE, comp_req->txn_id, handle, comp_req->dst_level);
		}
		//BFs and level keys accounting
		level_add_key_to_bf(handle->db_desc->dev_levels[comp_req->dst_level], comp_req->dst_tree,
				    kv_splice_base_get_key_buf(&splice), kv_splice_base_get_key_size(&splice));
		level_increase_size(handle->db_desc->dev_levels[comp_req->dst_level], kv_splice_base_get_size(&splice),
				    1);
		level_inc_num_keys(handle->db_desc->dev_levels[comp_req->dst_level], comp_req->dst_tree, 1);

	refill:
		if (min_heap_node.level_id == comp_req->src_level) {
			bool has_next = comp_req->src_level == 0 ? L0_scanner_get_next(comp_req->L0_scanner) :
								   level_comp_scanner_next(comp_req->src_scanner);
			if (false == has_next)
				continue;
			comp_fill_src_heap_node(comp_req, &src_heap_node);
			sh_insert_heap_node(m_heap, &src_heap_node);
		} else if (comp_req->dst_scanner && min_heap_node.level_id == comp_req->dst_level &&
			   level_comp_scanner_next(comp_req->dst_scanner)) {
			comp_fill_dst_heap_node(comp_req, &dst_heap_node);
			sh_insert_heap_node(m_heap, &dst_heap_node);
		}
	}

	sst_flush(comp_req->curr_sst);
	struct sst_meta *meta = sst_get_meta(comp_req->curr_sst);
	level_add_ssts(handle->db_desc->dev_levels[comp_req->dst_level], 1, &meta, comp_req->dst_tree);
	sst_close(comp_req->curr_sst);
	comp_req->curr_sst = NULL;
	handle->db_desc->dirty = 0x01;

	level_persist_bf(handle->db_desc->dev_levels[comp_req->dst_level], comp_req->dst_tree);

	if (comp_req->src_level == 0)
		L0_scanner_close(comp_req->L0_scanner);
	else
		level_comp_scanner_close(comp_req->src_scanner);
	if (comp_req->dst_scanner)
		level_comp_scanner_close(comp_req->dst_scanner);

	mark_segment_space(handle, m_heap->dups, comp_req->txn_id);

	sh_destroy_heap(m_heap);
	//old school
	// wcursor_flush_write_cursor(comp_req->wcursor);

#if COMPACTION_STATS
	gettimeofday(&end, NULL);
	double time_taken_usec = ((end.tv_sec - start.tv_sec) * 1000000) + (double)(end.tv_usec - start.tv_usec);
	double time_taken = time_taken_usec / 1000000;
	if (comp_req->src_level) {
		log_info(
			"Compaction from level: %u to level: %u took: [%lf seconds  or %lf usec] total kv pairs: %lu throughput (KV pairs/s): %lf",
			comp_req->src_level, comp_req->dst_level, time_taken, time_taken_usec, num_keys,
			num_keys / time_taken);
	}
#endif
	//old school
	// uint64_t root_offt = wcursor_get_current_root(comp_req->wcursor);
	// assert(root_offt);
	//  level_set_root(handle->db_desc->dev_levels[comp_req->dst_level], 1, REAL_ADDRESS(root_offt));
	// assert(level_get_root(handle->db_desc->dev_levels[comp_req->dst_level], 1)->type == rootNode);

	// if (wcursor_get_level_id(comp_req->wcursor) == handle->db_desc->level_medium_inplace) {
	// 	comp_medium_log_set_max_segment_id(comp_req->wcursor, handle->db_desc);
	// 	mlog_cache_destroy_LRU(wcursor_get_LRU_cache(comp_req->wcursor));
	// }
	comp_medium_log_set_max_segment_id(mlog_cache, handle->db_desc, comp_req->dst_level);
	mlog_cache_destroy_LRU(mlog_cache);

	compaction_close(comp_req);
	//old school
	// wcursor_close_write_cursor(comp_req->wcursor);
}

static void compact_with_empty_destination_level(struct compaction_request *comp_req)
{
	log_debug("Empty level %d time for an optimization :-)", comp_req->dst_level);

	if (comp_req->db_options->options[PRIMARY_MODE].value) {
		/*TODO: swap levels callback*/
		parallax_callbacks_t par_callbacks = comp_req->db_desc->parallax_callbacks;
		if (are_parallax_callbacks_set(par_callbacks)) {
			struct parallax_callback_funcs par_cb = parallax_get_callbacks(par_callbacks);
			void *context = parallax_get_context(par_callbacks);
			if (par_cb.swap_levels_cb)
				par_cb.swap_levels_cb(context, comp_req->src_level, comp_req->src_tree);
		}
	}

	lock_to_update_levels_after_compaction(comp_req);

	if (comp_req->src_level == 0) {
		log_fatal("No level swap with Level-0!");
		_exit(EXIT_FAILURE);
	}
	struct device_level *src_level = comp_req->db_desc->dev_levels[comp_req->src_level];
	struct device_level *dst_level = comp_req->db_desc->dev_levels[comp_req->dst_level];
	level_swap(dst_level, comp_req->dst_tree, src_level, comp_req->src_tree);

	pr_flush_compaction(comp_req->db_desc, comp_req->db_options, comp_req->dst_level, comp_req->dst_tree,
			    comp_req->txn_id);

	level_swap(dst_level, 0, dst_level, 1);
	log_debug("Flushed compaction (Swap levels) successfully from src[%u][%u] to dst[%u][%u]", comp_req->src_level,
		  comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree);

	unlock_to_update_levels_after_compaction(comp_req);

	log_debug("Swapped levels %d to %d successfully", comp_req->src_level, comp_req->dst_level);
}

void *compaction(void *compaction_request)
{
	db_handle handle;
	struct compaction_request *comp_req = (struct compaction_request *)compaction_request;
	db_descriptor *db_desc = comp_req->db_desc;
	pthread_setname_np(pthread_self(), "comp_thread");

	log_debug("Starting compaction from level's tree [%u][%u] to level's tree[%u][%u]", comp_req->src_level,
		  comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree);
	/*Initialize a scan object*/
	handle.db_desc = compaction_get_db_desc(comp_req);
	handle.volume_desc = compaction_get_volume_desc(comp_req);
	memcpy(&handle.db_options, comp_req->db_options, sizeof(struct par_db_options));
	//old school
	// struct node_header *dst_root = level_get_root(handle.db_desc->dev_levels[comp_req->dst_level], 0);

	if (comp_req->src_level == 0 || comp_req->dst_level == handle.db_desc->level_medium_inplace ||
	    !level_is_empty(handle.db_desc->dev_levels[comp_req->dst_level], 0))
		compact_level_direct_IO(&handle, comp_req);
	else
		compact_with_empty_destination_level(comp_req);

	log_debug("DONE Compaction from level's tree [%u][%u] to level's tree[%u][%u] "
		  "cleaning src level",
		  comp_req->src_level, comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree);
	if (0 == comp_req->src_level)
		bt_set_db_status(db_desc, BT_NO_COMPACTION, comp_req->src_level, comp_req->src_tree);
	else
		level_set_compaction_done(db_desc->dev_levels[comp_req->src_level]);

	level_set_compaction_done(db_desc->dev_levels[comp_req->dst_level]);

	if (comp_req->src_level == 0)
		/*wake up clients*/
		compactiond_notify_all(comp_req->db_desc->compactiond);

	compactiond_interrupt(comp_req->db_desc->compactiond);
	free(comp_req);
	return NULL;
}

void compaction_close(struct compaction_request *comp_req)
{
	assert(comp_req);

	struct device_level *dest_level = comp_req->db_desc->dev_levels[comp_req->dst_level];

	struct db_handle hd = { .db_desc = compaction_get_db_desc(comp_req),
				.volume_desc = compaction_get_volume_desc(comp_req) };

	lock_to_update_levels_after_compaction(comp_req);
	if (comp_req->db_options->options[PRIMARY_MODE].value) {
		/*TODO: closing compaction callback*/
		parallax_callbacks_t par_callbacks = comp_req->db_desc->parallax_callbacks;
		if (are_parallax_callbacks_set(par_callbacks)) {
			struct parallax_callback_funcs par_cb = parallax_get_callbacks(par_callbacks);
			void *context = parallax_get_context(par_callbacks);
			(void)context;
			// assert(level_get_index_first_seg(hd.db_desc->dev_levels[comp_req->dst_level], 1));
			// assert(level_get_index_last_seg(hd.db_desc->dev_levels[comp_req->dst_level], 1));
			if (par_cb.compaction_ended_cb) {
				// uint64_t first = ABSOLUTE_ADDRESS(
				// 	level_get_index_first_seg(hd.db_desc->dev_levels[comp_req->dst_level], 1));
				// uint64_t last = ABSOLUTE_ADDRESS(
				// 	level_get_index_last_seg(hd.db_desc->dev_levels[comp_req->dst_level], 1));
				// uint64_t root = ABSOLUTE_ADDRESS(
				// 	level_get_root(hd.db_desc->dev_levels[comp_req->dst_level], 1));
				// par_cb.compaction_ended_cb(context, comp_req->src_level, first, last, root);
			}
		}
	}

	uint64_t space_freed = 0;
	/*Free L_(i+1)*/
	if (comp_req->dst_scanner)
		level_free_space(comp_req->db_desc->dev_levels[comp_req->dst_level], 0, comp_req->db_desc,
				 comp_req->txn_id);
	/*Free and zero L_i*/
	// uint64_t txn_id = comp_req->db_desc->levels[comp_req->dst_level].allocation_txn_id[comp_req->dst_tree];
	//new level
	space_freed = 0 == comp_req->src_level ?
			      seg_free_L0(hd.db_desc, compaction_get_src_tree(comp_req)) :
			      level_free_space(comp_req->db_desc->dev_levels[comp_req->src_level], comp_req->src_tree,
					       comp_req->db_desc, comp_req->txn_id);
	(void)space_freed;
	log_debug("Freed space %lu MB from DB:%s source level %u", space_freed / (1024 * 1024L),
		  comp_req->db_desc->db_superblock->db_name, comp_req->src_level);
	comp_zero_level(hd.db_desc, comp_req->src_level, comp_req->src_tree);

	/*Finally persist compaction */
	pr_flush_compaction(comp_req->db_desc, comp_req->db_options, comp_req->dst_level, comp_req->dst_tree,
			    comp_req->txn_id);

	if (comp_req->src_level > 0)
		level_destroy_bf(comp_req->db_desc->dev_levels[comp_req->src_level], 0);

	level_destroy_bf(comp_req->db_desc->dev_levels[comp_req->dst_level], 0);

	level_swap(dest_level, 0, dest_level, 1);

	unlock_to_update_levels_after_compaction(comp_req);
}

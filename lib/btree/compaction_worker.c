#define _GNU_SOURCE
#include "compaction_worker.h"
#include "../allocator/redo_undo_log.h"
#include "../lib/allocator/device_structures.h"
#include "../utilities/dups_list.h"
#include "../utilities/spin_loop.h"
#include "gc.h"
#include "level_read_cursor.h"
#include "level_write_cursor.h"
#include "medium_log_LRU_cache.h"
#include "segment_allocator.h"
#include "uthash.h"
#include <assert.h>
#include <log.h>
#include <pthread.h>

struct compaction_roots {
	struct node_header *src_root;
	struct node_header *dst_root;
};

static void choose_compaction_roots(struct db_handle *handle, struct compaction_request *comp_req,
				    struct compaction_roots *comp_roots)
{
	comp_roots->src_root = handle->db_desc->levels[comp_req->src_level].root_r[comp_req->src_tree];
	if (handle->db_desc->levels[comp_req->src_level].root_w[comp_req->src_tree] != NULL)
		comp_roots->src_root = handle->db_desc->levels[comp_req->src_level].root_w[comp_req->src_tree];

	if (!comp_roots->src_root) {
		log_fatal("NULL src root for compaction from level's tree [%u][%u] to "
			  "level's tree[%u][%u] for db %s",
			  comp_req->src_level, comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree,
			  handle->db_desc->db_superblock->db_name);
		BUG_ON();
	}

	comp_roots->dst_root = handle->db_desc->levels[comp_req->dst_level].root_r[0];
	if (handle->db_desc->levels[comp_req->dst_level].root_w[0] != NULL)
		comp_roots->dst_root = handle->db_desc->levels[comp_req->dst_level].root_w[0];
}

static void comp_fill_parallax_key(struct sh_heap_node *h_node, struct comp_parallax_key *curr_key)
{
	curr_key->kv_category = h_node->cat;
	curr_key->tombstone = h_node->tombstone;
	assert(h_node->KV);
	switch (h_node->cat) {
	case SMALL_INPLACE:
	case MEDIUM_INPLACE:
		curr_key->kv_in_place = (struct kv_splice *)h_node->KV;
		curr_key->kv_type = KV_INPLACE;
		break;
	case BIG_INLOG:
	case MEDIUM_INLOG:
		curr_key->kv_inlog = *(struct kv_seperation_splice *)h_node->KV;
		curr_key->kv_type = KV_INLOG;
		break;
	default:
		log_info("Unhandle/Unknown category");
		BUG_ON();
	}
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

static void mark_segment_space(db_handle *handle, struct dups_list *list, uint8_t level_id, uint8_t tree_id)
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
		uint64_t txn_id = handle->db_desc->levels[level_id].allocation_txn_id[tree_id];
		struct rul_log_entry entry = { .dev_offt = persist_blob_metadata->dev_offt,
					       .txn_id = txn_id,
					       .op_type = BLOB_GARBAGE_BYTES,
					       .blob_garbage_bytes = persist_blob_metadata->kv_size };
		rul_add_entry_in_txn_buf(handle->db_desc, &entry);
	}
}

static void comp_medium_log_set_max_segment_id(struct WCURSOR_level_write_cursor *c)
{
	uint64_t max_segment_id = 0;
	uint64_t max_segment_offt = 0;

	struct medium_log_segment_map *current_entry = NULL;
	struct medium_log_segment_map *tmp = NULL;
	HASH_ITER(hh, c->medium_log_segment_map, current_entry, tmp)
	{
		/* Suprresses possible null pointer dereference of cppcheck*/
		assert(current_entry);
		uint64_t segment_id = current_entry->id;
		if (UINT64_MAX == segment_id) {
			struct segment_header *segment = REAL_ADDRESS(current_entry->dev_offt);
			segment_id = segment->segment_id;
		}

		// cppcheck-suppress unsignedPositive
		if (segment_id >= max_segment_id) {
			max_segment_id = segment_id;
			max_segment_offt = current_entry->dev_offt;
		}
		HASH_DEL(c->medium_log_segment_map, current_entry);
		free(current_entry);
	}
	struct level_descriptor *level_desc = &c->handle->db_desc->levels[c->level_id];
	level_desc->medium_in_place_max_segment_id = max_segment_id;
	level_desc->medium_in_place_segment_dev_offt = max_segment_offt;
	log_debug("Max segment id touched during medium transfer to in place is %lu and corresponding offt: %lu",
		  max_segment_id, max_segment_offt);
}

static void lock_to_update_levels_after_compaction(struct compaction_request *comp_req)
{
	if (RWLOCK_WRLOCK(&(comp_req->db_desc->levels[comp_req->src_level].guard_of_level.rx_lock))) {
		log_fatal("Failed to acquire guard lock");
		BUG_ON();
	}

	if (RWLOCK_WRLOCK(&(comp_req->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock))) {
		log_fatal("Failed to acquire guard lock");
		BUG_ON();
	}
	spin_loop(&comp_req->db_desc->levels[comp_req->src_level].active_operations, 0);
	spin_loop(&comp_req->db_desc->levels[comp_req->dst_level].active_operations, 0);
}

static void unlock_to_update_levels_after_compaction(struct compaction_request *comp_req)
{
	if (RWLOCK_UNLOCK(&(comp_req->db_desc->levels[comp_req->src_level].guard_of_level.rx_lock))) {
		log_fatal("Failed to acquire guard lock");
		BUG_ON();
	}

	if (RWLOCK_UNLOCK(&(comp_req->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock))) {
		log_fatal("Failed to acquire guard lock");
		BUG_ON();
	}
}

static void compact_level_direct_IO(struct db_handle *handle, struct compaction_request *comp_req)
{
	struct compaction_roots comp_roots = { .src_root = NULL, .dst_root = NULL };

	choose_compaction_roots(handle, comp_req, &comp_roots);

	assert(0 == handle->db_desc->levels[comp_req->dst_level].offset[comp_req->dst_tree]);
	struct RCURSOR_level_read_cursor *src_rcursor = NULL;
	if (comp_req->src_level == 0) {
		RWLOCK_WRLOCK(&handle->db_desc->levels[0].guard_of_level.rx_lock);
		spin_loop(&handle->db_desc->levels[0].active_operations, 0);
		pr_flush_log_tail(comp_req->db_desc, &comp_req->db_desc->big_log);
	}

	assert(0 == handle->db_desc->levels[comp_req->dst_level].offset[comp_req->dst_tree]);
	src_rcursor = RCURSOR_init_cursor(handle, comp_req->src_level, comp_req->src_tree,
					  handle->db_desc->db_volume->vol_fd);

	if (0 == comp_req->src_level)
		RWLOCK_UNLOCK(&handle->db_desc->levels[0].guard_of_level.rx_lock);

	struct RCURSOR_level_read_cursor *dst_rcursor =
		NULL == comp_roots.dst_root ?
			NULL :
			RCURSOR_init_cursor(handle, comp_req->dst_level, 0, comp_req->volume_desc->vol_fd);
	assert(0 == handle->db_desc->levels[comp_req->dst_level].offset[comp_req->dst_tree]);

	log_debug("Initializing write cursor for level [%u][%u]", comp_req->dst_level, comp_req->dst_tree);
	struct WCURSOR_level_write_cursor *new_level = WCURSOR_init_write_cursor(
		comp_req->dst_level, handle, comp_req->dst_tree, handle->db_desc->db_volume->vol_fd);

	//initialize LRU cache for storing chunks of segments when medium log goes in place
	if (new_level->level_id == handle->db_desc->level_medium_inplace)
		new_level->medium_log_LRU_cache = init_LRU(handle);

	log_debug("Src [%u][%u] size = %lu", comp_req->src_level, comp_req->src_tree,
		  handle->db_desc->levels[comp_req->src_level].level_size[comp_req->src_tree]);

	NULL == comp_roots.dst_root ? log_debug("Empty dst [%u]", comp_req->dst_level) :
				      log_debug("Dst [%u][%u] size = %lu", comp_req->dst_level, 0,
						handle->db_desc->levels[comp_req->dst_level].level_size[0]);

	// initialize and fill min_heap properly
	struct sh_heap *m_heap = sh_alloc_heap();
	sh_init_heap(m_heap, comp_req->src_level, MIN_HEAP);
	struct sh_heap_node src_heap_node = {
		.KV = NULL, .level_id = 0, .active_tree = 0, .duplicate = 0, .type = KV_PREFIX
	};
	struct sh_heap_node dst_heap_node = {
		.KV = NULL, .level_id = 0, .active_tree = 0, .duplicate = 0, .type = KV_PREFIX
	};
	struct sh_heap_node min_heap_node = {
		.KV = NULL, .level_id = 0, .active_tree = 0, .duplicate = 0, .type = KV_PREFIX
	};
	// init Li cursor
	WCURSOR_fill_heap_node(src_rcursor, &src_heap_node);
	sh_insert_heap_node(m_heap, &src_heap_node);

	// init Li+1 cursor (if any)
	if (dst_rcursor) {
		WCURSOR_fill_heap_node(dst_rcursor, &dst_heap_node);
		sh_insert_heap_node(m_heap, &dst_heap_node);
	}

	while (1) {
		handle->db_desc->dirty = 0x01;
		// This is to synchronize compactions with flush
		RWLOCK_RDLOCK(&handle->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock);

		if (!sh_remove_top(m_heap, &min_heap_node)) {
			RWLOCK_UNLOCK(&handle->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock);
			break;
		}

		if (!min_heap_node.duplicate) {
			struct comp_parallax_key key = { 0 };
			comp_fill_parallax_key(&min_heap_node, &key);
			WCURSOR_append_entry_to_leaf_node(new_level, &key);
		}

		/*refill from the appropriate level*/
		if (min_heap_node.level_id == comp_req->src_level && RCURSOR_get_next_kv(src_rcursor)) {
			WCURSOR_fill_heap_node(src_rcursor, &src_heap_node);
			sh_insert_heap_node(m_heap, &src_heap_node);
		} else if (dst_rcursor && min_heap_node.level_id == comp_req->dst_level &&
			   RCURSOR_get_next_kv(dst_rcursor)) {
			WCURSOR_fill_heap_node(dst_rcursor, &dst_heap_node);
			sh_insert_heap_node(m_heap, &dst_heap_node);
		}

		RWLOCK_UNLOCK(&handle->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock);
	}

	RCURSOR_close_cursor(src_rcursor);
	RCURSOR_close_cursor(dst_rcursor);

	mark_segment_space(handle, m_heap->dups, comp_req->dst_level, 1);

	sh_destroy_heap(m_heap);
	WCURSOR_flush_write_cursor(new_level);
	assert(new_level->root_offt);

	new_level->handle->db_desc->levels[comp_req->dst_level].root_w[1] =
		(struct node_header *)REAL_ADDRESS(new_level->root_offt);
	assert(new_level->handle->db_desc->levels[comp_req->dst_level].root_w[1]->type == rootNode);

	if (new_level->level_id == handle->db_desc->level_medium_inplace) {
		comp_medium_log_set_max_segment_id(new_level);
		destroy_LRU(new_level->medium_log_LRU_cache);
	}

	/***************************************************************/
	struct level_descriptor *ld = &comp_req->db_desc->levels[comp_req->dst_level];
	struct db_handle hd = { .db_desc = comp_req->db_desc, .volume_desc = comp_req->volume_desc };

	lock_to_update_levels_after_compaction(comp_req);

	uint64_t space_freed = 0;
	/*Free L_(i+1)*/
	if (dst_rcursor) {
		uint64_t txn_id = comp_req->db_desc->levels[comp_req->dst_level].allocation_txn_id[comp_req->dst_tree];
		/*free dst (L_i+1) level*/
		space_freed = seg_free_level(comp_req->db_desc, txn_id, comp_req->dst_level, 0);

		log_debug("Freed space %lu MB from db:%s destination level %u", space_freed / (1024 * 1024L),
			  comp_req->db_desc->db_superblock->db_name, comp_req->dst_level);
	}
	/*Free and zero L_i*/
	uint64_t txn_id = comp_req->db_desc->levels[comp_req->dst_level].allocation_txn_id[comp_req->dst_tree];
	space_freed = seg_free_level(hd.db_desc, txn_id, comp_req->src_level, comp_req->src_tree);
	log_debug("Freed space %lu MB from db:%s source level %u", space_freed / (1024 * 1024L),
		  comp_req->db_desc->db_superblock->db_name, comp_req->src_level);
	seg_zero_level(hd.db_desc, comp_req->src_level, comp_req->src_tree);

#if ENABLE_BLOOM_FILTERS
	if (dst_root) {
		log_debug("Freeing previous bloom filter for dst level %u", comp_req->dst_level);
		bloom_free(&handle.db_desc->levels[comp_req->src_level].bloom_filter[0]);
	}
	ld->bloom_filter[0] = ld->bloom_filter[1];
	memset(&ld->bloom_filter[1], 0x00, sizeof(struct bloom));
#endif

	/*Finally persist compaction */
	pr_flush_compaction(comp_req->db_desc, comp_req->dst_level, comp_req->dst_tree);
	log_debug("Flushed compaction[%u][%u] successfully", comp_req->dst_level, comp_req->dst_tree);
	/*set L'_(i+1) as L_(i+1)*/
	ld->first_segment[0] = ld->first_segment[1];
	ld->first_segment[1] = NULL;
	ld->last_segment[0] = ld->last_segment[1];
	ld->last_segment[1] = NULL;
	ld->offset[0] = ld->offset[1];
	ld->offset[1] = 0;

	if (ld->root_w[1] != NULL)
		ld->root_r[0] = ld->root_w[1];
	else if (ld->root_r[1] != NULL)
		ld->root_r[0] = ld->root_r[1];
	else {
		log_fatal("Where is the root?");
		BUG_ON();
	}

	ld->root_w[0] = NULL;
	ld->level_size[0] = ld->level_size[1];
	ld->level_size[1] = 0;
	ld->root_w[1] = NULL;
	ld->root_r[1] = NULL;

	unlock_to_update_levels_after_compaction(comp_req);

	WCURSOR_close_write_cursor(new_level);
}

static void swap_levels(struct level_descriptor *src, struct level_descriptor *dst, int src_active_tree,
			int dst_active_tree)
{
	dst->first_segment[dst_active_tree] = src->first_segment[src_active_tree];
	src->first_segment[src_active_tree] = NULL;

	dst->last_segment[dst_active_tree] = src->last_segment[src_active_tree];
	src->last_segment[src_active_tree] = NULL;

	dst->offset[dst_active_tree] = src->offset[src_active_tree];
	src->offset[src_active_tree] = 0;

	dst->level_size[dst_active_tree] = src->level_size[src_active_tree];
	src->level_size[src_active_tree] = 0;

	while (!__sync_bool_compare_and_swap(&dst->root_w[dst_active_tree], dst->root_w[dst_active_tree],
					     src->root_w[src_active_tree])) {
	}
	// dst->root_w[dst_active_tree] = src->root_w[src_active_tree];
	src->root_w[src_active_tree] = NULL;

	while (!__sync_bool_compare_and_swap(&dst->root_r[dst_active_tree], dst->root_r[dst_active_tree],
					     src->root_r[src_active_tree])) {
	}
	// dst->root_r[dst_active_tree] = src->root_r[src_active_tree];
	src->root_r[src_active_tree] = NULL;
}

static void compact_with_empty_destination_level(struct compaction_request *comp_req)
{
	log_debug("Empty level %d time for an optimization :-)", comp_req->dst_level);

	lock_to_update_levels_after_compaction(comp_req);

	struct level_descriptor *leveld_src = &comp_req->db_desc->levels[comp_req->src_level];
	struct level_descriptor *leveld_dst = &comp_req->db_desc->levels[comp_req->dst_level];

	swap_levels(leveld_src, leveld_dst, comp_req->src_tree, 1);

	pr_flush_compaction(comp_req->db_desc, comp_req->dst_level, comp_req->dst_tree);
	swap_levels(leveld_dst, leveld_dst, 1, 0);
	log_debug("Flushed compaction (Swap levels) successfully from src[%u][%u] to dst[%u][%u]", comp_req->src_level,
		  comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree);

#if ENABLE_BLOOM_FILTERS
	log_info("Swapping also bloom filter");
	leveld_dst->bloom_filter[0] = leveld_src->bloom_filter[0];
	memset(&leveld_src->bloom_filter[0], 0x00, sizeof(struct bloom));
#endif
	unlock_to_update_levels_after_compaction(comp_req);

	log_debug("Swapped levels %d to %d successfully", comp_req->src_level, comp_req->dst_level);
	log_debug("After swapping src tree[%d][%d] size is %lu", comp_req->src_level, 0, leveld_src->level_size[0]);
	log_debug("After swapping dst tree[%d][%d] size is %lu", comp_req->dst_level, 0, leveld_dst->level_size[0]);
	assert(leveld_dst->first_segment != NULL);
}

void *compaction(void *compaction_request)
{
	db_handle handle;
	struct compaction_request *comp_req = (struct compaction_request *)compaction_request;
	db_descriptor *db_desc = comp_req->db_desc;
	pthread_setname_np(pthread_self(), "comp_thread");

	log_debug("starting compaction from level's tree [%u][%u] to level's tree[%u][%u]", comp_req->src_level,
		  comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree);
	/*Initialize a scan object*/
	handle.db_desc = comp_req->db_desc;
	handle.volume_desc = comp_req->volume_desc;
	memcpy(&handle.db_options, comp_req->db_options, sizeof(struct par_db_options));
	// optimization check if level below is empty
	struct node_header *dst_root = NULL;
	if (handle.db_desc->levels[comp_req->dst_level].root_w[0] != NULL)
		dst_root = handle.db_desc->levels[comp_req->dst_level].root_w[0];
	else if (handle.db_desc->levels[comp_req->dst_level].root_r[0] != NULL)
		dst_root = handle.db_desc->levels[comp_req->dst_level].root_r[0];
	else {
		dst_root = NULL;
	}

	if (comp_req->src_level == 0 || comp_req->dst_level == handle.db_desc->level_medium_inplace || dst_root)
		compact_level_direct_IO(&handle, comp_req);
	else
		compact_with_empty_destination_level(comp_req);

	log_debug("DONE Compaction from level's tree [%u][%u] to level's tree[%u][%u] "
		  "cleaning src level",
		  comp_req->src_level, comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree);

	db_desc->levels[comp_req->src_level].tree_status[comp_req->src_tree] = NO_COMPACTION;
	db_desc->levels[comp_req->dst_level].tree_status[0] = NO_COMPACTION;

	/*wake up clients*/
	if (comp_req->src_level == 0) {
		log_debug("src level %d dst level %d src_tree %d dst_tree %d", comp_req->src_level, comp_req->dst_level,
			  comp_req->src_tree, comp_req->dst_tree);
		MUTEX_LOCK(&comp_req->db_desc->client_barrier_lock);
		if (pthread_cond_broadcast(&db_desc->client_barrier) != 0) {
			log_fatal("Failed to wake up stopped clients");
			BUG_ON();
		}
	}
	MUTEX_UNLOCK(&db_desc->client_barrier_lock);
	sem_post(&db_desc->compaction_daemon_interrupts);
	free(comp_req);
	return NULL;
}

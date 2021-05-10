#define _GNU_SOURCE
#define COMPACTION
#include <semaphore.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>
#include <log.h>
#include <spin_loop.h>
#include "btree.h"
#include "gc.h"
#include "segment_allocator.h"
#include "conf.h"
#include "../scanner/scanner.h"
#include "../scanner/min_max_heap.h"
#include "../allocator/allocator.h"
#include "../../utilities/dups_list.h"

#define COMPACTION_UNIT_OF_WORK 131072

/* Checks for pending compactions. It is responsible to check for dependencies
 * between two levels before triggering a compaction. */
extern sem_t gc_daemon_interrupts;
#if 0
static void prepare_kvs_forgc(db_handle *handle, struct sh_min_heap *heap)
{
	for (int i = 0; i < heap->dup_array_entries; ++i) {
		char *pointer_inlog =
			(char *)ABSOLUTE_ADDRESS(*(uint64_t *)(heap->duplicate_large_kvs[i].KV + PREFIX_SIZE));
		insert_key_value(handle->db_desc->gc_db, pointer_inlog, "1", sizeof(uint64_t), 2);
	}
}
#endif
struct compaction_request {
	db_descriptor *db_desc;
	volume_descriptor *volume_desc;
	uint64_t l0_start;
	uint64_t l0_end;
	uint8_t src_level;
	uint8_t src_tree;
	uint8_t dst_level;
	uint8_t dst_tree;
};

void mark_segment_space(db_handle *handle, struct dups_list *list)
{
	struct gc_value gc_value;
	struct dups_node *list_iter;
	struct segment_header *segment;
	uint64_t segment_dev_offt;

	for (list_iter = list->head; list_iter; list_iter = list_iter->next) {
		segment = (struct segment_header *)list_iter->dev_offset;
		segment_dev_offt = ABSOLUTE_ADDRESS(list_iter->dev_offset);
		__sync_add_and_fetch(&segment->segment_garbage_bytes, list_iter->kv_size);

		if ((double)segment->segment_garbage_bytes >=
		    ((double)segment->segment_garbage_bytes) * GC_SEGMENT_THRESHOLD) {
			char *found = find_key(handle->db_desc->gc_db, &segment_dev_offt, sizeof(segment_dev_offt));
			gc_value.group_id = handle->db_desc->group_id;
			gc_value.index = handle->db_desc->group_index;
			gc_value.moved = segment->moved_kvs;

			if (!found || !segment->moved_kvs)
				insert_key_value(handle->db_desc->gc_db, &segment_dev_offt, &gc_value,
						 sizeof(segment_dev_offt), sizeof(gc_value));
		}

		assert(segment->segment_garbage_bytes < (SEGMENT_SIZE - sizeof(struct segment_header)));
	}
}

#ifdef COMPACTION
static void *compaction(void *_comp_req);
#else
static void *spill_buffer(void *_comp_req);
#endif

void *compaction_daemon(void *args)
{
	struct db_handle *handle = (struct db_handle *)args;
	struct db_descriptor *db_desc = handle->db_desc;
	struct compaction_request *comp_req = NULL;
	pthread_setname_np(pthread_self(), "compactiond");

	int next_L0_tree_to_compact = 0;
	while (1) {
		/*special care for Level 0 to 1*/
		sem_wait(&db_desc->compaction_daemon_interrupts);
		struct level_descriptor *level_0 = &handle->db_desc->levels[0];
		struct level_descriptor *level_1 = &handle->db_desc->levels[1];

		int L0_tree = next_L0_tree_to_compact;
		// is level-0 full and not already spilling?
		if (level_0->tree_status[L0_tree] == NO_SPILLING &&
		    level_0->level_size[L0_tree] >= level_0->max_level_size) {
			// Can I issue a spill to L1?
			int L1_tree = 0;
			if (level_1->tree_status[L1_tree] == NO_SPILLING &&
			    level_1->level_size[L1_tree] < level_1->max_level_size) {
				/*mark them as spilling L0*/
				level_0->tree_status[L0_tree] = SPILLING_IN_PROGRESS;
				/*mark them as spilling L1*/
				level_1->tree_status[L1_tree] = SPILLING_IN_PROGRESS;

				/*start a compaction*/
				comp_req = (struct compaction_request *)calloc(1, sizeof(struct compaction_request));
				assert(comp_req);
				comp_req->db_desc = handle->db_desc;
				comp_req->volume_desc = handle->volume_desc;
				comp_req->src_level = 0;
				comp_req->src_tree = L0_tree;
				comp_req->dst_level = 1;
#ifdef COMPACTION
				comp_req->dst_tree = 1;
#else
				comp_req->dst_tree = 0;
#endif
				if (++next_L0_tree_to_compact >= NUM_TREES_PER_LEVEL)
					next_L0_tree_to_compact = 0;
			}
		}
		/*can I set a different active tree for L0*/
		int active_tree = db_desc->levels[0].active_tree;
		if (db_desc->levels[0].tree_status[active_tree] == SPILLING_IN_PROGRESS) {
			/* for (int i = 0; i < NUM_TREES_PER_LEVEL; i++) { */
			int next_active_tree = active_tree != (NUM_TREES_PER_LEVEL - 1) ? active_tree + 1 : 0;
			if (db_desc->levels[0].tree_status[next_active_tree] == NO_SPILLING) {
				/*Acquire guard lock and wait writers to finish*/
				if (RWLOCK_WRLOCK(&(handle->db_desc->levels[0].guard_of_level.rx_lock))) {
					log_fatal("Failed to acquire guard lock");
					exit(EXIT_FAILURE);
				}

				spin_loop(&(handle->db_desc->levels[0].active_writers), 0);
				/*done now atomically change active tree*/
				db_desc->levels[0].active_tree = next_active_tree;
				log_info("next active tree %d", next_active_tree);
				/*Release guard lock*/
				if (RWLOCK_UNLOCK(&handle->db_desc->levels[0].guard_of_level.rx_lock)) {
					log_fatal("Failed to acquire guard lock");
					exit(EXIT_FAILURE);
				}

				MUTEX_LOCK(&db_desc->client_barrier_lock);
				if (pthread_cond_broadcast(&db_desc->client_barrier) != 0) {
					log_fatal("Failed to wake up stopped clients");
					exit(EXIT_FAILURE);
				}
				MUTEX_UNLOCK(&db_desc->client_barrier_lock);
			}
			/* } */
		}

		/*Now fire up (if needed) the spill/compaction from L0 to L1*/
		if (comp_req) {
#ifdef COMPACTION
			comp_req->dst_tree = 1;
			assert(db_desc->levels[0].root_w[comp_req->src_tree] != NULL ||
			       db_desc->levels[0].root_r[comp_req->src_tree] != NULL);
			if (pthread_create(&db_desc->levels[0].compaction_thread[comp_req->src_tree], NULL, compaction,
					   comp_req) != 0) {
				log_fatal("Failed to start compaction");
				exit(EXIT_FAILURE);
			}
#else
			comp_req->dst_tree = 0;
			if (pthread_create(&db_desc->levels[0].compaction_thread[comp_req->src_tree], NULL,
					   spill_buffer, comp_req) != 0) {
				log_fatal("Failed to start compaction");
				exit(EXIT_FAILURE);
			}
#endif
			comp_req = NULL;
		}

		// rest of levels
		for (int level_id = 1; level_id < MAX_LEVELS - 1; ++level_id) {
			level_1 = &handle->db_desc->levels[level_id];
			struct level_descriptor *level_2 = &handle->db_desc->levels[level_id + 1];
			uint8_t tree_1 = 0; // level_1->active_tree;
			uint8_t tree_2 = 0; // level_2->active_tree;

			if (level_1->tree_status[tree_1] == NO_SPILLING &&
			    level_1->level_size[tree_1] >= level_1->max_level_size) {
				if (level_2->tree_status[tree_2] == NO_SPILLING &&
				    level_2->level_size[tree_2] < level_2->max_level_size) {
					level_1->tree_status[tree_1] = SPILLING_IN_PROGRESS;
					level_2->tree_status[tree_2] = SPILLING_IN_PROGRESS;
					/*start a compaction*/
					struct compaction_request *comp_req_p =
						(struct compaction_request *)malloc(sizeof(struct compaction_request));
					assert(comp_req_p);
					comp_req_p->db_desc = handle->db_desc;
					comp_req_p->volume_desc = handle->volume_desc;
					comp_req_p->src_level = level_id;
					comp_req_p->src_tree = tree_1;
					comp_req_p->dst_level = level_id + 1;

#ifdef COMPACTION
					comp_req_p->dst_tree = 1;
					assert(db_desc->levels[level_id].root_w[0] != NULL ||
					       db_desc->levels[level_id].root_r[0] != NULL);
					if (pthread_create(&db_desc->levels[0].compaction_thread[tree_1], NULL,
							   compaction, comp_req_p) != 0) {
						log_fatal("Failed to start compaction");
						exit(EXIT_FAILURE);
					}
#else
					comp_req_p->dst_tree = 0;
					if (pthread_create(&db_desc->levels[level_id].compaction_thread[tree_1], NULL,
							   spill_buffer, comp_req_p) != 0) {
						log_fatal("Failed to start compaction");
						exit(EXIT_FAILURE);
					}
#endif
				}
			}
		}
	}
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

	return;
}

#ifdef COMPACTION

static void compact_level_mmap_IO(struct db_handle *handle, struct compaction_request *comp_req)
{
#if ENABLE_BLOOM_FILTERS
	// allocate new bloom filter
	uint64_t capacity = handle.db_desc->levels[comp_req->dst_level].max_level_size;
	if (bloom_init(&handle.db_desc->levels[comp_req->dst_level].bloom_filter[1], capacity, 0.01)) {
		log_fatal("Failed to init bloom");
		assert(0);
		exit(EXIT_FAILURE);
	} else
		log_info("Allocated bloom filter for dst level %u capacity in keys %llu", comp_req->dst_level,
			 capacity);
#endif
	struct node_header *src_root = NULL;
	if (handle->db_desc->levels[comp_req->src_level].root_w[comp_req->src_tree] != NULL)
		src_root = handle->db_desc->levels[comp_req->src_level].root_w[comp_req->src_tree];
	else if (handle->db_desc->levels[comp_req->src_level].root_r[comp_req->src_tree] != NULL)
		src_root = handle->db_desc->levels[comp_req->src_level].root_r[comp_req->src_tree];
	else {
		log_fatal("NULL src root for compaction from level's tree [%u][%u] to "
			  "level's tree[%u][%u] for db %s",
			  comp_req->src_level, comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree,
			  handle->db_desc->db_name);
		exit(EXIT_FAILURE);
	}

	struct node_header *dst_root = NULL;
	if (handle->db_desc->levels[comp_req->dst_level].root_w[0] != NULL)
		dst_root = handle->db_desc->levels[comp_req->dst_level].root_w[0];
	else if (handle->db_desc->levels[comp_req->dst_level].root_r[0] != NULL)
		dst_root = handle->db_desc->levels[comp_req->dst_level].root_r[0];
	else {
		dst_root = NULL;
	}
	struct level_scanner *level_src = _init_spill_buffer_scanner(handle, comp_req->src_level, src_root, NULL);

	struct level_scanner *level_dst = NULL;
	if (dst_root)
		level_dst = _init_spill_buffer_scanner(handle, comp_req->dst_level, dst_root, NULL);

	struct db_descriptor *db_desc = handle->db_desc;
	log_info("Src [%u][%u] size = %llu", comp_req->src_level, comp_req->src_tree,
		 db_desc->levels[comp_req->src_level].level_size[comp_req->src_tree]);

	log_info("Dst [%u][%u] size = %llu", comp_req->dst_level, 0,
		 db_desc->levels[comp_req->dst_level].level_size[0]);

	if (!level_src) {
		log_fatal("Failed to create pair of spill buffer scanners for level's "
			  "tree[%u][%u]",
			  comp_req->src_level, comp_req->src_tree);
		exit(EXIT_FAILURE);
	}
	struct sh_min_heap *m_heap = sh_alloc_heap();
	/* 	(struct sh_min_heap *)malloc(sizeof(struct sh_min_heap)); */
	/* sh_init_heap(m_heap, comp_req->src_level); */
	struct sh_heap_node nd_src = { .KV = NULL, .level_id = 0, .active_tree = 0, .duplicate = 0, .type = KV_PREFIX };
	struct sh_heap_node nd_dst = { .KV = NULL, .level_id = 0, .active_tree = 0, .duplicate = 0, .type = KV_PREFIX };
	struct sh_heap_node nd_min = { .KV = NULL, .level_id = 0, .active_tree = 0, .duplicate = 0, .type = KV_PREFIX };

	//initialize and fill min_heap properly
	sh_init_heap(m_heap, comp_req->src_level);

	nd_src.KV = level_src->keyValue;
	nd_src.level_id = comp_req->src_level;
	nd_src.type = level_src->kv_format;
	nd_src.cat = level_src->cat;
	nd_src.kv_size = level_src->kv_size;
	nd_src.active_tree = comp_req->src_tree;
	sh_insert_heap_node(m_heap, &nd_src);

	if (level_dst) {
		nd_dst.KV = level_dst->keyValue;
		nd_dst.level_id = comp_req->dst_level;
		nd_dst.type = level_dst->kv_format;
		nd_dst.cat = level_dst->cat;
		nd_dst.kv_size = level_dst->kv_size;
		nd_dst.active_tree = comp_req->dst_tree;
		sh_insert_heap_node(m_heap, &nd_dst);
	}

	struct bt_insert_req ins_req;
	int c_exit = 0;
	do {
		for (int i = 0; i < COMPACTION_UNIT_OF_WORK; ++i) {
			db_desc->dirty = 0x01;
			ins_req.metadata.handle = handle;

			ins_req.metadata.special_split = 1;
			ins_req.metadata.gc_request = 0;
			ins_req.metadata.recovery_request = 0;

			enum sh_heap_status stat = sh_remove_min(m_heap, &nd_min);
			if (stat == EMPTY_MIN_HEAP) {
				c_exit = 1;
				break;
			}
			ins_req.key_value_buf = nd_min.KV;
			ins_req.metadata.key_format = nd_min.type;
			ins_req.metadata.cat = nd_min.cat;
			ins_req.metadata.level_id = comp_req->dst_level;
			ins_req.metadata.tree_id = 1;

			if (comp_req->dst_level == LEVEL_MEDIUM_INPLACE && nd_min.cat == MEDIUM_INLOG) {
				ins_req.metadata.append_to_log = 0;
				int key_size = *(uint32_t *)*(uint64_t *)(nd_min.KV + PREFIX_SIZE);
				int value_size =
					*(uint32_t *)((char *)(*(uint64_t *)(nd_min.KV + PREFIX_SIZE)) + key_size + 4);
				ins_req.metadata.kv_size =
					key_size + value_size + sizeof(key_size) + sizeof(value_size);
			} else if (comp_req->dst_level == 1 && level_src->cat == MEDIUM_INPLACE) {
				ins_req.metadata.append_to_log = 1;
				ins_req.metadata.kv_size = nd_min.kv_size;
				ins_req.metadata.cat = MEDIUM_INLOG;
			} else {
				ins_req.metadata.append_to_log = 0;
				ins_req.metadata.kv_size = nd_min.kv_size;
			}

			assert(ins_req.metadata.key_format == KV_FORMAT || ins_req.metadata.key_format == KV_PREFIX);
			_insert_key_value(&ins_req);
#if ENABLE_BLOOM_FILTERS
			char *prefix;
			if (nd_min.cat == BIG_INLOG || nd_min.cat == MEDIUM_INLOG || nd_min.cat == SMALL_INLOG) {
				prefix = ins_req.key_value_buf;
				key_size = PREFIX_SIZE;
			} else {
				prefix = ins_req.key_value_buf + sizeof(uint32_t);
				key_size = *(uint32_t *)ins_req.key_value_buf;
			}
			int bloom_rc = bloom_add(
				&ins_req.metadata.handle->db_desc->levels[ins_req.metadata.level_id].bloom_filter[1],
				prefix, MIN(PREFIX_SIZE, key_size));
			if (0 != bloom_rc) {
				log_fatal("Failed to ins key in bloom filter");
				exit(EXIT_FAILURE);
			}
#endif
			//refill from the appropriate level
			struct level_scanner *curr_scanner = NULL;
			if (nd_min.level_id == comp_req->src_level)
				curr_scanner = level_src;
			else if (nd_min.level_id == comp_req->dst_level)
				curr_scanner = level_dst;
			else {
				log_fatal("Corruption unknown level to refill");
				exit(EXIT_FAILURE);
				return;
			}
			int rc = _get_next_KV(curr_scanner);
			if (rc != END_OF_DATABASE) {
				nd_min.KV = curr_scanner->keyValue;
				nd_min.type = curr_scanner->kv_format;
				nd_min.cat = curr_scanner->cat;
				nd_min.kv_size = curr_scanner->kv_size;
				nd_min.level_id = curr_scanner->level_id;
				sh_insert_heap_node(m_heap, &nd_min);
			} else
				c_exit = 1;
		}
	} while (!c_exit);

	_close_spill_buffer_scanner(level_src);
	if (dst_root)
		_close_spill_buffer_scanner(level_dst);

	struct level_descriptor *ld = &comp_req->db_desc->levels[comp_req->dst_level];
	struct db_handle hd = { .db_desc = comp_req->db_desc, .volume_desc = comp_req->volume_desc };

	if (RWLOCK_WRLOCK(&(comp_req->db_desc->levels[comp_req->src_level].guard_of_level.rx_lock))) {
		log_fatal("Failed to acquire guard lock");
		exit(EXIT_FAILURE);
	}

	if (RWLOCK_WRLOCK(&(comp_req->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock))) {
		log_fatal("Failed to acquire guard lock");
		exit(EXIT_FAILURE);
	}

	if (level_dst) {
		//free previous dst level
		struct segment_header *curr_segment = comp_req->db_desc->levels[comp_req->dst_level].first_segment[0];
		struct segment_header *next_segment;

		assert(curr_segment != NULL);
		uint64_t space_freed = 0;

		while (curr_segment != NULL) {
			/* log_info("TEST %llu %llu
       * %d",curr_segment->segment_id,curr_segment->next_segment,curr_segment->in_mem);
       */
			if (curr_segment->next_segment == NULL) {
				next_segment = NULL;
			} else {
				next_segment = MAPPED + curr_segment->next_segment;
			}

			if (curr_segment->in_mem == 0)
				free_block(comp_req->volume_desc, curr_segment, SEGMENT_SIZE);
			else
				free(curr_segment);

			space_freed += SEGMENT_SIZE;
			if (next_segment)
				curr_segment = next_segment;
			else
				break;
		}

		log_info("Freed space %llu MB from db:%s destination level %u", space_freed / (1024 * 1024),
			 comp_req->db_desc->db_name, comp_req->src_level);
	}
	//switch dst tree
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
		assert(0);
		exit(EXIT_FAILURE);
	}

	ld->root_w[0] = NULL;
	ld->level_size[0] = ld->level_size[1];
	ld->level_size[1] = 0;
	ld->root_w[1] = NULL;
	ld->root_r[1] = NULL;
	seg_free_level(&hd, comp_req->src_level, comp_req->src_tree);
#if ENABLE_BLOOM_FILTERS
	if (dst_root) {
		log_info("Freeing previous bloom filter for dst level %u", comp_req->dst_level);
		bloom_free(&handle.db_desc->levels[comp_req->src_level].bloom_filter[0]);
	}
	ld->bloom_filter[0] = ld->bloom_filter[1];
	memset(&ld->bloom_filter[1], 0x00, sizeof(struct bloom));
#endif

	if (RWLOCK_UNLOCK(&(comp_req->db_desc->levels[comp_req->src_level].guard_of_level.rx_lock))) {
		log_fatal("Failed to acquire guard lock");
		exit(EXIT_FAILURE);
	}

	if (RWLOCK_UNLOCK(&(comp_req->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock))) {
		log_fatal("Failed to acquire guard lock");
		exit(EXIT_FAILURE);
	}

	mark_segment_space(handle, m_heap->dups);
	sh_destroy_heap(m_heap);
}

void *compaction(void *_comp_req)
{
	db_handle handle;
	struct compaction_request *comp_req = (struct compaction_request *)_comp_req;
	db_descriptor *db_desc = comp_req->db_desc;
	pthread_setname_np(pthread_self(), "comp_thread");
	log_info("starting compaction from level's tree [%u][%u] to level's tree[%u][%u]", comp_req->src_level,
		 comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree);
	/*Initialize a scan object*/

	handle.db_desc = comp_req->db_desc;
	handle.volume_desc = comp_req->volume_desc;

	//optimization check if level below is empty
	struct node_header *dst_root = NULL;
	if (handle.db_desc->levels[comp_req->dst_level].root_w[0] != NULL)
		dst_root = handle.db_desc->levels[comp_req->dst_level].root_w[0];
	else if (handle.db_desc->levels[comp_req->dst_level].root_r[0] != NULL)
		dst_root = handle.db_desc->levels[comp_req->dst_level].root_r[0];
	else {
		dst_root = NULL;
	}

	if (comp_req->src_level == 0 || comp_req->dst_level == LEVEL_MEDIUM_INPLACE)
		compact_level_mmap_IO(&handle, comp_req);
	else if (dst_root) {
		compact_level_mmap_IO(&handle, comp_req);
	} else {
		log_info("Empty level %d time for an optimization :-)", comp_req->dst_level);

		if (RWLOCK_WRLOCK(&(comp_req->db_desc->levels[comp_req->src_level].guard_of_level.rx_lock))) {
			log_fatal("Failed to acquire guard lock");
			exit(EXIT_FAILURE);
		}

		if (RWLOCK_WRLOCK(&(comp_req->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock))) {
			log_fatal("Failed to acquire guard lock");
			exit(EXIT_FAILURE);
		}
		struct level_descriptor *leveld_src = &comp_req->db_desc->levels[comp_req->src_level];
		struct level_descriptor *leveld_dst = &comp_req->db_desc->levels[comp_req->dst_level];

		swap_levels(leveld_src, leveld_dst, comp_req->src_tree, 0);
#if ENABLE_BLOOM_FILTERS
		log_info("Swapping also bloom filter");
		leveld_dst->bloom_filter[0] = leveld_src->bloom_filter[0];
		memset(&leveld_src->bloom_filter[0], 0x00, sizeof(struct bloom));
#endif

		if (RWLOCK_UNLOCK(&(comp_req->db_desc->levels[comp_req->src_level].guard_of_level.rx_lock))) {
			log_fatal("Failed to acquire guard lock");
			exit(EXIT_FAILURE);
		}

		if (RWLOCK_UNLOCK(&(comp_req->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock))) {
			log_fatal("Failed to acquire guard lock");
			exit(EXIT_FAILURE);
		}

		log_info("Swapped levels %d to %d successfully", comp_req->src_level, comp_req->dst_level);
		log_info("After swapping src tree[%d][%d] size is %llu", comp_req->src_level, 0,
			 leveld_src->level_size[0]);
		log_info("After swapping dst tree[%d][%d] size is %llu", comp_req->dst_level, 0,
			 leveld_dst->level_size[0]);
		assert(leveld_dst->first_segment != NULL);
	}

	log_info("DONE Compaction from level's tree [%u][%u] to level's tree[%u][%u] "
		 "cleaning src level",
		 comp_req->src_level, comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree);

	snapshot(comp_req->volume_desc);
	db_desc->levels[comp_req->src_level].tree_status[comp_req->src_tree] = NO_SPILLING;
	db_desc->levels[comp_req->dst_level].tree_status[0] = NO_SPILLING;

	/*wake up clients*/
	if (comp_req->src_level == 0) {
		log_info("src level %d dst level %d src_tree %d dst_tree %d", comp_req->src_level, comp_req->dst_level,
			 comp_req->src_tree, comp_req->dst_tree);
		pthread_mutex_lock(&comp_req->db_desc->client_barrier_lock);
		if (pthread_cond_broadcast(&db_desc->client_barrier) != 0) {
			log_fatal("Failed to wake up stopped clients");
			exit(EXIT_FAILURE);
		}
	}
	pthread_mutex_unlock(&db_desc->client_barrier_lock);
	sem_post(&db_desc->compaction_daemon_interrupts);
	free(comp_req);
	sem_post(&gc_daemon_interrupts);
	return NULL;
}

#else
void *spill_buffer(void *_comp_req)
{
	struct bt_insert_req ins_req;
	struct compaction_request *comp_req = (struct compaction_request *)_comp_req;
	struct db_descriptor *db_desc;
	struct level_scanner *level_sc;

	int32_t local_spilled_keys = 0;
	int i, rc = 100;

	pthread_setname_np(pthread_self(), "comp_thread");
	log_info("starting compaction from level's tree [%u][%u] to level's tree[%u][%u]", comp_req->src_level,
		 comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree);
	/*Initialize a scan object*/
	db_desc = comp_req->db_desc;

	db_handle handle = { .db_desc = comp_req->db_desc, .volume_desc = comp_req->volume_desc };
	struct node_header *src_root = NULL;

	if (handle.db_desc->levels[comp_req->src_level].root_w[comp_req->src_tree] != NULL)
		src_root = handle.db_desc->levels[comp_req->src_level].root_w[comp_req->src_tree];
	else if (handle.db_desc->levels[comp_req->src_level].root_r[comp_req->src_tree] != NULL)
		src_root = handle.db_desc->levels[comp_req->src_level].root_r[comp_req->src_tree];
	else {
		log_fatal("NULL src root for compaction?");
		exit(EXIT_FAILURE);
	}
	level_sc = _init_spill_buffer_scanner(&handle, src_root, NULL);
	if (!level_sc) {
		log_fatal("Failed to create a spill buffer scanner for level's tree[%u][%u]", comp_req->src_level,
			  comp_req->src_tree);
		exit(EXIT_FAILURE);
	}
	int32_t num_of_keys = (SPILL_BUFFER_SIZE - (2 * sizeof(uint32_t))) / (PREFIX_SIZE + sizeof(uint64_t));

	/*optimization check if level below is empty than spill is a metadata
	 * operation*/
	struct node_header *dst_root = NULL;
	if (handle.db_desc->levels[comp_req->dst_level].root_w[0] != NULL)
		dst_root = handle.db_desc->levels[comp_req->dst_level].root_w[0];
	else if (handle.db_desc->levels[comp_req->dst_level].root_r[0] != NULL)
		dst_root = handle.db_desc->levels[comp_req->dst_level].root_r[0];
	else {
		log_info("Empty level %d time for an optimization :-)");
		dst_root = NULL;
	}

	if (dst_root) {
		do {
			while (handle.volume_desc->snap_preemption == SNAP_INTERRUPT_ENABLE)
				usleep(50000);

			db_desc->dirty = 0x01;
			if (handle.db_desc->stat == DB_IS_CLOSING) {
				log_info("db is closing bye bye from spiller");
				return NULL;
			}

			ins_req.metadata.handle = &handle;
			ins_req.metadata.level_id = comp_req->dst_level;
			ins_req.metadata.tree_id = comp_req->dst_tree;
			ins_req.metadata.key_format = KV_PREFIX;
			ins_req.metadata.append_to_log = 0;
			ins_req.metadata.special_split = 0;

			ins_req.metadata.gc_request = 0;
			ins_req.metadata.recovery_request = 0;

			for (i = 0; i < num_of_keys; i++) {
				ins_req.key_value_buf = level_sc->keyValue;
				_insert_key_value(&ins_req);
				rc = _get_next_KV(level_sc);
				if (rc == END_OF_DATABASE)
					break;

				++local_spilled_keys;
			}
		} while (rc != END_OF_DATABASE);

		_close_spill_buffer_scanner(level_sc);

		log_info("local spilled keys %d", local_spilled_keys);

		struct db_handle hd = { .db_desc = comp_req->db_desc, .volume_desc = comp_req->volume_desc };
		seg_free_level(&hd, comp_req->src_level, comp_req->src_tree);
	} else {
		struct level_descriptor *level_src = &comp_req->db_desc->levels[comp_req->src_level];
		struct level_descriptor *level_dst = &comp_req->db_desc->levels[comp_req->dst_level];
		swap_levels(level_src, level_dst, comp_req->src_tree, comp_req->dst_tree);

		log_info("Swapped levels %d to %d successfully", comp_req->src_level, comp_req->dst_level);
	}

	/*Clean up code, Free the buffer tree was occupying. free_block() used
* intentionally*/
	log_info("DONE Compaction from level's tree [%u][%u] to level's tree[%u][%u] "
		 "cleaning src level",
		 comp_req->src_level, comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree);

	/*assert check
      if(db_desc->spilled_keys !=
db_desc->total_keys[comp_req->src_tree_id]){
      printf("[%s:%s:%d] FATAL keys missing --- spilled keys %llu actual
%llu spiller
      id
      %d\n",__FILE__,__func__,__LINE__,(LLU)db_desc->spilled_keys,(LLU)db_desc->total_keys[comp_req->src_tree_id],
      comp_req->src_tree_id);
      exit(EXIT_FAILURE);
      }*/
	snapshot(comp_req->volume_desc);
	db_desc->levels[comp_req->src_level].tree_status[comp_req->src_tree] = NO_SPILLING;
	db_desc->levels[comp_req->dst_level].tree_status[comp_req->dst_tree] = NO_SPILLING;
	if (comp_req->src_tree == 0)
		db_desc->L0_start_log_offset = comp_req->l0_end;

	// log_info("DONE Cleaning src level tree [%u][%u] snapshotting...",
	// comp_req->src_level, comp_req->src_tree);
	/*interrupt compaction daemon*/
	/*wake up clients*/
	if (comp_req->src_level == 0) {
		pthread_mutex_lock(&comp_req->db_desc->client_barrier_lock);
		if (pthread_cond_broadcast(&db_desc->client_barrier) != 0) {
			log_fatal("Failed to wake up stopped clients");
			exit(EXIT_FAILURE);
		}
	}
	pthread_mutex_unlock(&db_desc->client_barrier_lock);
	sem_post(&db_desc->compaction_daemon_interrupts);
	free(comp_req);
	return NULL;
}
#endif

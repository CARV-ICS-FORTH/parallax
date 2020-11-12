#define _GNU_SOURCE
#define COMPACTION

#include <pthread.h>
#include <assert.h>
#include "../scanner/scanner.h"
#include "btree.h"
#include "segment_allocator.h"
#include <log.h>
/* Checks for pending compactions. It is responsible to check for dependencies
 * between two levels before triggering a compaction. */

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
				comp_req = (struct compaction_request *)malloc(sizeof(struct compaction_request));
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
			for (int i = 0; i < NUM_TREES_PER_LEVEL; i++) {
				if (db_desc->levels[0].tree_status[i] == NO_SPILLING) {
					/*Acquire guard lock and wait writers to finish*/
					if (RWLOCK_WRLOCK(&(handle->db_desc->levels[0].guard_of_level.rx_lock))) {
						log_fatal("Failed to acquire guard lock");
						exit(EXIT_FAILURE);
					}
					spin_loop(&(comp_req->db_desc->levels[0].active_writers), 0);
					/*done now atomically change active tree*/
					db_desc->levels[0].active_tree = i;

					/*Release guard lock*/
					if (RWLOCK_UNLOCK(&handle->db_desc->levels[0].guard_of_level.rx_lock)) {
						log_fatal("Failed to acquire guard lock");
						exit(EXIT_FAILURE);
					}

					pthread_mutex_lock(&db_desc->client_barrier_lock);
					if (pthread_cond_broadcast(&db_desc->client_barrier) != 0) {
						log_fatal("Failed to wake up stopped clients");
						exit(EXIT_FAILURE);
					}
					pthread_mutex_unlock(&db_desc->client_barrier_lock);
				}
			}
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
			struct level_descriptor *level_1 = &handle->db_desc->levels[level_id];
			struct level_descriptor *level_2 = &handle->db_desc->levels[level_id + 1];
			uint8_t tree_1 = 0; // level_1->active_tree;
			uint8_t tree_2 = 0; // level_2->active_tree;

			// log_info("level[%u][%u] = %llu size max is: %llu level[%u][%u] = %llu
			// size", level_id, tree_1,
			//	 level_1->level_size[tree_1], level_1->max_level_size, level_id
			//+ 1, tree_2,
			//	 level_2->level_size[tree_2]);
			// log_info("level status = %u", level_1->tree_status[tree_1]);
			if (level_1->tree_status[tree_1] == NO_SPILLING &&
			    level_1->level_size[tree_1] >= level_1->max_level_size) {
				// log_info("Level %u is F U L L", level_id);
				// src ready is destination ok?
				if (level_2->tree_status[tree_2] == NO_SPILLING &&
				    level_2->level_size[tree_2] < level_2->max_level_size) {
					level_1->tree_status[tree_1] = SPILLING_IN_PROGRESS;
					level_2->tree_status[tree_2] = SPILLING_IN_PROGRESS;
					/*start a compaction*/
					struct compaction_request *comp_req_p =
						(struct compaction_request *)malloc(sizeof(struct compaction_request));
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
void *compaction(void *_comp_req)
{
	struct bt_insert_req ins_req;
	struct compaction_request *comp_req = (struct compaction_request *)_comp_req;
	struct db_descriptor *db_desc;

	uint32_t local_spilled_keys = 0;
	int i, rc = 100;

	pthread_setname_np(pthread_self(), "comp_thread");
	log_info("starting compaction from level's tree [%u][%u] to level's tree[%u][%u]", comp_req->src_level,
		 comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree);
	/*Initialize a scan object*/
	db_desc = comp_req->db_desc;

	db_handle handle;
	handle.db_desc = comp_req->db_desc;
	handle.volume_desc = comp_req->volume_desc;

	struct node_header *src_root = NULL;
	if (handle.db_desc->levels[comp_req->src_level].root_w[comp_req->src_tree] != NULL)
		src_root = handle.db_desc->levels[comp_req->src_level].root_w[comp_req->src_tree];
	else if (handle.db_desc->levels[comp_req->src_level].root_r[comp_req->src_tree] != NULL)
		src_root = handle.db_desc->levels[comp_req->src_level].root_r[comp_req->src_tree];
	else {
		log_fatal("NULL src root for compaction from level's tree [%u][%u] to "
			  "level's tree[%u][%u] for db %s",
			  comp_req->src_level, comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree,
			  handle.db_desc->db_name);
		exit(EXIT_FAILURE);
	}

	/*optimization check if level below is empty than spill is a metadata
   * operation*/
	struct node_header *dst_root = NULL;
	if (handle.db_desc->levels[comp_req->dst_level].root_w[0] != NULL)
		dst_root = handle.db_desc->levels[comp_req->dst_level].root_w[0];
	else if (handle.db_desc->levels[comp_req->dst_level].root_r[0] != NULL)
		dst_root = handle.db_desc->levels[comp_req->dst_level].root_r[0];
	else {
		log_info("Empty level %d time for an optimization :-)", comp_req->dst_level);
		dst_root = NULL;
	}

	if (dst_root) {
		struct level_scanner *level_src =
			_init_spill_buffer_scanner(&handle, comp_req->src_level, src_root, NULL);
		struct level_scanner *level_dst =
			_init_spill_buffer_scanner(&handle, comp_req->dst_level, dst_root, NULL);

		log_info("Src [%u][%u] size = %llu", comp_req->src_level, comp_req->src_tree,
			 db_desc->levels[comp_req->src_level].level_size[comp_req->src_tree]);

		log_info("Dst [%u][%u] size = %llu", comp_req->dst_level, 0,
			 db_desc->levels[comp_req->dst_level].level_size[0]);

		if (!level_src || !level_dst) {
			log_fatal("Failed to create pair of spill buffer scanners for level's "
				  "tree[%u][%u]",
				  comp_req->src_level, comp_req->src_tree);
			exit(EXIT_FAILURE);
		}
		struct sh_min_heap *m_heap = (struct sh_min_heap *)malloc(sizeof(struct sh_min_heap));
		sh_init_heap(m_heap, comp_req->src_level);
		struct sh_heap_node nd_src = {
			.KV = NULL, .level_id = 0, .active_tree = 0, .duplicate = 0, .type = KV_PREFIX
		};
		struct sh_heap_node nd_dst = {
			.KV = NULL, .level_id = 0, .active_tree = 0, .duplicate = 0, .type = KV_PREFIX
		};
		struct sh_heap_node nd_min = {
			.KV = NULL, .level_id = 0, .active_tree = 0, .duplicate = 0, .type = KV_PREFIX
		};

		nd_src.KV = level_src->keyValue;
		nd_src.level_id = comp_req->src_level;
		nd_src.active_tree = comp_req->src_tree;
		sh_insert_heap_node(m_heap, &nd_src);

		nd_dst.KV = level_dst->keyValue;
		nd_dst.level_id = comp_req->dst_level;
		nd_dst.active_tree = comp_req->dst_tree;
		sh_insert_heap_node(m_heap, &nd_dst);
		log_info("level scanners and min heap ready");
		int32_t num_of_keys = (SPILL_BUFFER_SIZE - (2 * sizeof(uint32_t))) / (PREFIX_SIZE + sizeof(uint64_t));
		enum sh_heap_status stat = GOT_MIN_HEAP;
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
			ins_req.metadata.special_split = 1;
			ins_req.metadata.gc_request = 0;
			ins_req.metadata.recovery_request = 0;

			for (i = 0; i < num_of_keys; i++) {
				stat = sh_remove_min(m_heap, &nd_min);
				if (stat != EMPTY_MIN_HEAP) {
					ins_req.key_value_buf = nd_min.KV;
				} else
					break;
				// log_info("Compacting key %s from level %d",
				//	 (*(uint64_t *)(ins_req.key_value_buf + PREFIX_SIZE)) + 4,
				// nd_min.level_id);
				_insert_key_value(&ins_req);
				// log_info("level size
				// %llu",comp_req->db_desc->levels[comp_req->dst_level].level_size[comp_req->dst_tree]);
				/*refill from the appropriate level*/
				struct level_scanner *curr_scanner = NULL;
				if (nd_min.level_id == comp_req->src_level)
					curr_scanner = level_src;
				else if (nd_min.level_id == comp_req->dst_level)
					curr_scanner = level_dst;
				else {
					log_fatal("corruption unknown level");
					exit(EXIT_FAILURE);
				}
				rc = _get_next_KV(curr_scanner);
				if (rc != END_OF_DATABASE) {
					nd_min.KV = curr_scanner->keyValue;
					sh_insert_heap_node(m_heap, &nd_min);
				}
				++local_spilled_keys;
			}
		} while (stat != EMPTY_MIN_HEAP);

		_close_spill_buffer_scanner(level_src, src_root);
		_close_spill_buffer_scanner(level_dst, dst_root);

		log_info("local spilled keys %d", local_spilled_keys);
		assert(local_spilled_keys == db_desc->levels[comp_req->src_level].level_size[comp_req->src_tree] +
						     db_desc->levels[comp_req->dst_level].level_size[0]);
		struct db_handle hd = { .db_desc = comp_req->db_desc, .volume_desc = comp_req->volume_desc };
		/*
     * Now the difficult part we need atomically to free the src level, dst
     * level[0]. Then
     * we need to atomically switch dst_level[1] to dst_level[0]. We ll acquire
     * the guard lock of each
     * level for scanners. We ll need another set of lamport counters for
     * readers to inform them that a
     * level change took place
     */

		// if
		// (RWLOCK_WRLOCK(&(comp_req->db_desc->levels[comp_req->src_level].guard_of_level.rx_lock)))
		// {
		//	log_fatal("Failed to acquire guard lock");
		//	exit(EXIT_FAILURE);
		//}

		// if
		// (RWLOCK_WRLOCK(&(comp_req->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock)))
		// {
		//	log_fatal("Failed to acquire guard lock");
		//	exit(EXIT_FAILURE);
		//}

		/*special care for dst level atomic switch tree 2 to tree 1 of dst*/
		struct segment_header *curr_segment = comp_req->db_desc->levels[comp_req->dst_level].first_segment[0];
		assert(curr_segment != NULL);
		uint64_t space_freed = 0;
		while (1) {
			free_block(comp_req->volume_desc, curr_segment, SEGMENT_SIZE, -1);
			space_freed += SEGMENT_SIZE;
			if (curr_segment->next_segment == NULL)
				break;
			curr_segment = MAPPED + curr_segment->next_segment;
		}
		log_info("Freed space %llu MB from db:%s level %u", space_freed / (1024 * 1024),
			 comp_req->db_desc->db_name, comp_req->src_level);
		log_info("Switching tree[%u][%u] to tree[%u][%u]", comp_req->dst_level, 1, comp_req->dst_level, 0);
		struct level_descriptor *ld = &comp_req->db_desc->levels[comp_req->dst_level];

		ld->first_segment[0] = ld->first_segment[1];
		ld->first_segment[1] = NULL;
		ld->last_segment[0] = ld->last_segment[1];
		ld->last_segment[1] = NULL;
		ld->offset[0] = ld->offset[1];
		ld->offset[1] = 0;

		if (ld->root_w[1] != NULL) {
			while (!__sync_bool_compare_and_swap(&ld->root_r[0], ld->root_r[0], ld->root_w[1])) {
			}
		} else if (ld->root_r[1] != NULL) {
			while (!__sync_bool_compare_and_swap(&ld->root_r[0], ld->root_r[0], ld->root_r[1])) {
			}
		} else {
			log_fatal("Where is the root?");
			exit(EXIT_FAILURE);
		}
		ld->root_w[0] = NULL;
		ld->level_size[0] = ld->level_size[1];
		ld->level_size[1] = 0;
		ld->root_w[1] = NULL;
		ld->root_r[1] = NULL;

		/*free src level*/
		seg_free_level(&hd, comp_req->src_level, comp_req->src_tree);

		// if
		// (RWLOCK_UNLOCK(&(comp_req->db_desc->levels[comp_req->src_level].guard_of_level.rx_lock)))
		// {
		//	log_fatal("Failed to acquire guard lock");
		//	exit(EXIT_FAILURE);
		//}

		// if
		// (RWLOCK_UNLOCK(&(comp_req->db_desc->levels[comp_req->dst_level].guard_of_level.rx_lock)))
		// {
		//	log_fatal("Failed to acquire guard lock");
		//	exit(EXIT_FAILURE);
		//}
		log_info("After compaction tree[%d][%d] size is %llu", comp_req->dst_level, 0, ld->level_size[0]);
	} else {
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

	/*Clean up code, Free the buffer tree was occupying. free_block() used
   * intentionally*/
	log_info("DONE Compaction from level's tree [%u][%u] to level's tree[%u][%u] "
		 "cleaning src level",
		 comp_req->src_level, comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree);

	db_desc->levels[comp_req->src_level].tree_status[comp_req->src_tree] = NO_SPILLING;

	db_desc->levels[comp_req->dst_level].tree_status[0] = NO_SPILLING;

	// log_info("DONE Cleaning src level tree [%u][%u] snapshotting...",
	// comp_req->src_level, comp_req->src_tree);
	/*interrupt compaction daemon*/
	snapshot(comp_req->volume_desc);
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

	db_handle handle;
	handle.db_desc = comp_req->db_desc;
	handle.volume_desc = comp_req->volume_desc;
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

		_close_spill_buffer_scanner(level_sc, src_root);

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

	db_desc->levels[comp_req->src_level].tree_status[comp_req->src_tree] = NO_SPILLING;
	db_desc->levels[comp_req->dst_level].tree_status[comp_req->dst_tree] = NO_SPILLING;
	if (comp_req->src_tree == 0)
		db_desc->L0_start_log_offset = comp_req->l0_end;

	// log_info("DONE Cleaning src level tree [%u][%u] snapshotting...",
	// comp_req->src_level, comp_req->src_tree);
	/*interrupt compaction daemon*/
	snapshot(comp_req->volume_desc);
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

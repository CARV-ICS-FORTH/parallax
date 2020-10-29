#define _GNU_SOURCE

#include <pthread.h>
#include <assert.h>
#include "../scanner/scanner.h"
#include "btree.h"
#include "segment_allocator.h"
#include <log.h>
/* Checks for pending compactions. It is responsible to check for dependencies between two levels before triggering a compaction. */

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
static void *spill_buffer(void *_comp_req);

void *compaction_daemon(void *args)
{
	struct db_handle *handle = (struct db_handle *)args;
	struct db_descriptor *db_desc = handle->db_desc;
	int active_tree;
	pthread_setname_np(pthread_self(), "compactiond");

	while (1) {
		/*special care for Level 0 to 1*/
		sem_wait(&db_desc->compaction_daemon_interrupts);
		for (int i = 0; i < NUM_TREES_PER_LEVEL; i++) {
			struct level_descriptor *level_desc = &handle->db_desc->levels[0];
			//is level-0 full and not already spilling?
			if (level_desc->tree_status[i] == NO_SPILLING &&
			    level_desc->level_size[i] >= level_desc->max_level_size) {
				//Can I issue a spill to L1?
				uint8_t active_tree = db_desc->levels[1].active_tree;
				if (level_desc->tree_status[i] == NO_SPILLING &&
				    db_desc->levels[1].level_size[active_tree] < db_desc->levels[1].max_level_size) {
					/*mark them as spilling L0*/
					level_desc->tree_status[i] = SPILLING_IN_PROGRESS;
					/*mark them as spilling L1*/
					db_desc->levels[1].tree_status[active_tree] = SPILLING_IN_PROGRESS;
					/*start a compaction*/
					struct compaction_request *comp_req =
						(struct compaction_request *)malloc(sizeof(struct compaction_request));
					comp_req->db_desc = handle->db_desc;
					comp_req->volume_desc = handle->volume_desc;
					comp_req->src_level = 0;
					comp_req->src_tree = i;
					comp_req->dst_level = 1;
					comp_req->dst_tree = active_tree;
					if (pthread_create(&db_desc->levels[0].compaction_thread[i], NULL, spill_buffer,
							   comp_req) != 0) {
						log_fatal("Failed to start compaction");
						exit(EXIT_FAILURE);
					}
				}
			}
		}
		/*can I set a different active tree for L0*/
		active_tree = db_desc->levels[0].active_tree;
		if (db_desc->levels[0].tree_status[active_tree] == SPILLING_IN_PROGRESS) {
			for (int i = 0; i < NUM_TREES_PER_LEVEL; i++) {
				if (db_desc->levels[0].tree_status[i] == NO_SPILLING) {
					pthread_mutex_lock(&db_desc->client_barrier_lock);
					db_desc->levels[0].active_tree = i;
					if (pthread_cond_broadcast(&db_desc->client_barrier) != 0) {
						log_fatal("Failed to wake up stopped clients");
						exit(EXIT_FAILURE);
					}
					pthread_mutex_unlock(&db_desc->client_barrier_lock);
				}
			}
		}

		//rest of levels
		for (int level_id = 1; level_id < MAX_LEVELS - 1; ++level_id) {
			struct level_descriptor *level_1 = &handle->db_desc->levels[level_id];
			struct level_descriptor *level_2 = &handle->db_desc->levels[level_id + 1];
			uint8_t tree_1 = level_1->active_tree;
			uint8_t tree_2 = level_2->active_tree;

			//log_info("level[%u][%u] = %llu size max is: %llu level[%u][%u] = %llu size", level_id, tree_1,
			//	 level_1->level_size[tree_1], level_1->max_level_size, level_id + 1, tree_2,
			//	 level_2->level_size[tree_2]);
			//log_info("level status = %u", level_1->tree_status[tree_1]);
			if (level_1->tree_status[tree_1] == NO_SPILLING &&
			    level_1->level_size[tree_1] >= level_1->max_level_size) {
				//log_info("Level %u is F U L L", level_id);
				//src ready is destination ok?
				if (level_2->tree_status[tree_2] == NO_SPILLING &&
				    level_2->level_size[tree_2] < level_2->max_level_size) {
					level_1->tree_status[tree_1] = SPILLING_IN_PROGRESS;
					level_2->tree_status[tree_2] = SPILLING_IN_PROGRESS;
					/*start a compaction*/
					struct compaction_request *comp_req =
						(struct compaction_request *)malloc(sizeof(struct compaction_request));
					comp_req->db_desc = handle->db_desc;
					comp_req->volume_desc = handle->volume_desc;
					comp_req->src_level = level_id;
					comp_req->src_tree = tree_1;
					comp_req->dst_level = level_id + 1;
					comp_req->dst_tree = tree_2;
					if (pthread_create(&db_desc->levels[level_id].compaction_thread[tree_1], NULL,
							   spill_buffer, comp_req) != 0) {
						log_fatal("Failed to start compaction");
						exit(EXIT_FAILURE);
					}
				}
			}
		}
	}
}

static void swap_levels(struct level_descriptor *src, struct level_descriptor *dst, int src_active_tree,
			int dst_active_tree)
{
	dst->root_r[dst_active_tree] = src->root_r[src_active_tree];
	dst->root_w[dst_active_tree] = src->root_w[src_active_tree];
	dst->first_segment[dst_active_tree] = src->first_segment[src_active_tree];
	dst->last_segment[dst_active_tree] = src->last_segment[src_active_tree];
	dst->offset[dst_active_tree] = src->offset[src_active_tree];
	dst->level_size[dst_active_tree] = src->level_size[src_active_tree];
	return;
}

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

	/*optimization check if level below is empty than spill is a metadata operation*/
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
	log_info("DONE Compaction from level's tree [%u][%u] to level's tree[%u][%u] cleaning src level",
		 comp_req->src_level, comp_req->src_tree, comp_req->dst_level, comp_req->dst_tree);

	/*assert check
		  if(db_desc->spilled_keys != db_desc->total_keys[comp_req->src_tree_id]){
		  printf("[%s:%s:%d] FATAL keys missing --- spilled keys %llu actual %llu spiller
		  id
		  %d\n",__FILE__,__func__,__LINE__,(LLU)db_desc->spilled_keys,(LLU)db_desc->total_keys[comp_req->src_tree_id],
		  comp_req->src_tree_id);
		  exit(EXIT_FAILURE);
		  }*/

	db_desc->levels[comp_req->src_level].tree_status[comp_req->src_tree] = NO_SPILLING;
	db_desc->levels[comp_req->dst_level].tree_status[comp_req->dst_tree] = NO_SPILLING;
	if (comp_req->src_tree == 0)
		db_desc->L0_start_log_offset = comp_req->l0_end;

	//log_info("DONE Cleaning src level tree [%u][%u] snapshotting...", comp_req->src_level, comp_req->src_tree);
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


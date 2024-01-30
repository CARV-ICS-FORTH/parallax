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

#define _GNU_SOURCE
#include "compaction_daemon.h"
#include "../allocator/device_structures.h"
#include "../allocator/log_structures.h"
#include "../allocator/persistent_operations.h"
#include "../allocator/redo_undo_log.h"
#include "../common/common.h"
#include "../lib/parallax_callbacks/parallax_callbacks.h"
#include "btree.h"
#include "compaction_worker.h"
#include "conf.h"
#include "device_level.h"
#include "parallax/structures.h"
#include <assert.h>
#include <log.h>
#include <pthread.h>
#include <semaphore.h>
#include <spin_loop.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct device_level;
struct node_header;
// IWYU pragma: no_forward_declare index_node

struct compaction_daemon {
	pthread_mutex_t barrier_lock;
	pthread_cond_t barrier;
	sem_t compaction_daemon_interrupts;
	db_handle *db_handle;
	int next_L0_tree_to_compact;
	bool do_not_issue_L0_compactions;
};

struct compaction_daemon *compactiond_create(struct db_handle *handle, bool do_not_issue_L0_compactions)
{
	struct compaction_daemon *daemon = calloc(1UL, sizeof(struct compaction_daemon));
	daemon->db_handle = handle;
	daemon->do_not_issue_L0_compactions = do_not_issue_L0_compactions;
	daemon->next_L0_tree_to_compact = 0;
	pthread_mutex_init(&daemon->barrier_lock, NULL);
	sem_init(&daemon->compaction_daemon_interrupts, 0, 0);
	pthread_cond_init(&daemon->barrier, NULL);
	return daemon;
}

static struct compaction_request *compactiond_compact_L0(struct compaction_daemon *daemon, uint8_t L0_tree_id,
							 uint8_t L1_tree_id)
{
	struct level_descriptor *level_0 = &daemon->db_handle->db_desc->L0;
	struct device_level *level_1 = daemon->db_handle->db_desc->dev_levels[1];

	if (level_0->tree_status[L0_tree_id] != BT_NO_COMPACTION)
		return NULL;

	if (level_0->level_size[L0_tree_id] < level_0->max_level_size)
		return NULL;

	if (level_is_compacting(daemon->db_handle->db_desc->dev_levels[1]))
		return NULL;

	if (level_has_overflow(level_1, L1_tree_id))
		return NULL;

	bt_set_db_status(daemon->db_handle->db_desc, BT_COMPACTION_IN_PROGRESS, 0, L0_tree_id);
	level_set_comp_in_progress(daemon->db_handle->db_desc->dev_levels[1]);

	/*start a compaction*/
	return compaction_create_req(daemon->db_handle->db_desc, &daemon->db_handle->db_options, UINT64_MAX, UINT64_MAX,
				     0, L0_tree_id, 1, 1);
}

static void *compactiond_run(void *args)
{
	struct compaction_daemon *daemon = (struct compaction_daemon *)args;
	assert(daemon);
	struct db_handle *handle = daemon->db_handle;
	struct db_descriptor *db_desc = handle->db_desc;
	struct compaction_request *comp_req = NULL;
	pthread_setname_np(pthread_self(), "compactiond");

	while (1) {
		sem_wait(&daemon->compaction_daemon_interrupts);

		if (db_desc->db_state == DB_TERMINATE_COMPACTION_DAEMON) {
			log_warn("Compaction daemon instructed to exit because DB %s is closing, "
				 "Bye bye!...",
				 db_desc->db_superblock->db_name);
			db_desc->db_state = DB_IS_CLOSING;
			return NULL;
		}
		// struct level_descriptor *level_0 = &handle->db_desc->levels[0];

		// int L0_tree = next_L0_tree_to_compact;
		// int L1_tree = 0;
		comp_req = compactiond_compact_L0(daemon, daemon->next_L0_tree_to_compact % NUM_TREES_PER_LEVEL, 0);
		if (comp_req)
			++daemon->next_L0_tree_to_compact;
		// if (level_0->tree_status[next_L0_tree_to_compact % NUM_TREES_PER_LEVEL] == BT_NO_COMPACTION &&
		//     level_0->level_size[next_L0_tree_to_compact % NUM_TREES_PER_LEVEL] >= level_0->max_level_size &&
		//     src_level->tree_status[L1_tree] == BT_NO_COMPACTION &&
		//     src_level->level_size[L1_tree] < src_level->max_level_size) {
		// 	/*mark them as compacting L0*/

		// 	bt_set_db_status(db_desc, BT_COMPACTION_IN_PROGRESS, 0,
		// 			 next_L0_tree_to_compact % NUM_TREES_PER_LEVEL);
		// 	/*mark them as compacting L1*/
		// 	bt_set_db_status(db_desc, BT_COMPACTION_IN_PROGRESS, 1, L1_tree);

		// 	/*start a compaction*/
		// 	comp_req = compaction_create_req(handle->db_desc, &handle->db_options, UINT64_MAX, UINT64_MAX,
		// 					 0, next_L0_tree_to_compact++ % NUM_TREES_PER_LEVEL, 1, 1);
		// 	// if (++next_L0_tree_to_compact >= NUM_TREES_PER_LEVEL)
		// 	// 	next_L0_tree_to_compact = 0;
		// }
		/*can I set a different active tree for L0*/
		int active_tree = db_desc->L0.active_tree;
		if (db_desc->L0.tree_status[active_tree] == BT_COMPACTION_IN_PROGRESS) {
			int next_active_tree = active_tree < NUM_TREES_PER_LEVEL - 1 ? active_tree + 1 : 0;
			if (db_desc->L0.tree_status[next_active_tree] == BT_NO_COMPACTION) {
				/*Acquire guard lock and wait writers to finish*/
				if (RWLOCK_WRLOCK(&db_desc->L0.guard_of_level.rx_lock)) {
					log_fatal("Failed to acquire guard lock");
					BUG_ON();
				}
				spin_loop(&(db_desc->L0.active_operations), 0);
				/*fill L0 recovery log  info*/
				db_desc->small_log_start_segment_dev_offt = db_desc->small_log.tail_dev_offt;
				log_debug("Setting db_desc->small_log_start_segment_dev_offt to %lu",
					  db_desc->small_log.tail_dev_offt);
				db_desc->small_log_start_offt_in_segment = db_desc->small_log.size % SEGMENT_SIZE;

				/*fill big log recovery  info*/
				db_desc->big_log_start_segment_dev_offt = db_desc->big_log.tail_dev_offt;
				db_desc->big_log_start_offt_in_segment = db_desc->big_log.size % SEGMENT_SIZE;
				/*done now atomically change active tree*/

				db_desc->L0.active_tree = next_active_tree;
				db_desc->L0.scanner_epoch += 1;
				db_desc->L0.epoch[active_tree] = db_desc->L0.scanner_epoch;
				log_debug("Next active tree %u for L0 of DB: %s", next_active_tree,
					  db_desc->db_superblock->db_name);
				/*Acquire a new transaction id for the next_active_tree*/
				db_desc->L0.allocation_txn_id[next_active_tree] = rul_start_txn(db_desc);
				/*Release guard lock*/
				if (RWLOCK_UNLOCK(&db_desc->L0.guard_of_level.rx_lock)) {
					log_fatal("Failed to acquire guard lock");
					BUG_ON();
				}

				MUTEX_LOCK(&daemon->barrier_lock);
				if (pthread_cond_broadcast(&daemon->barrier) != 0) {
					log_fatal("Failed to wake up stopped clients");
					BUG_ON();
				}
				MUTEX_UNLOCK(&daemon->barrier_lock);
			}
		}

		if (comp_req) {
			/*Start a compaction from L0 to L1. Flush L0 prior to compaction from L0 to L1*/
			log_debug("Flushing L0 for region:%s tree:[0][%u]", db_desc->db_superblock->db_name,
				  compaction_get_src_tree(comp_req));
			pr_flush_L0(db_desc, compaction_get_src_tree(comp_req));
			compaction_set_dst_tree(comp_req, 1);
			assert(db_desc->L0.root[compaction_get_src_tree(comp_req)] != NULL);

			//TODO: geostyl callback
			parallax_callbacks_t par_callbacks = db_desc->parallax_callbacks;
			if (are_parallax_callbacks_set(par_callbacks) &&
			    handle->db_options.options[PRIMARY_MODE].value) {
				struct parallax_callback_funcs par_cb = parallax_get_callbacks(par_callbacks);
				void *context = parallax_get_context(par_callbacks);
				if (par_cb.build_index_L0_compaction_started_cb)
					par_cb.build_index_L0_compaction_started_cb(context);
			}

			if (pthread_create(&db_desc->L0.compaction_thread[compaction_get_src_tree(comp_req)], NULL,
					   compaction, comp_req) != 0) {
				log_fatal("Failed to start compaction");
				BUG_ON();
			}
			comp_req = NULL;
		}

		// rest of levels
		for (uint8_t level_id = 1; level_id < MAX_LEVELS - 1; ++level_id) {
			struct device_level *src_level = db_desc->dev_levels[level_id];
			struct device_level *dst_level = db_desc->dev_levels[level_id + 1];
			if (false == level_has_overflow(src_level, 0))
				continue;
			if (level_is_compacting(src_level))
				continue;
			if (level_is_compacting(dst_level))
				continue;
			level_set_comp_in_progress(db_desc->dev_levels[level_id]);
			level_set_comp_in_progress(db_desc->dev_levels[level_id + 1]);

			//compaction request will get a txn in its constructor
			struct compaction_request *comp_req_p = compaction_create_req(
				db_desc, &handle->db_options, UINT64_MAX, UINT64_MAX, level_id, 0, level_id + 1, 1);

			level_start_comp_thread(db_desc->dev_levels[compaction_get_dst_level(comp_req_p)], compaction,
						comp_req_p);
		}
	}
}

bool compactiond_start(struct compaction_daemon *daemon, pthread_t *context)
{
	assert(daemon && context);
	if (pthread_create(context, NULL, compactiond_run, daemon) != 0) {
		log_fatal("Failed to start compaction_daemon for db %s", daemon->db_handle->db_options.db_name);
		BUG_ON();
	}
	return true;
}

void compactiond_wait(struct compaction_daemon *daemon)
{
	MUTEX_LOCK(&daemon->barrier_lock);

	if (pthread_cond_wait(&daemon->barrier, &daemon->barrier_lock) != 0) {
		log_fatal("failed to throttle");
		BUG_ON();
	}
	MUTEX_UNLOCK(&daemon->barrier_lock);
}

void compactiond_notify_all(struct compaction_daemon *daemon)
{
	assert(daemon);
	MUTEX_LOCK(&daemon->barrier_lock);
	if (pthread_cond_broadcast(&daemon->barrier) != 0) {
		log_fatal("Failed to wake up stopped clients");
		BUG_ON();
	}
	MUTEX_UNLOCK(&daemon->barrier_lock);
}

void compactiond_interrupt(struct compaction_daemon *daemon)
{
	assert(daemon);
	sem_post(&daemon->compaction_daemon_interrupts);
}

void compactiond_close(struct compaction_daemon *daemon)
{
	assert(daemon);
	if (pthread_cond_destroy(&daemon->barrier) != 0) {
		log_fatal("Failed to destroy condition variable");
		perror("pthread_cond_destroy() error");
		BUG_ON();
	}
	free(daemon);
}

// cppcheck-suppress unusedFunction
void compactiond_force_L0_compaction(struct compaction_daemon *daemon)
{
	assert(daemon);
	struct level_descriptor *level_0 = &daemon->db_handle->db_desc->L0;
	int tree_id = daemon->next_L0_tree_to_compact % NUM_TREES_PER_LEVEL;
	level_0->level_size[tree_id] = level_0->max_level_size;
	compactiond_interrupt(daemon);
}

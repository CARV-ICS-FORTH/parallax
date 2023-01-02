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
#include "btree.h"
#include "compaction_worker.h"
#include "conf.h"
#include <assert.h>
#include <log.h>
#include <pthread.h>
#include <semaphore.h>
#include <spin_loop.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
struct node_header;
// IWYU pragma: no_forward_declare index_node

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
		if (db_desc->db_state == DB_TERMINATE_COMPACTION_DAEMON) {
			log_warn("Compaction daemon instructed to exit because DB %s is closing, "
				 "Bye bye!...",
				 db_desc->db_superblock->db_name);
			db_desc->db_state = DB_IS_CLOSING;
			return NULL;
		}
		struct level_descriptor *level_0 = &handle->db_desc->levels[0];
		struct level_descriptor *src_level = &handle->db_desc->levels[1];

		int L0_tree = next_L0_tree_to_compact;
		// is level-0 full and not already compacting?
		if (level_0->tree_status[L0_tree] == BT_NO_COMPACTION &&
		    level_0->level_size[L0_tree] >= level_0->max_level_size) {
			// Can I issue a compaction to L1?
			int L1_tree = 0;
			if (src_level->tree_status[L1_tree] == BT_NO_COMPACTION &&
			    src_level->level_size[L1_tree] < src_level->max_level_size) {
				/*mark them as compacting L0*/

				bt_set_db_status(db_desc, BT_COMPACTION_IN_PROGRESS, 0, L0_tree);
				/*mark them as compacting L1*/
				bt_set_db_status(db_desc, BT_COMPACTION_IN_PROGRESS, 1, L1_tree);

				/*start a compaction*/
				comp_req = (struct compaction_request *)calloc(1UL, sizeof(struct compaction_request));
				assert(comp_req);
				comp_req->db_desc = handle->db_desc;
				comp_req->volume_desc = handle->volume_desc;
				comp_req->db_options = &handle->db_options;
				comp_req->src_level = 0;
				comp_req->src_tree = L0_tree;
				comp_req->dst_level = 1;
				comp_req->dst_tree = 1;
				if (++next_L0_tree_to_compact >= NUM_TREES_PER_LEVEL)
					next_L0_tree_to_compact = 0;
			}
		}
		/*can I set a different active tree for L0*/
		int active_tree = db_desc->levels[0].active_tree;
		if (db_desc->levels[0].tree_status[active_tree] == BT_COMPACTION_IN_PROGRESS) {
			int next_active_tree = active_tree != (NUM_TREES_PER_LEVEL - 1) ? active_tree + 1 : 0;
			if (db_desc->levels[0].tree_status[next_active_tree] == BT_NO_COMPACTION) {
				/*Acquire guard lock and wait writers to finish*/
				if (RWLOCK_WRLOCK(&db_desc->levels[0].guard_of_level.rx_lock)) {
					log_fatal("Failed to acquire guard lock");
					BUG_ON();
				}
				spin_loop(&(db_desc->levels[0].active_operations), 0);
				/*fill L0 recovery log  info*/
				db_desc->small_log_start_segment_dev_offt = db_desc->small_log.tail_dev_offt;
				log_debug("Setting db_desc->small_log_start_segment_dev_offt to %lu",
					  db_desc->small_log.tail_dev_offt);
				db_desc->small_log_start_offt_in_segment = db_desc->small_log.size % SEGMENT_SIZE;

				/*fill big log recovery  info*/
				db_desc->big_log_start_segment_dev_offt = db_desc->big_log.tail_dev_offt;
				db_desc->big_log_start_offt_in_segment = db_desc->big_log.size % SEGMENT_SIZE;
				/*done now atomically change active tree*/

				db_desc->levels[0].active_tree = next_active_tree;
				db_desc->levels[0].scanner_epoch += 1;
				db_desc->levels[0].epoch[active_tree] = db_desc->levels[0].scanner_epoch;
				log_debug("Next active tree %u for L0 of DB: %s", next_active_tree,
					  db_desc->db_superblock->db_name);
				/*Acquire a new transaction id for the next_active_tree*/
				db_desc->levels[0].allocation_txn_id[next_active_tree] = rul_start_txn(db_desc);
				/*Release guard lock*/
				if (RWLOCK_UNLOCK(&db_desc->levels[0].guard_of_level.rx_lock)) {
					log_fatal("Failed to acquire guard lock");
					BUG_ON();
				}

				MUTEX_LOCK(&db_desc->client_barrier_lock);
				if (pthread_cond_broadcast(&db_desc->client_barrier) != 0) {
					log_fatal("Failed to wake up stopped clients");
					BUG_ON();
				}
				MUTEX_UNLOCK(&db_desc->client_barrier_lock);
			}
		}

		if (comp_req) {
			/*Start a compaction from L0 to L1. Flush L0 prior to compaction from L0 to L1*/
			log_debug("Flushing L0 for region:%s tree:[0][%u]", db_desc->db_superblock->db_name,
				  comp_req->src_tree);
			//TODO: geostyl callback
			parallax_callbacks_t par_callbacks = db_desc->parallax_callbacks;
			if (are_parallax_callbacks_set(par_callbacks)) {
				struct parallax_callback_funcs par_cb = parallax_get_callbacks(par_callbacks);
				void *context = parallax_get_context(par_callbacks);
				par_cb.compaction_started_cb(context, 0, 1);
			}
			pr_flush_L0(db_desc, comp_req->src_tree);
			db_desc->levels[1].allocation_txn_id[1] = rul_start_txn(db_desc);
			comp_req->dst_tree = 1;
			assert(db_desc->levels[0].root[comp_req->src_tree] != NULL);
			if (pthread_create(&db_desc->levels[0].compaction_thread[comp_req->src_tree], NULL, compaction,
					   comp_req) != 0) {
				log_fatal("Failed to start compaction");
				BUG_ON();
			}
			comp_req = NULL;
		}

		// rest of levels
		for (int level_id = 1; level_id < MAX_LEVELS - 1; ++level_id) {
			src_level = &db_desc->levels[level_id];
			struct level_descriptor *dst_level = &db_desc->levels[level_id + 1];
			uint8_t tree_1 = 0;

			if (src_level->tree_status[tree_1] == BT_NO_COMPACTION &&
			    src_level->level_size[tree_1] >= src_level->max_level_size) {
				uint8_t tree_2 = 0;

				if (dst_level->tree_status[tree_2] == BT_NO_COMPACTION &&
				    dst_level->level_size[tree_2] < dst_level->max_level_size) {
					bt_set_db_status(db_desc, BT_COMPACTION_IN_PROGRESS, level_id, tree_1);
					bt_set_db_status(db_desc, BT_COMPACTION_IN_PROGRESS, level_id + 1, tree_2);
					/*start a compaction*/
					struct compaction_request *comp_req_p = (struct compaction_request *)calloc(
						1, sizeof(struct compaction_request));
					assert(comp_req_p);
					comp_req_p->db_desc = db_desc;
					comp_req_p->volume_desc = handle->volume_desc;
					comp_req_p->db_options = &handle->db_options;
					comp_req_p->src_level = level_id;
					comp_req_p->src_tree = tree_1;
					comp_req_p->dst_level = level_id + 1;

					comp_req_p->dst_tree = 1;

					/*Acquire a txn_id for the allocations of the compaction*/
					db_desc->levels[comp_req_p->dst_level].allocation_txn_id[comp_req_p->dst_tree] =
						rul_start_txn(db_desc);

					assert(db_desc->levels[level_id].root[0] != NULL);
					//TODO: geostyl callback
					parallax_callbacks_t par_callbacks = db_desc->parallax_callbacks;
					if (are_parallax_callbacks_set(par_callbacks)) {
						struct parallax_callback_funcs par_cb =
							parallax_get_callbacks(par_callbacks);
						void *context = parallax_get_context(par_callbacks);
						par_cb.compaction_started_cb(context, level_id, comp_req_p->dst_tree);
					}
					if (pthread_create(&db_desc->levels[comp_req_p->dst_level]
								    .compaction_thread[comp_req_p->dst_tree],
							   NULL, compaction, comp_req_p) != 0) {
						log_fatal("Failed to start compaction");
						BUG_ON();
					}
				}
			}
		}
	}
}

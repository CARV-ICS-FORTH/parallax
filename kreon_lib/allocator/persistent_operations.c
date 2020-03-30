#include <sys/mman.h>
#include <errno.h>
#include "allocator.h"
#include "../btree/btree.h"
#include "../btree/segment_allocator.h"
#include "../../build/external-deps/log/src/log.h"

/*persists the KV-log of a DB, not thread safe!*/
void commit_db_log(db_descriptor *db_desc)
{
	segment_header *current_segment;

	/*sync data then metadata*/
	current_segment = (segment_header *)(MAPPED + (uint64_t)db_desc->commit_log->last_kv_log);
	while ((uint64_t)current_segment != MAPPED) {
		msync(current_segment, (size_t)SEGMENT_SIZE, MS_SYNC);
		current_segment = (segment_header *)(MAPPED + (uint64_t)current_segment->next_segment);
	}
	/*write log info*/
	if (db_desc->KV_log_first_segment != NULL)
		db_desc->commit_log->first_kv_log =
			(segment_header *)((uint64_t)db_desc->KV_log_first_segment - MAPPED);
	else
		db_desc->commit_log->first_kv_log = NULL;

	if (db_desc->KV_log_last_segment != NULL)
		db_desc->commit_log->last_kv_log = (segment_header *)((uint64_t)db_desc->KV_log_last_segment - MAPPED);
	else
		db_desc->commit_log->last_kv_log = NULL;

	db_desc->commit_log->kv_log_size = db_desc->KV_log_size;

	if (msync(db_desc->commit_log, sizeof(commit_log_info), MS_SYNC) == -1) {
		log_info("FATAL msync failed");
		exit(EXIT_FAILURE);
	}
	return;
}

void commit_db_logs_per_volume(volume_descriptor *volume_desc)
{
	NODE *node;
	db_descriptor *db_desc;
	node = get_first(volume_desc->open_databases);

	while (node != NULL) {
#if LOG_WITH_MUTEX
		MUTEX_LOCK(&db_desc->lock_log);
#else
		SPIN_LOCK(&db_desc->lock_log);
#endif
		db_desc = (db_descriptor *)(node->data);
		if (db_desc->commit_log->kv_log_size != db_desc->KV_log_size)
			commit_db_log(db_desc);
		node = node->next;

#if LOG_WITH_MUTEX
		MUTEX_UNLOCK(&db_desc->lock_log);
#else
		SPIN_UNLOCK(&db_desc->lock_log);
#endif
	}
}

/*persists a consistent snapshot of the system*/
void snapshot(volume_descriptor *volume_desc)
{
	pr_db_group *db_group;
	pr_db_entry *db_entry;
	//forest *new_forest;
	node_header *old_root;
	uint64_t a, b;
	uint64_t c;
	uint32_t i, j;
	int32_t dirty = 0;
	uint8_t level_id;
	int l;

	log_info("trigerring snapshot");
	volume_desc->snap_preemption = SNAP_INTERRUPT_ENABLE;
	/*1. Acquire all write locks for each database of the specific volume*/
	NODE *node = get_first(volume_desc->open_databases);
	db_descriptor *db_desc;

	while (node != NULL) {
		db_desc = (db_descriptor *)(node->data);
		/*stop log appenders*/
		//#if LOG_WITH_MUTEX
		//		MUTEX_LOCK(&db_desc->lock_log);
		//#else
		//		SPIN_LOCK(&db_desc->lock_log);
		//#endif
		/*stop all level writers*/
		for (level_id = 0; level_id < MAX_LEVELS; level_id++) {
			/*stop level 0 writers for this db*/
			RWLOCK_WRLOCK(&db_desc->levels[level_id].guard_of_level.rx_lock);
			/*spinning*/
			spin_loop(&(db_desc->levels[level_id].active_writers), 0);
		}
		/*all levels locked*/
		dirty += db_desc->dirty;
		/*update the catalogue if db is dirty*/
		if (db_desc->dirty > 0) {
			/*cow check*/
			db_group =
				(pr_db_group *)(MAPPED +
						(uint64_t)volume_desc->mem_catalogue->db_group_index[db_desc->group_id]);
			//printf("[%s:%s:%d] check for cow on db_group %llu\n",__FILE__,__func__,__LINE__,(LLU)db_group);
			if (db_group->epoch <= volume_desc->dev_catalogue->epoch) {
				/*do cow*/
				//superindex_db_group * new_group = (superindex_db_group *)allocate(volume_desc,DEVICE_BLOCK_SIZE,-1,GROUP_COW);
				pr_db_group *new_group =
					(pr_db_group *)get_space_for_system(volume_desc, sizeof(pr_db_group));

				memcpy(new_group, db_group, sizeof(pr_db_group));
				new_group->epoch = volume_desc->mem_catalogue->epoch;
				free_block(volume_desc, db_group, sizeof(pr_db_group), -1);
				db_group = new_group;
				volume_desc->mem_catalogue->db_group_index[db_desc->group_id] =
					(pr_db_group *)((uint64_t)db_group - MAPPED);
			}

			db_entry = &db_group->db_entries[db_desc->group_index];

			for (i = 0; i < MAX_LEVELS; i++) {
				for (j = 0; j < NUM_TREES_PER_LEVEL; j++) {
					/*Serialize and persist space allocation info for all levels*/
					if (db_desc->levels[i].last_segment[j] != NULL) {
						db_entry->first_segment[(i * MAX_LEVELS) + j] =
							(uint64_t)db_desc->levels[i].first_segment[j] - MAPPED;

						db_entry->last_segment[(i * MAX_LEVELS) + j] =
							(uint64_t)db_desc->levels[i].last_segment[j] - MAPPED;

						db_entry->offset[(i * MAX_LEVELS) + j] =
							(uint64_t)db_desc->levels[i].offset[j] - MAPPED;
					} else {
						db_entry->first_segment[(i * MAX_LEVELS) + j] = 0;

						db_entry->last_segment[(i * MAX_LEVELS) + j] = 0;

						db_entry->offset[(i * MAX_LEVELS) + j] = 0;
					}

					/*now mark new roots*/
					if (db_desc->levels[i].root_w[j] != NULL) {
						db_entry->root_r[i * j] =
							((uint64_t)db_desc->levels[i].root_w[j]) - MAPPED;

						/*mark old root to free it later*/
						old_root = db_desc->levels[i].root_r[j];
						db_desc->levels[i].root_r[j] = db_desc->levels[i].root_w[j];
						db_desc->levels[i].root_w[j] = NULL;

						if (old_root) {
							if (old_root->type == rootNode)
								free_block(volume_desc, old_root, INDEX_NODE_SIZE, -1);
							else
								free_block(volume_desc, old_root, LEAF_NODE_SIZE, -1);
						}

					} else if (db_desc->levels[i].root_r[j] == NULL) {
						//log_warn("set %lu to %llu of db_entry %llu", i * j,
						//	 db_entry->root_r[(i * MAX_LEVELS) + j], (uint64_t)db_entry - MAPPED);
						db_entry->root_r[(i * MAX_LEVELS) + j] = 0;
					}

					db_entry->total_keys[i] = db_desc->levels[i].total_keys[j];
				}
			}
			/*KV log status, not needed commit log is the truth*/
			//db_group->db_entries[db_desc->group_index].KV_log_first_segment = (segment_header *)((uint64_t)db_desc->KV_log_first_segment - MAPPED);
			//db_group->db_entries[db_desc->group_index].KV_log_last_segment =  (segment_header *)((uint64_t)db_desc->KV_log_last_segment - MAPPED);
			//db_group->db_entries[db_desc->group_index].KV_log_size = (uint64_t)db_desc->KV_log_size;
			db_entry->commit_log = (uint64_t)db_desc->commit_log - MAPPED;

			/*L0 bounds*/
			commit_db_log(db_desc);
			db_desc->L0_start_log_offset = db_desc->KV_log_size;
			db_desc->L0_end_log_offset = db_desc->KV_log_size;
			db_entry->L0_start_log_offset = (uint64_t)db_desc->L0_start_log_offset;
			db_entry->L0_end_log_offset = (uint64_t)db_desc->L0_end_log_offset;
		}
		node = node->next;
	}
	if (dirty > 0) { /*At least one db is dirty proceed to snapshot()*/

		free_block(volume_desc, volume_desc->dev_catalogue, sizeof(pr_system_catalogue), -1);
		volume_desc->dev_catalogue = volume_desc->mem_catalogue;
		/*allocate a new position for superindex*/

		pr_system_catalogue *tmp =
			(pr_system_catalogue *)get_space_for_system(volume_desc, sizeof(pr_system_catalogue));
		memcpy(tmp, volume_desc->dev_catalogue, sizeof(pr_system_catalogue));
		++tmp->epoch;
		volume_desc->mem_catalogue = tmp;

		/*XXX TODO XXX write superblock(!), caution! this command in future version should be executed after msync*/
		volume_desc->volume_superblock->system_catalogue =
			(pr_system_catalogue *)((uint64_t)volume_desc->dev_catalogue - MAPPED);

		/*protect this segment because cleaner may run in parallel */
		MUTEX_LOCK(&volume_desc->allocator_lock);
		/*update allocator state, soft state staff */
		for (l = 0; l < volume_desc->allocator_size; l += 8) {
			a = *(uint64_t *)((uint64_t)(volume_desc->allocator_state) + l);
			b = *(uint64_t *)((uint64_t)(volume_desc->sync_signal) + l);
			c = a ^ b;
			if ((c - a) != 0) {
#ifdef DEBUG_SNAPSHOT
				log_debug("Updating automaton state");
				log_debug("allocator = %llu ", (LLU)a);
				log_debug("sync_signal = %llu ", (LLU)b);
				log_debug("Result = %llu \n", (LLU)c);
#endif
				*(uint64_t *)((uint64_t)(volume_desc->allocator_state) + i) = c;
			}
		}
		memset(volume_desc->sync_signal, 0x00, volume_desc->allocator_size);
		MUTEX_UNLOCK(&volume_desc->allocator_lock);
		//pthread_mutex_unlock(&(volume_desc->allocator_lock)); /*ok release allocator lock */
	}

	volume_desc->last_snapshot = get_timestamp(); /*update snapshot ts*/
	volume_desc->last_commit = volume_desc->last_snapshot;
	volume_desc->last_sync = get_timestamp(); /*update snapshot ts*/

	/*release locks*/
	node = get_first(volume_desc->open_databases);
	while (node != NULL) {
		db_desc = (db_descriptor *)node->data;
		db_desc->dirty = 0x00;
#if LOG_WITH_MUTEX
		MUTEX_UNLOCK(&db_desc->lock_log);
#else
		SPIN_UNLOCK(&db_desc->lock_log);
#endif
		for (i = 0; i < MAX_LEVELS; i++)
			RWLOCK_UNLOCK(&db_desc->levels[i].guard_of_level.rx_lock);

		node = node->next;
	}
	volume_desc->snap_preemption = SNAP_INTERRUPT_DISABLE;

	if (dirty > 0) { /*At least one db is dirty proceed to snapshot()*/
		//double t1,t2;
		//struct timeval tim;

		//gettimeofday(&tim, NULL);
		//t1=tim.tv_sec+(tim.tv_usec/1000000.0);
		log_info("Syncing volume... from %llu to %llu", volume_desc->start_addr, volume_desc->size);
		if (msync(volume_desc->start_addr, volume_desc->size, MS_SYNC) != 0) {
			log_fatal("Error at msync start_addr %llu size %llu", (LLU)volume_desc->start_addr,
				  (LLU)volume_desc->size);
			switch (errno) {
			case EBUSY:
				log_error("msync returned EBUSY");
			case EINVAL:
				log_error("msync returned EINVAL");
			case ENOMEM:
				log_error("msync returned EBUSY");
			}
			exit(EXIT_FAILURE);
		}
		//gettimeofday(&tim, NULL);
		//t2=tim.tv_sec+(tim.tv_usec/1000000.0);
		//fprintf(stderr, "snap_time=[%lf]sec\n", (t2-t1));
	}

	/*stats counters*/
	//printf("[%s:%s:%d] hit l0 %lld miss l0 %lld hit l1 %lld miss l1 %lld\n",__FILE__,__func__,__LINE__,ins_prefix_hit_l0,ins_prefix_miss_l0,ins_prefix_hit_l1, ins_prefix_miss_l1);
	//printf("[%s:%s:%d] L-0 hit ratio %lf\n",__FILE__,__func__,__LINE__,(double)ins_prefix_hit_l0/(double)(ins_prefix_hit_l0+ins_prefix_miss_l0)*100);
	//printf("[%s:%s:%d] L-1 hit ratio %lf\n",__FILE__,__func__,__LINE__,(double)ins_prefix_hit_l1/(double)(ins_prefix_hit_l1+ins_prefix_miss_l1)*100);
	//printf("[%s:%s:%d] hack hit %llu hack miss %llu\n",__FILE__,__func__,__LINE__,ins_hack_hit,ins_hack_miss);
}

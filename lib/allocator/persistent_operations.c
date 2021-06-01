#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <log.h>
#include <list.h>
#include <spin_loop.h>
#include "allocator.h"
#include "../btree/btree.h"
#include "../btree/segment_allocator.h"
#include "../btree/conf.h"

#if 0
void write_log_metadata(db_descriptor *db_desc, commit_log_info *info)
{
	/*write log info*/
	if (info->big_log_head != NULL)
		db_desc->commit_log->big_log_head = (segment_header *)ABSOLUTE_ADDRESS(info->big_log_head);
	else
		db_desc->commit_log->big_log_head = NULL;

	if (info->big_log_tail != NULL)
		db_desc->commit_log->big_log_tail = (segment_header *)ABSOLUTE_ADDRESS(info->big_log_tail);
	else
		db_desc->commit_log->big_log_tail = NULL;

	/*write log info*/
	if (info->medium_log_head != NULL)
		db_desc->commit_log->medium_log_head = (segment_header *)ABSOLUTE_ADDRESS(info->medium_log_head);
	else
		db_desc->commit_log->medium_log_head = NULL;

	if (info->medium_log_tail != NULL)
		db_desc->commit_log->medium_log_tail = (segment_header *)ABSOLUTE_ADDRESS(info->medium_log_tail);
	else
		db_desc->commit_log->medium_log_tail = NULL;

	/*write log info*/
	if (info->small_log_head != NULL)
		db_desc->commit_log->small_log_head = (segment_header *)ABSOLUTE_ADDRESS(info->small_log_head);
	else
		db_desc->commit_log->small_log_head = NULL;

	if (info->small_log_tail != NULL)
		db_desc->commit_log->small_log_tail = (segment_header *)ABSOLUTE_ADDRESS(info->small_log_tail);
	else
		db_desc->commit_log->small_log_tail = NULL;

	db_desc->commit_log->big_log_size = info->big_log_size;
	db_desc->commit_log->medium_log_size = info->medium_log_size;
	db_desc->commit_log->small_log_size = info->small_log_size;
}

/*persists the KV-log of a DB, not thread safe!*/
void commit_db_log(db_descriptor *db_desc, commit_log_info *info)
{
	segment_header *big_log_current_segment, *big_log_first_segment, *big_log_last_segment;
	segment_header *medium_log_current_segment, *medium_log_first_segment, *medium_log_last_segment;
	segment_header *small_log_current_segment, *small_log_first_segment, *small_log_last_segment;
	unsigned all_logs_persisted = 1;

	/*sync data then metadata*/
	big_log_first_segment = (segment_header *)REAL_ADDRESS(db_desc->commit_log->big_log_tail);
	medium_log_first_segment = (segment_header *)REAL_ADDRESS(db_desc->commit_log->medium_log_tail);
	small_log_first_segment = (segment_header *)REAL_ADDRESS(db_desc->commit_log->small_log_tail);

	big_log_last_segment = info->big_log_tail;
	medium_log_last_segment = info->medium_log_tail;
	small_log_last_segment = info->small_log_tail;

	big_log_current_segment = big_log_first_segment;
	medium_log_current_segment = medium_log_first_segment;
	small_log_current_segment = small_log_first_segment;

	db_desc->commit_log->lsn = info->lsn;

	while (all_logs_persisted) {
		all_logs_persisted = 0;

		msync(big_log_current_segment, SEGMENT_SIZE, MS_SYNC);
		msync(medium_log_current_segment, SEGMENT_SIZE, MS_SYNC);
		msync(small_log_current_segment, SEGMENT_SIZE, MS_SYNC);

#ifdef DEBUG_COMMIT
		log_info("Committed Segment id %llu", big_log_current_segment->segment_id);
		log_info("Committed Segment id %llu", medium_log_current_segment->segment_id);
		log_info("Committed Segment id %llu", small_log_current_segment->segment_id);
#endif

		if (big_log_current_segment != big_log_last_segment) {
			big_log_current_segment = (segment_header *)REAL_ADDRESS(big_log_current_segment->next_segment);
			++all_logs_persisted;
		}

		if (medium_log_current_segment->next_segment != NULL &&
		    medium_log_current_segment != medium_log_last_segment) {
			medium_log_current_segment =
				(segment_header *)REAL_ADDRESS(medium_log_current_segment->next_segment);
			++all_logs_persisted;
		}

		if (small_log_current_segment != small_log_last_segment) {
			small_log_current_segment =
				(segment_header *)REAL_ADDRESS(small_log_current_segment->next_segment);
			++all_logs_persisted;
		}
	}

	write_log_metadata(db_desc, info);

	if (msync(db_desc->commit_log, sizeof(commit_log_info), MS_SYNC) == -1) {
		log_fatal("msync failed");
		exit(EXIT_FAILURE);
	}

	return;
}

void commit_db_logs_per_volume(volume_descriptor *volume_desc)
{
	struct commit_log_info info;
	struct klist_node *node;

	db_descriptor *db_desc;
	node = klist_get_first(volume_desc->open_databases);

	while (node != NULL) {
		db_desc = (db_descriptor *)(node->data);
		/*stop level 0 writers for this db*/
		RWLOCK_WRLOCK(&db_desc->levels[0].guard_of_level.rx_lock);
		/*spinning*/
		spin_loop(&(db_desc->levels[0].active_writers), 0);

#if LOG_WITH_MUTEX
		MUTEX_LOCK(&db_desc->lock_log);
#else
		SPIN_LOCK(&db_desc->lock_log);
#endif
		info.big_log_head = (segment_header *)db_desc->big_log_head;
		info.big_log_tail = (segment_header *)db_desc->big_log_tail;
		info.big_log_size = db_desc->big_log_size;

		info.medium_log_head = (segment_header *)db_desc->medium_log_head;
		info.medium_log_tail = (segment_header *)db_desc->medium_log_tail;
		info.medium_log_size = db_desc->medium_log_size;

		info.small_log_head = (segment_header *)db_desc->small_log_head;
		info.small_log_tail = (segment_header *)db_desc->small_log_tail;
		info.small_log_size = db_desc->small_log_size;
		info.lsn = db_desc->lsn;
#if LOG_WITH_MUTEX
		MUTEX_UNLOCK(&db_desc->lock_log);
#else
		SPIN_UNLOCK(&db_desc->lock_log);
#endif
		RWLOCK_UNLOCK(&db_desc->levels[0].guard_of_level.rx_lock);

		if (db_desc->commit_log->big_log_size != db_desc->big_log_size ||
		    db_desc->commit_log->medium_log_size != db_desc->medium_log_size ||
		    db_desc->commit_log->small_log_size != db_desc->small_log_size)
			commit_db_log(db_desc, &info);

		node = node->next;
	}
}
#endif

/*As normal snapshot except it increases system's epoch
 * even in the case where no writes have taken place
 */
void force_snapshot(volume_descriptor *volume_desc)
{
	volume_desc->force_snapshot = 1;
	snapshot(volume_desc);
}

void pr_flush_log_tail(struct db_descriptor *db_desc, struct volume_descriptor *volume_desc,
		       struct bt_log_descriptor *log_desc)
{
	(void)db_desc;
	(void)volume_desc;
	int last_tail = log_desc->curr_tail_id % LOG_TAIL_NUM_BUFS;
	uint64_t offt_in_seg = log_desc->size % SEGMENT_SIZE;
	uint64_t start_offt, end_offt;
	uint32_t chunk_id;
	uint32_t idx = log_desc->size % SEGMENT_SIZE;
	uint32_t remaining_bytes = 0;

	if (idx) {
		remaining_bytes = SEGMENT_SIZE - idx;
		memset(&log_desc->tail[last_tail]->buf[idx], 0, remaining_bytes);
		log_desc->size += remaining_bytes;
	} else
		return;

	chunk_id = offt_in_seg / LOG_CHUNK_SIZE;

	for (int i = chunk_id; i < SEGMENT_SIZE / LOG_CHUNK_SIZE; ++i)
		log_desc->tail[last_tail]->bytes_in_chunk[i] = LOG_CHUNK_SIZE;

	log_desc->tail[last_tail]->IOs_completed_in_tail = SEGMENT_SIZE / LOG_CHUNK_SIZE;

	if (chunk_id)
		start_offt = chunk_id * LOG_CHUNK_SIZE;
	else
		start_offt = sizeof(struct segment_header);

	start_offt = sizeof(segment_header);
	ssize_t bytes_written = 0;
	/* end_offt = start_offt + LOG_CHUNK_SIZE; */
	end_offt = SEGMENT_SIZE /* - start_offt */;
	while (start_offt < end_offt) {
		bytes_written = pwrite(FD, &log_desc->tail[last_tail]->buf[start_offt], end_offt - start_offt,
				       log_desc->tail[last_tail]->dev_offt + start_offt);

		if (bytes_written == -1) {
			log_fatal("Failed to write LOG_CHUNK reason follows");
			perror("Reason");
			exit(EXIT_FAILURE);
		}
		start_offt += bytes_written;
	}
}

/*persists a consistent snapshot of the system*/
void snapshot(volume_descriptor *volume_desc)
{
	//struct commit_log_info log_info;
	pr_db_group *db_group;
	pr_db_entry *db_entry;
	node_header *old_root;
	uint32_t i;
	uint32_t j;
	int32_t dirty = 0;
	uint8_t level_id;

	log_info("trigerring snapshot");
	volume_desc->snap_preemption = SNAP_INTERRUPT_ENABLE;
	/*1. Acquire all write locks for each database of the specific volume*/
	struct klist_node *node = klist_get_first(volume_desc->open_databases);
	db_descriptor *db_desc;

	while (node != NULL) {
		db_desc = (db_descriptor *)node->data;

		/*stop all level writers*/
		for (level_id = 0; level_id < MAX_LEVELS; level_id++) {
			/*stop level 0 writers for this db*/
			RWLOCK_WRLOCK(&db_desc->levels[level_id].guard_of_level.rx_lock);
		}

		for (level_id = 0; level_id < MAX_LEVELS; level_id++)
			spin_loop(&(db_desc->levels[level_id].active_writers), 0);

		//all levels locked
		dirty += db_desc->dirty;
		/*update the catalogue if db is dirty*/
		if (db_desc->dirty > 0) {
			pr_flush_log_tail(db_desc, volume_desc, &db_desc->small_log);
			pr_flush_log_tail(db_desc, volume_desc, &db_desc->medium_log);
			pr_flush_log_tail(db_desc, volume_desc, &db_desc->big_log);
			db_desc->dirty = 0x00;
			/*cow check*/
			db_group = (pr_db_group *)REAL_ADDRESS(
				volume_desc->mem_catalogue->db_group_index[db_desc->group_id]);

			if (!db_group) {
				log_fatal("db_group is NULL!");
				assert(0);
				exit(EXIT_FAILURE);
			}
			//log_info("group epoch %llu  dev_catalogue %llu", (LLU)db_group->epoch,
			// volume_desc->dev_catalogue->epoch);

			if (db_group->epoch <= volume_desc->dev_catalogue->epoch) {
				//log_info("cow for db_group %llu", (LLU)db_group);
				/*do cow*/
				//superindex_db_group * new_group = (superindex_db_group *)allocate(volume_desc,DEVICE_BLOCK_SIZE,-1,GROUP_COW);
				pr_db_group *new_group =
					(pr_db_group *)get_space_for_system(volume_desc, sizeof(pr_db_group), 0);

				memcpy(new_group, db_group, sizeof(pr_db_group));
				new_group->epoch = volume_desc->mem_catalogue->epoch;
				free_block(volume_desc, db_group, sizeof(pr_db_group));
				db_group = new_group;
				volume_desc->mem_catalogue->db_group_index[db_desc->group_id] =
					(pr_db_group *)ABSOLUTE_ADDRESS(db_group);
			}

			db_entry = &(db_group->db_entries[db_desc->group_index]);
			//log_info("pr db entry name %s db name %s", db_entry->db_name, db_desc->db_name);

			for (i = 1; i < MAX_LEVELS; i++) {
				for (j = 0; j < NUM_TREES_PER_LEVEL; j++) {
					/*Serialize and persist space allocation info for all levels*/
					if (db_desc->levels[i].last_segment[j] != NULL) {
						db_entry->first_segment[i][j] =
							ABSOLUTE_ADDRESS(db_desc->levels[i].first_segment[j]);
						db_entry->last_segment[i][j] =
							ABSOLUTE_ADDRESS(db_desc->levels[i].last_segment[j]);
						db_entry->offset[i][j] = db_desc->levels[i].offset[j];
					} else {
						db_entry->first_segment[i][j] = 0;
						db_entry->last_segment[i][j] = 0;
						db_entry->offset[i][j] = 0;
					}

					/*now mark new roots*/
					if (db_desc->levels[i].root_w[j] != NULL) {
						db_entry->root_r[i][j] = ABSOLUTE_ADDRESS(db_desc->levels[i].root_w[j]);

						/*mark old root to free it later*/
						old_root = db_desc->levels[i].root_r[j];
						db_desc->levels[i].root_r[j] = db_desc->levels[i].root_w[j];
						db_desc->levels[i].root_w[j] = NULL;

						if (old_root) {
							if (old_root->type == rootNode)
								free_block(volume_desc, old_root, INDEX_NODE_SIZE);
							else
								free_block(volume_desc, old_root, LEAF_NODE_SIZE);
						}

					} else if (db_desc->levels[i].root_r[j] == NULL) {
						//log_warn("set %lu to %llu of db_entry %llu", i * j,
						//	 db_entry->root_r[(i * MAX_LEVELS) + j], (uint64_t)db_entry - MAPPED);
						db_entry->root_r[i][j] = 0;
					}

					db_entry->level_size[i][j] = db_desc->levels[i].level_size[j];
				}
			}

			db_entry->big_log_head_offt = db_desc->big_log.head_dev_offt;
			db_entry->big_log_tail_offt = db_desc->big_log.tail_dev_offt;
			db_entry->big_log_size = db_desc->big_log.size;

			db_entry->medium_log_head_offt = db_desc->medium_log.head_dev_offt;
			db_entry->medium_log_tail_offt = db_desc->medium_log.tail_dev_offt;
			db_entry->medium_log_size = db_desc->medium_log.size;

			db_entry->small_log_head_offt = db_desc->small_log.head_dev_offt;
			db_entry->small_log_tail_offt = db_desc->small_log.tail_dev_offt;
			db_entry->small_log_size = db_desc->small_log.size;
		}
		node = node->next;
	}

	if (dirty > 0) {
		//At least one db is dirty proceed to snapshot()
		free_block(volume_desc, volume_desc->dev_catalogue, sizeof(pr_system_catalogue));
		volume_desc->dev_catalogue = volume_desc->mem_catalogue;
		/*allocate a new position for superindex*/

		pr_system_catalogue *tmp =
			(pr_system_catalogue *)get_space_for_system(volume_desc, sizeof(pr_system_catalogue), 0);
		memcpy(tmp, volume_desc->dev_catalogue, sizeof(pr_system_catalogue));
		++tmp->epoch;
		volume_desc->mem_catalogue = tmp;

		volume_desc->volume_superblock->system_catalogue =
			(pr_system_catalogue *)ABSOLUTE_ADDRESS(volume_desc->dev_catalogue);

		bitmap_set_buddies_immutable(volume_desc);

		MUTEX_UNLOCK(&volume_desc->bitmap_lock);
	}

	volume_desc->last_snapshot = get_timestamp(); /*update snapshot ts*/
	volume_desc->last_commit = volume_desc->last_snapshot;
	volume_desc->last_sync = get_timestamp(); /*update snapshot ts*/
	if (dirty > 0) { /*At least one db is dirty proceed to snapshot()*/
		//double t1,t2;
		//struct timeval tim;

		//gettimeofday(&tim, NULL);
		//t1=tim.tv_sec+(tim.tv_usec/1000000.0);
		log_info("Syncing volume... from %llu to %llu", volume_desc->start_addr, volume_desc->size);
#if 0
		if (msync(volume_desc->start_addr, volume_desc->size, MS_SYNC) != 0) {
			log_fatal("Error at msync start_addr %llu size %llu",
				  (long long unsigned)volume_desc->start_addr, (long long unsigned)volume_desc->size);
			switch (errno) {
			case EBUSY:
				log_error("msync returned EBUSY");
				break;
			case EINVAL:
				log_error("msync returned EINVAL");
				break;
			case ENOMEM:
				log_error("msync returned ENOMEM");
				break;
			}
			exit(EXIT_FAILURE);
		}
#endif
		//gettimeofday(&tim, NULL);
		//t2=tim.tv_sec+(tim.tv_usec/1000000.0);
		//fprintf(stderr, "snap_time=[%lf]sec\n", (t2-t1));
	}
	volume_desc->snap_preemption = SNAP_INTERRUPT_DISABLE;

	/*release locks*/
	node = klist_get_first(volume_desc->open_databases);

	while (node != NULL) {
		db_desc = (db_descriptor *)node->data;

		for (i = 0; i < MAX_LEVELS; i++)
			RWLOCK_UNLOCK(&db_desc->levels[i].guard_of_level.rx_lock);

		node = node->next;
	}
}

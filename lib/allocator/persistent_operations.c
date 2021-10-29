#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <log.h>
#include <list.h>
#include <spin_loop.h>
#include "device_structures.h"
#include "log_structures.h"
#include "volume_manager.h"
#include "redo_undo_log.h"
#include "../btree/btree.h"
#include "../btree/segment_allocator.h"
#include "../btree/conf.h"

/*As normal snapshot except it increases system's epoch
 * even in the case where no writes have taken place
 */
void force_snapshot(volume_descriptor *volume_desc)
{
	volume_desc->force_snapshot = 1;
	snapshot(volume_desc);
}

/*<new_persistent_design>*/
void pr_flush_L0(struct db_descriptor *db_desc, uint8_t tree_id)
{
	struct my_log_info {
		uint64_t tail_dev_offt;
		uint64_t size;
	};

	struct my_log_info large_log;
	struct my_log_info L0_recovery_log;

	MUTEX_LOCK(&db_desc->flush_L0_lock);

	/*Lock logs L0_recovery_log, medium, and Large locked*/
	MUTEX_LOCK(&db_desc->lock_log);

	/*keep large log state prior to releasing the lock*/
	large_log.tail_dev_offt = db_desc->big_log.tail_dev_offt;
	large_log.size = db_desc->big_log.size;
	/*keep L0_recovery_log state prior to releasing the lock*/
	L0_recovery_log.tail_dev_offt = db_desc->small_log.tail_dev_offt;
	L0_recovery_log.size = db_desc->small_log.size;
	MUTEX_UNLOCK(&db_desc->lock_log);
	/*
   * Flush large and L0_recovery_log may flush more. We do this
   * 1)To avoid holding all logs lock while doing I/O
   * 2)We are sure that the (tail, size) of the previous step
   * will be at the device
  */
	/*Flush large log*/
	pr_flush_log_tail(db_desc, db_desc->my_volume, &db_desc->big_log);
	/*Flush L0 recovery log*/
	pr_flush_log_tail(db_desc, db_desc->my_volume, &db_desc->small_log);

	/*time to write superblock*/
	pr_lock_region_superblock(db_desc);
	/*Flush my allocations*/
	struct rul_log_info rul_log = rul_flush_txn(db_desc, db_desc->levels[0].allocation_txn_id[tree_id]);
	/*new info about large*/
	db_desc->my_superblock.big_log_tail_offt = large_log.tail_dev_offt;
	db_desc->my_superblock.big_log_size = large_log.size;
	/*new info about L0_recovery_log*/
	db_desc->my_superblock.small_log_tail_offt = L0_recovery_log.tail_dev_offt;
	db_desc->my_superblock.small_log_size = L0_recovery_log.size;
	/*new info about allocation_log*/
	db_desc->my_superblock.allocation_log.tail_dev_offt = rul_log.tail_dev_offt;
	db_desc->my_superblock.allocation_log.size = rul_log.size;
	db_desc->my_superblock.allocation_log.txn_id = rul_log.txn_id;
	/*flush region superblock*/
	pr_flush_region_superblock(db_desc);

	pr_unlock_region_superblock(db_desc);

	MUTEX_UNLOCK(&db_desc->flush_L0_lock);
}

static void pr_flush_L0_to_L1(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	struct my_log_info {
		uint64_t tail_dev_offt;
		uint64_t size;
	};

	struct my_log_info medium_log;
	/*
   *Keep medium log state. We don't need to lock because ONLY one compaction
   * from L0 to L1 is allowed.
  */
	medium_log.tail_dev_offt = db_desc->medium_log.tail_dev_offt;
	medium_log.size = db_desc->medium_log.size;
	/*Flush medium log*/
	pr_flush_log_tail(db_desc, db_desc->my_volume, &db_desc->medium_log);
	pr_lock_region_superblock(db_desc);
	/*medium log info*/
	db_desc->my_superblock.medium_log_tail_offt = medium_log.tail_dev_offt;
	db_desc->my_superblock.medium_log_size = medium_log.size;
	/*Flush my allocations*/
	struct rul_log_info rul_log = rul_flush_txn(db_desc, db_desc->levels[0].allocation_txn_id[tree_id]);
	/*new info about allocation_log*/
	db_desc->my_superblock.allocation_log.tail_dev_offt = rul_log.tail_dev_offt;
	db_desc->my_superblock.allocation_log.size = rul_log.size;
	db_desc->my_superblock.allocation_log.txn_id = rul_log.txn_id;
	/*new info about my level*/
	db_desc->my_superblock.root_r[level_id][tree_id] = ABSOLUTE_ADDRESS(db_desc->levels[level_id].root_r[tree_id]);
	db_desc->my_superblock.first_segment[level_id][0] =
		ABSOLUTE_ADDRESS(db_desc->levels[level_id].first_segment[tree_id]);
	db_desc->my_superblock.last_segment[level_id][tree_id] =
		ABSOLUTE_ADDRESS(db_desc->levels[level_id].last_segment[tree_id]);
	db_desc->my_superblock.offset[level_id][tree_id] = db_desc->levels[level_id].offset[tree_id];
	db_desc->my_superblock.level_size[level_id][tree_id] = db_desc->levels[level_id].level_size[tree_id];
	pr_flush_region_superblock(db_desc);

	pr_unlock_region_superblock(db_desc);
}

static void pr_flush_Lmax_to_Ln(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	pr_lock_region_superblock(db_desc);
	/*Flush my allocations*/
	struct rul_log_info rul_log = rul_flush_txn(db_desc, db_desc->levels[0].allocation_txn_id[tree_id]);
	/*new info about allocation_log*/
	db_desc->my_superblock.allocation_log.tail_dev_offt = rul_log.tail_dev_offt;
	db_desc->my_superblock.allocation_log.size = rul_log.size;
	db_desc->my_superblock.allocation_log.txn_id = rul_log.txn_id;
	/*new info about my level*/
	db_desc->my_superblock.root_r[level_id][tree_id] = ABSOLUTE_ADDRESS(db_desc->levels[level_id].root_r[tree_id]);
	db_desc->my_superblock.first_segment[level_id][0] =
		ABSOLUTE_ADDRESS(db_desc->levels[level_id].first_segment[tree_id]);
	db_desc->my_superblock.last_segment[level_id][tree_id] =
		ABSOLUTE_ADDRESS(db_desc->levels[level_id].last_segment[tree_id]);
	db_desc->my_superblock.offset[level_id][tree_id] = db_desc->levels[level_id].offset[tree_id];
	db_desc->my_superblock.level_size[level_id][tree_id] = db_desc->levels[level_id].level_size[tree_id];
	pr_flush_region_superblock(db_desc);

	pr_unlock_region_superblock(db_desc);
}

void pr_flush_compaction(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id)
{
	if (level_id == 1)
		return pr_flush_L0_to_L1(db_desc, level_id, tree_id);

	if (level_id == LEVEL_MEDIUM_INPLACE)
		return pr_flush_Lmax_to_Ln(db_desc, level_id, tree_id);

	pr_lock_region_superblock(db_desc);
	/*Flush my allocations*/
	struct rul_log_info rul_log = rul_flush_txn(db_desc, db_desc->levels[0].allocation_txn_id[tree_id]);
	/*new info about allocation_log*/
	db_desc->my_superblock.allocation_log.tail_dev_offt = rul_log.tail_dev_offt;
	db_desc->my_superblock.allocation_log.size = rul_log.size;
	db_desc->my_superblock.allocation_log.txn_id = rul_log.txn_id;
	/*new info about my level*/

	db_desc->my_superblock.root_r[level_id][tree_id] = ABSOLUTE_ADDRESS(db_desc->levels[level_id].root_r[tree_id]);
	db_desc->my_superblock.first_segment[level_id][0] =
		ABSOLUTE_ADDRESS(db_desc->levels[level_id].first_segment[tree_id]);
	db_desc->my_superblock.last_segment[level_id][tree_id] =
		ABSOLUTE_ADDRESS(db_desc->levels[level_id].last_segment[tree_id]);
	db_desc->my_superblock.offset[level_id][tree_id] = db_desc->levels[level_id].offset[tree_id];
	db_desc->my_superblock.level_size[level_id][tree_id] = db_desc->levels[level_id].level_size[tree_id];
	pr_flush_region_superblock(db_desc);

	pr_unlock_region_superblock(db_desc);
}

void pr_lock_region_superblock(struct db_descriptor *db_desc)
{
	MUTEX_LOCK(&db_desc->my_superblock_lock);
}

void pr_unlock_region_superblock(struct db_descriptor *db_desc)
{
	MUTEX_UNLOCK(&db_desc->my_superblock_lock);
}

void pr_flush_region_superblock(struct db_descriptor *db_desc)
{
	uint64_t my_superblock_offt =
		sizeof(struct superblock) + (sizeof(struct pr_region_superblock) + db_desc->my_superblock_idx);
	ssize_t total_bytes_written = 0;
	ssize_t bytes_written = 0;
	ssize_t size = sizeof(struct pr_region_superblock);
	while (total_bytes_written < size) {
		bytes_written = pwrite(db_desc->my_volume->my_fd, &db_desc->my_superblock, size - total_bytes_written,
				       my_superblock_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to write region's %s superblock", db_desc->my_superblock.region_name);
			perror("Reason");
			exit(EXIT_FAILURE);
		}
		total_bytes_written += bytes_written;
	}
}

void pr_read_region_superblock(struct db_descriptor *db_desc)
{
	//where is my superblock
	ssize_t total_bytes_written = 0;
	ssize_t bytes_written = 0;
	ssize_t size = sizeof(struct pr_region_superblock);
	uint64_t my_superblock_offt =
		sizeof(struct superblock) + (sizeof(struct pr_region_superblock) + db_desc->my_superblock_idx);

	while (total_bytes_written < size) {
		bytes_written = pwrite(db_desc->my_volume->my_fd, &db_desc->my_superblock, size - total_bytes_written,
				       my_superblock_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to read region's %s superblock", db_desc->my_superblock.region_name);
			perror("Reason");
			assert(0);
			exit(EXIT_FAILURE);
		}
		total_bytes_written += bytes_written;
	}
}
/*</new_persistent_design>*/

void pr_flush_log_tail(struct db_descriptor *db_desc, struct volume_descriptor *volume_desc,
		       struct log_descriptor *log_desc)
{
	(void)db_desc;
	(void)volume_desc;

	uint64_t offt_in_seg = log_desc->size % SEGMENT_SIZE;
	if (!offt_in_seg)
		return;

	int last_tail = log_desc->curr_tail_id % LOG_TAIL_NUM_BUFS;

	/*Barrier wait all previous operations to finish*/
	uint32_t chunk_id = offt_in_seg / LOG_CHUNK_SIZE;
	for (uint32_t i = 0; i < chunk_id; ++i)
		wait_for_value(&log_desc->tail[last_tail]->bytes_in_chunk[i], LOG_CHUNK_SIZE);

	uint64_t start_offt;
	if (chunk_id)
		start_offt = chunk_id * LOG_CHUNK_SIZE;
	else
		start_offt = sizeof(struct segment_header);

	ssize_t bytes_written = 0;
	uint64_t end_offt = start_offt + LOG_CHUNK_SIZE;
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
	struct pr_db_group *db_group;
	struct pr_db_entry *db_entry;
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
			db_group = (struct pr_db_group *)REAL_ADDRESS(
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
				struct pr_db_group *new_group = (struct pr_db_group *)get_space_for_system(
					volume_desc, sizeof(struct pr_db_group), 0);

				memcpy(new_group, db_group, sizeof(struct pr_db_group));
				new_group->epoch = volume_desc->mem_catalogue->epoch;
				free_block(volume_desc, db_group, sizeof(struct pr_db_group));
				db_group = new_group;
				volume_desc->mem_catalogue->db_group_index[db_desc->group_id] =
					(struct pr_db_group *)ABSOLUTE_ADDRESS(db_group);
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
		free_block(volume_desc, volume_desc->dev_catalogue, sizeof(struct pr_system_catalogue));
		volume_desc->dev_catalogue = volume_desc->mem_catalogue;
		/*allocate a new position for superindex*/

		struct pr_system_catalogue *tmp = (struct pr_system_catalogue *)get_space_for_system(
			volume_desc, sizeof(struct pr_system_catalogue), 0);
		memcpy(tmp, volume_desc->dev_catalogue, sizeof(struct pr_system_catalogue));
		++tmp->epoch;
		volume_desc->mem_catalogue = tmp;

		volume_desc->volume_superblock->system_catalogue =
			(struct pr_system_catalogue *)ABSOLUTE_ADDRESS(volume_desc->dev_catalogue);

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

#ifndef PERSISTENT_OPERATIONS_H_
#define PERSISTENT_OPERATIONS_H_

#include "../btree/btree.h"
#include "log_structures.h"
#include <stdint.h>
/**
 * Returns number of garbage entries detected during the recovery of the redo undo log.
 */
uint32_t get_garbage_entries(void);

/**
 * Returns garbage bytes detected during the recovery of the redo undo log.
 */
uint32_t get_garbage_bytes(void);

/**
 * Triggers the counting for blobs garbage bytes when recovering redo_undo_log.
 */
void enable_validation_garbage_bytes(void);

/**
 * Disables the counting for blobs garbage bytes when recovering redo_undo_log.
 */
void disable_validation_garbage_bytes(void);

/**
 * Persists L0 key value pairs in storage making it recoverable.
 * in L0 during a compaction operation from L0 to L1. As a result, valid tree_id
 * values are from 0 to NUM_TREES_PER_LEVEL-1.
 * @param db_desc is the descriptor of the db
 * @param tree_id The id of the tree in L0. Parallax performs double buffering
 */
void pr_flush_L0(struct db_descriptor *db_desc, uint8_t tree_id);

void pr_read_db_superblock(struct db_descriptor *db_desc);

void pr_flush_db_superblock(struct db_descriptor *db_desc);

void pr_lock_db_superblock(struct db_descriptor *db_desc);

void pr_unlock_db_superblock(struct db_descriptor *db_desc);

/**
 * Persists the results of a compaction from Li to Li+1 where i >= 1.
 * @param db_desc the descriptor of the database @param level_id the id of
 * level i+1
 * @param tree_id
 */
void pr_flush_compaction(struct db_descriptor *db_desc, struct par_db_options *db_options, uint8_t level_id,
			 uint8_t tree_id, uint64_t txn_id);

void pr_recover_L0(struct db_descriptor *db_desc);

/**
 * Adds and flushes the contets of buf to the associated log_cat log
 * The size of the flush is equal to IO_size while the buf_size is for keeping the log accounting.
 * This happends becauase the buf_size may not be a mutliple to alignment size.
 */
uint64_t pr_add_and_flush_segment_in_log(db_handle *dbhandle, char *buf, int32_t buf_size, uint32_t IO_size,
					 enum log_type log_cat, uint64_t txn_id);

void pr_append_segment_to_log(struct log_descriptor *log_desc, char *buf, uint64_t next_tail_offt);
void pr_flush_buffer_to_log(struct log_descriptor *log_desc, uint64_t IO_start_offt, uint32_t IO_size, char *buf,
			    uint32_t buf_size);
#endif // PERSISTENT_OPERATIONS_H_

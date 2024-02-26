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
#include "region_log.h"
#include "../btree/btree.h"
#include "../btree/conf.h"
#include "../common/common.h"
#include "device_structures.h"
#include "persistent_operations.h"
#include "volume_manager.h"

#include <aio.h>
#include <assert.h>
#include <errno.h>
#include <log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uthash.h>

#define REGL_ALIGN_UP(number, alignment) (((number) + (alignment)-1) / (alignment) * (alignment))
/**
 * Writes synchronously to the device a chunk from a log segment.
 * */
static void rul_flush_log_chunk(struct db_descriptor *db_desc, uint32_t chunk_id)
{
	struct regl_log_descriptor *log_desc = db_desc->allocation_log;

	//check if pending
	for (uint32_t i = 0; i <= chunk_id; ++i) {
		while (log_desc->pending_IO[i]) {
			int state = aio_error(&log_desc->aiocbp[i]);
			switch (state) {
			case 0:
				log_desc->pending_IO[i] = 0;
				break;
			case EINPROGRESS:
				break;
			case ECANCELED:
				log_warn("Request cacelled");
				break;
			default:
				log_fatal("error appending to redo undo log");
				break;
			}
		}
	}

	//ssize_t size = REGL_LOG_CHUNK_SIZE_IN_BYTES;
	ssize_t size = (db_desc->allocation_log->size % REGL_LOG_CHUNK_SIZE_IN_BYTES) ?
			       (db_desc->allocation_log->size % REGL_LOG_CHUNK_SIZE_IN_BYTES) :
			       REGL_LOG_CHUNK_SIZE_IN_BYTES;

	size = REGL_ALIGN_UP(size, 512);

	ssize_t dev_offt = log_desc->tail_dev_offt + (chunk_id * REGL_LOG_CHUNK_SIZE_IN_BYTES);

	ssize_t total_bytes_written = 0;

	while (total_bytes_written < size) {
		ssize_t bytes_written = pwrite(db_desc->db_volume->vol_fd,
					       db_desc->allocation_log->segment.chunk[chunk_id],
					       size - total_bytes_written, dev_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to write DB's %s superblock", db_desc->db_superblock->db_name);
			perror("Reason");
			BUG_ON();
		}
		total_bytes_written += bytes_written;
	}
}

/**
 * Writes asynchronously to the device a chunk from a log segment.
 * */
static void rul_async_flush_log_chunk(struct db_descriptor *db_desc, uint32_t chunk_id)
{
	struct regl_log_descriptor *log_desc = db_desc->allocation_log;

	//check if pending
	while (log_desc->pending_IO[chunk_id]) {
		int state = aio_error(&log_desc->aiocbp[chunk_id]);
		switch (state) {
		case 0:
			log_desc->pending_IO[chunk_id] = 0;
			break;
		case EINPROGRESS:
			break;
		case ECANCELED:
			log_warn("Request cacelled");
			break;
		default:
			log_fatal("error appending to redo undo log");
			break;
		}
	}

	//Prepare an async IO request
	memset(&log_desc->aiocbp[chunk_id], 0x00, sizeof(struct aiocb));
	log_desc->aiocbp[chunk_id].aio_fildes = db_desc->db_volume->vol_fd;
	log_desc->aiocbp[chunk_id].aio_offset = log_desc->tail_dev_offt + (chunk_id * REGL_LOG_CHUNK_SIZE_IN_BYTES);
	assert(log_desc->aiocbp[chunk_id].aio_offset % ALIGNMENT_SIZE == 0);
	log_desc->aiocbp[chunk_id].aio_buf = log_desc->segment.chunk[chunk_id];
	assert((uint64_t)log_desc->aiocbp[chunk_id].aio_buf % ALIGNMENT_SIZE == 0);
	log_desc->aiocbp[chunk_id].aio_nbytes = REGL_LOG_CHUNK_SIZE_IN_BYTES;
	log_desc->pending_IO[chunk_id] = 1;
	/*log_info("Aflush chunk id %u dev offset: %lu", chunk_id, log_desc->aiocbp[chunk_id].aio_offset);*/

	//Now issue the async IO
	if (aio_write(&log_desc->aiocbp[chunk_id])) {
		log_fatal("IO failed for redo undo log offset is %lu", log_desc->aiocbp[chunk_id].aio_offset);
		perror("Reason:");
		BUG_ON();
	}

	uint32_t i = chunk_id;
	while (log_desc->pending_IO[i]) {
		int state = aio_error(&log_desc->aiocbp[i]);
		switch (state) {
		case 0:
			log_desc->pending_IO[i] = 0;
			break;
		case EINPROGRESS:
			break;
		case ECANCELED:
			log_warn("Request cacelled");
			break;
		default:
			log_fatal("error appending to redo undo log for chunk %u  state is %d Reason is %s", i, state,
				  strerror(state));
			BUG_ON();
		}
	}
}

static void rul_wait_all_chunk_IOs(struct db_descriptor *db_desc, uint32_t chunk_num)
{
	struct regl_log_descriptor *log_desc = db_desc->allocation_log;
	for (uint32_t i = 0; i < chunk_num; ++i) {
		//check if pending
		while (log_desc->pending_IO[i]) {
			int state = aio_error(&log_desc->aiocbp[i]);
			switch (state) {
			case 0:
				log_desc->pending_IO[i] = 0;
				break;
			case EINPROGRESS:
				break;
			case ECANCELED:
				log_warn("Request cacelled");
				break;
			default:
				log_fatal("error appending to redo undo log for chunk %u  state is %d Reason is %s", i,
					  state, strerror(state));
				BUG_ON();
			}
		}
	}
}

static void rul_flush_last_chunk(struct db_descriptor *db_desc)
{
	// Write with explicit I/O the segment_header
	ssize_t total_bytes_written = 0;
	ssize_t size;
	ssize_t dev_offt;
	uint32_t chunk_id = REGL_LOG_CHUNK_NUM - 1;

	rul_wait_all_chunk_IOs(db_desc, REGL_LOG_CHUNK_NUM);

	size = REGL_LOG_CHUNK_SIZE_IN_BYTES + REGL_SEGMENT_FOOTER_SIZE_IN_BYTES;
	dev_offt = (db_desc->allocation_log->tail_dev_offt + SEGMENT_SIZE) - size;

	while (total_bytes_written < size) {
		ssize_t bytes_written = pwrite(db_desc->db_volume->vol_fd,
					       db_desc->allocation_log->segment.chunk[chunk_id],
					       size - total_bytes_written, dev_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to write DB's %s superblock", db_desc->db_superblock->db_name);
			perror("Reason");
			BUG_ON();
		}
		total_bytes_written += bytes_written;
	}
}

static void rul_read_last_segment(struct db_descriptor *db_desc)
{
	ssize_t total_bytes_read = 0;
	ssize_t size = SEGMENT_SIZE;
	ssize_t dev_offt = db_desc->allocation_log->tail_dev_offt;
	while (total_bytes_read < size) {
		ssize_t bytes_read = pread(db_desc->db_volume->vol_fd, &db_desc->allocation_log->segment,
					   size - total_bytes_read, dev_offt + total_bytes_read);
		if (bytes_read == -1) {
			log_fatal("Failed to read DB's %s superblock", db_desc->db_superblock->db_name);
			perror("Reason");
			BUG_ON();
		}
		total_bytes_read += bytes_read;
	}
}

/**
 * Appends a new entry in the redo-undo log
 *
 */
static int rul_append(struct db_descriptor *db_desc, const struct regl_log_entry *entry)
{
	int ret = 0;
	struct regl_log_descriptor *allocation_log = db_desc->allocation_log;

	if (allocation_log->curr_segment_entry >= REGL_SEGMENT_MAX_ENTRIES) {
		uint64_t segment_id;
		// Time to add a new segment
		uint64_t new_tail_dev_offt = mem_allocate(db_desc->db_volume, SEGMENT_SIZE);
		allocation_log->segment.next_seg_offt = new_tail_dev_offt;
		segment_id = allocation_log->segment.segment_id;
		struct regl_log_entry e = {
			.txn_id = 0, .dev_offt = new_tail_dev_offt, .op_type = REGL_ALLOCATE, .size = SEGMENT_SIZE
		};

		//add new entry in the memory segment
		allocation_log->segment.chunk[allocation_log->curr_chunk_id][allocation_log->curr_chunk_entry] = e;
		allocation_log->size += (sizeof(struct regl_log_entry) + REGL_SEGMENT_FOOTER_SIZE_IN_BYTES);
		rul_flush_last_chunk(db_desc);

		allocation_log->tail_dev_offt = new_tail_dev_offt;
		allocation_log->curr_chunk_id = 0;
		allocation_log->curr_chunk_entry = 0;
		allocation_log->curr_segment_entry = 0;
		memset(&allocation_log->segment, 0x00, sizeof(struct regl_log_segment));
		allocation_log->segment.segment_id = segment_id + 1;
	}

	if (allocation_log->curr_chunk_entry >= REGL_LOG_CHUNK_MAX_ENTRIES) {
		rul_async_flush_log_chunk(db_desc, allocation_log->curr_chunk_id);
		++allocation_log->curr_chunk_id;
		allocation_log->curr_chunk_entry = 0;
	}

	/*Finally append*/
	/*log_info("Appending in segment (%u,%u)", allocation_log->curr_chunk_id, allocation_log->curr_chunk_entry);*/
	allocation_log->segment.chunk[allocation_log->curr_chunk_id][allocation_log->curr_chunk_entry] = *entry;

	allocation_log->size += sizeof(struct regl_log_entry);
	++allocation_log->curr_chunk_entry;
	++allocation_log->curr_segment_entry;
	return ret;
}

void regl_log_destroy(struct db_descriptor *db_desc)
{
	free(db_desc->allocation_log);
}

static void rul_add_first_entry(struct db_descriptor *db_desc, struct regl_log_entry *log_entry)
{
	char *log_chunk;

	if (0 != posix_memalign((void **)&log_chunk, ALIGNMENT_SIZE, REGL_LOG_CHUNK_SIZE_IN_BYTES)) {
		log_fatal("memalign failed");
		BUG_ON();
	}

	memset(log_chunk, 0xFF, REGL_LOG_CHUNK_SIZE_IN_BYTES);
	assert(log_entry->op_type != 0);
	memcpy(log_chunk, log_entry, sizeof(struct regl_log_entry));
	ssize_t size = REGL_LOG_CHUNK_SIZE_IN_BYTES;
	ssize_t dev_offt = db_desc->allocation_log->tail_dev_offt;
	ssize_t total_bytes_written = 0;

	while (total_bytes_written < size) {
		ssize_t bytes_written = pwrite(db_desc->db_volume->vol_fd, log_chunk, size - total_bytes_written,
					       dev_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to initialize allocation log of DB: %s", db_desc->db_superblock->db_name);
			perror("Reason");
			BUG_ON();
		}
		total_bytes_written += bytes_written;
	}
	struct regl_log_descriptor *allocation_log = db_desc->allocation_log;
	allocation_log->size += sizeof(*log_entry);
	allocation_log->segment.chunk[allocation_log->curr_chunk_id][allocation_log->curr_chunk_entry] = *log_entry;
	++allocation_log->curr_chunk_entry;
	++allocation_log->curr_segment_entry;

	free(log_chunk);
}

void regl_log_init(struct db_descriptor *db_desc)
{
	_Static_assert(REGL_LOG_CHUNK_NUM % 2 == 0, "REGL_LOG_CHUNK_NUM invalid!");
	_Static_assert(REGL_LOG_CHUNK_SIZE_IN_BYTES % ALIGNMENT_SIZE == 0, "REGL_LOG_CHUNK_SIZE_IN_BYTES not aligned!");
	_Static_assert(sizeof(struct regl_log_entry) + sizeof(uint64_t) <= ALIGNMENT_SIZE,
		       "Redo-undo log footer must be <= 512");
	_Static_assert(sizeof(struct regl_log_segment) == SEGMENT_SIZE,
		       "Redo undo log segment not equal to SEGMENT_SIZE!");

	struct regl_log_descriptor *log_desc;
	if (posix_memalign((void **)&log_desc, ALIGNMENT, sizeof(struct regl_log_descriptor)) != 0) {
		log_fatal("Failed to allocate region_log descriptor buffer");
		BUG_ON();
	}
	memset(log_desc, 0x00, sizeof(struct regl_log_descriptor));

	pr_lock_db_superblock(db_desc);

	MUTEX_INIT(&log_desc->regl_lock, NULL);
	MUTEX_INIT(&log_desc->trans_map_lock, NULL);
	// resume state, superblock must have been read in memory

	log_desc->size = db_desc->db_superblock->allocation_log.size;
	log_desc->trans_map = NULL;
	log_desc->txn_id = db_desc->db_superblock->allocation_log.txn_id;

	db_desc->allocation_log = log_desc;

	if (db_desc->db_superblock->allocation_log.head_dev_offt == 0) {
		// empty log do the first allocation
		uint64_t head_dev_offt = (uint64_t)mem_allocate(db_desc->db_volume, SEGMENT_SIZE);
		if (!head_dev_offt) {
			log_fatal("Out of Space!");
			BUG_ON();
		}
		log_desc->head_dev_offt = head_dev_offt;
		log_desc->tail_dev_offt = head_dev_offt;
		log_desc->txn_id = 1;
		log_desc->size = 0;

		struct regl_log_entry log_entry = {
			.txn_id = 0, .dev_offt = head_dev_offt, .op_type = REGL_ALLOCATE, .size = SEGMENT_SIZE
		};
		MUTEX_LOCK(&log_desc->regl_lock);
		rul_add_first_entry(db_desc, &log_entry);
		MUTEX_UNLOCK(&log_desc->regl_lock);
	} else {
		log_desc->head_dev_offt = db_desc->db_superblock->allocation_log.head_dev_offt;
		log_desc->tail_dev_offt = db_desc->db_superblock->allocation_log.tail_dev_offt;
		/*Read last segment in memory*/
		rul_read_last_segment(db_desc);
	}
	pr_unlock_db_superblock(db_desc);

	uint32_t tail_size = log_desc->size % SEGMENT_SIZE;
	uint32_t n_entries_in_tail = tail_size / sizeof(struct regl_log_entry);
	log_desc->curr_segment_entry = n_entries_in_tail;
	log_desc->curr_chunk_id = n_entries_in_tail / REGL_LOG_CHUNK_MAX_ENTRIES;
	log_desc->curr_chunk_entry = n_entries_in_tail % REGL_LOG_CHUNK_MAX_ENTRIES;
	log_debug(
		"State of the allocation log of DB:%s head_dev_offt: %lu tail_dev_offt: %lu size: %lu curr_chunk_id: %u curr_chunk_entry: %u, curr_segment_entry: %u",
		db_desc->db_superblock->db_name, log_desc->head_dev_offt, log_desc->tail_dev_offt, log_desc->size,
		log_desc->curr_chunk_id, log_desc->curr_chunk_entry, log_desc->curr_segment_entry);
}

uint64_t regl_start_txn(struct db_descriptor *db_desc)
{
	struct regl_log_descriptor *log_desc = db_desc->allocation_log;
	uint64_t txn_id = __sync_fetch_and_add(&log_desc->txn_id, 1);
	// log_debug("Staring transaction %lu", txn_id);

	/*check if (accidentally) txn exists already*/
	struct regl_transaction *transaction;

	MUTEX_LOCK(&log_desc->trans_map_lock);
	HASH_FIND_PTR(log_desc->trans_map, &txn_id, transaction);
	if (transaction != NULL) {
		log_fatal("Txn %lu already exists (it shouldn't)", txn_id);
		BUG_ON();
	}
	transaction = calloc(1, sizeof(struct regl_transaction));
	transaction->txn_id = txn_id;
	struct regl_transaction_buffer *transaction_buf = calloc(1, sizeof(struct regl_transaction_buffer));
	transaction->head = transaction_buf;
	transaction->tail = transaction_buf;

	HASH_ADD_PTR(log_desc->trans_map, txn_id, transaction);
	MUTEX_UNLOCK(&log_desc->trans_map_lock);
	return txn_id;
}

void regl_add_entry_in_txn_buf(struct db_descriptor *db_desc, struct regl_log_entry *entry)
{
	struct regl_log_descriptor *log_desc = db_desc->allocation_log;
	uint64_t txn_id = entry->txn_id;
	struct regl_transaction *transaction;

	MUTEX_LOCK(&log_desc->trans_map_lock);
	HASH_FIND_PTR(log_desc->trans_map, &txn_id, transaction);

	if (transaction == NULL) {
		log_fatal("Txn %lu not found!", txn_id);
		assert(0);
		BUG_ON();
	}
	MUTEX_UNLOCK(&log_desc->trans_map_lock);

	struct regl_transaction_buffer *transaction_buf = transaction->tail;
	// Is there enough space
	if (transaction_buf->n_entries >= REGL_ENTRIES_PER_TXN_BUFFER) {
		struct regl_transaction_buffer *new_trans_buf = calloc(1, sizeof(struct regl_transaction_buffer));
		transaction_buf->next = new_trans_buf;
		transaction->tail = new_trans_buf;
		transaction_buf = new_trans_buf;
	}

	assert(entry->op_type != 0);
	transaction_buf->txn_entry[transaction_buf->n_entries++] = *entry;
}

struct regl_log_info regl_flush_txn(struct db_descriptor *db_desc, uint64_t txn_id)
{
	struct regl_log_info info = { .head_dev_offt = 0, .tail_dev_offt = 0, .size = 0, .txn_id = 0 };
	struct regl_log_descriptor *log_desc = db_desc->allocation_log;
	struct regl_transaction *transaction = NULL;

	MUTEX_LOCK(&log_desc->trans_map_lock);
	HASH_FIND_PTR(log_desc->trans_map, &txn_id, transaction);

	if (transaction == NULL) {
		log_fatal("Txn %lu not found!", txn_id);
		BUG_ON();
	}
	MUTEX_UNLOCK(&log_desc->trans_map_lock);

	MUTEX_LOCK(&log_desc->regl_lock);
	struct regl_transaction_buffer *curr = transaction->head;

	assert(curr != NULL);
	while (curr) {
		for (uint32_t i = 0; i < curr->n_entries; ++i) {
			assert(curr->txn_entry[i].op_type != 0);
			rul_append(db_desc, &curr->txn_entry[i]);
		}

#ifndef NDEBUG
		if (!curr->next)
			assert(curr == transaction->tail);
#endif

		curr = curr->next;
	}

	if (log_desc->curr_chunk_id > 0)
		rul_wait_all_chunk_IOs(db_desc, log_desc->curr_chunk_id);

	//synchronously write last
	rul_flush_log_chunk(db_desc, log_desc->curr_chunk_id);
	info.head_dev_offt = db_desc->allocation_log->head_dev_offt;
	info.tail_dev_offt = db_desc->allocation_log->tail_dev_offt;
	info.size = db_desc->allocation_log->size;
	info.txn_id = db_desc->allocation_log->txn_id;
	MUTEX_UNLOCK(&log_desc->regl_lock);
	return info;
}

void regl_apply_txn_buf_freeops_and_destroy(struct db_descriptor *db_desc, uint64_t txn_id)
{
	struct regl_log_descriptor *log_desc = db_desc->allocation_log;
	struct regl_transaction *transaction;

	MUTEX_LOCK(&log_desc->trans_map_lock);
	HASH_FIND_PTR(log_desc->trans_map, &txn_id, transaction);

	if (transaction == NULL) {
		log_fatal("Txn %lu not found!", txn_id);
		BUG_ON();
	}
	MUTEX_UNLOCK(&log_desc->trans_map_lock);

	struct regl_transaction_buffer *curr = transaction->head;
	assert(curr != NULL);
	while (curr) {
		for (uint32_t i = 0; i < curr->n_entries; ++i) {
			//rul_append(db_desc, &curr->txn_entry[i]);
			switch (curr->txn_entry[i].op_type) {
			case REGL_FREE:
			case REGL_LOG_FREE:
			case REGL_FREE_SST:
				mem_free_segment(db_desc->db_volume, curr->txn_entry[i].dev_offt);
				break;
			case REGL_ALLOCATE:
			case REGL_ALLOCATE_SST:
			case REGL_LARGE_LOG_ALLOCATE:
			case REGL_MEDIUM_LOG_ALLOCATE:
			case REGL_SMALL_LOG_ALLOCATE:
			case BLOB_GARBAGE_BYTES:
				break;
			default:
				log_fatal("Unhandled case probably corruption in txn buffer");
				BUG_ON();
			}
		}
		struct regl_transaction_buffer *del = curr;
		curr = curr->next;
		free(del);
		del = NULL;
	}

	MUTEX_LOCK(&log_desc->trans_map_lock);
	HASH_DEL(log_desc->trans_map, transaction);
	MUTEX_UNLOCK(&log_desc->trans_map_lock);
	free(transaction);
}

struct regl_cursor *regl_cursor_init(struct volume_descriptor *volume_desc, struct pr_db_superblock *db_superblock)
{
	struct regl_cursor *cursor = calloc(1, sizeof(struct regl_cursor));
	if (!cursor) {
		log_fatal("Failed to allocate memory");
		BUG_ON();
	}
	cursor->volume_desc = volume_desc;
	cursor->db_superblock = db_superblock;
	cursor->segment = NULL;
	cursor->chunks_in_segment = 0;
	cursor->curr_chunk_id = 0;
	cursor->chunk_entries = 0;
	cursor->curr_entry_in_chunk = 0;
	cursor->state = GET_HEAD;
	cursor->valid = 1;
	return cursor;
}

struct regl_log_entry *regl_cursor_get_next(struct regl_cursor *cursor)
{
	struct pr_region_allocation_log *allocation_log = &cursor->db_superblock->allocation_log;
	while (1) {
		switch (cursor->state) {
		case GET_HEAD:
			if (!allocation_log->head_dev_offt) {
				cursor->segment = NULL;
				cursor->state = EXIT;
				cursor->valid = 0;
				break;
			}
			cursor->segment = REAL_ADDRESS(allocation_log->head_dev_offt);
			cursor->state = CALCULATE_CHUNKS_IN_SEGMENT;
			break;
		case GET_NEXT_SEGMENT:
			assert(REAL_ADDRESS(allocation_log->tail_dev_offt));
			if (cursor->segment == REAL_ADDRESS(allocation_log->tail_dev_offt)) {
				cursor->segment = NULL;
				cursor->valid = 0;
				cursor->state = EXIT;
				break;
			}
			cursor->segment = REAL_ADDRESS(cursor->segment->next_seg_offt);
			cursor->state = CALCULATE_CHUNKS_IN_SEGMENT;
			break;
		case GET_NEXT_CHUNK:
			++cursor->curr_chunk_id;
			if (cursor->curr_chunk_id >= cursor->chunks_in_segment) {
				cursor->state = GET_NEXT_SEGMENT;
				break;
			}

			cursor->state = CALCULATE_CHUNK_ENTRIES;
			break;
		case CALCULATE_CHUNKS_IN_SEGMENT: {
			cursor->chunks_in_segment = REGL_LOG_CHUNK_NUM;

			uint8_t last_segment = cursor->segment == REAL_ADDRESS(allocation_log->tail_dev_offt);
			if (last_segment) {
				uint32_t last_segment_size = allocation_log->size % SEGMENT_SIZE;
				cursor->chunks_in_segment = last_segment_size / REGL_LOG_CHUNK_SIZE_IN_BYTES;
				cursor->chunks_in_segment += last_segment_size % REGL_LOG_CHUNK_SIZE_IN_BYTES != 0;
			}

			cursor->curr_chunk_id = 0;
			cursor->state = CALCULATE_CHUNK_ENTRIES;
			break;
		}
		case CALCULATE_CHUNK_ENTRIES:
			cursor->chunk_entries = REGL_LOG_CHUNK_MAX_ENTRIES;

			uint8_t last_segment = cursor->segment == REAL_ADDRESS(allocation_log->tail_dev_offt);
			if (last_segment && cursor->curr_chunk_id == cursor->chunks_in_segment - 1) {
				uint32_t last_chunk_size = (allocation_log->size % SEGMENT_SIZE) -
							   (cursor->curr_chunk_id * REGL_LOG_CHUNK_SIZE_IN_BYTES);
				assert(0 == last_chunk_size % sizeof(struct regl_log_entry));
				cursor->chunk_entries = last_chunk_size / sizeof(struct regl_log_entry);
			}

			cursor->curr_entry_in_chunk = 0;
			cursor->state = GET_NEXT_ENTRY;
			break;

		case GET_NEXT_ENTRY:
			if (cursor->curr_entry_in_chunk >= cursor->chunk_entries) {
				cursor->state = GET_NEXT_CHUNK;
				break;
			}
			return &cursor->segment->chunk[cursor->curr_chunk_id][cursor->curr_entry_in_chunk++];
		case EXIT:
			cursor->segment = NULL;
			cursor->valid = 0;
			return NULL;
		default:
			log_fatal("Unknown state in redo undo log!");
			BUG_ON();
		}
	}
}

void regl_close_cursor(struct regl_cursor *cursor)
{
	free(cursor);
}

bool regl_replay_mem_guards(struct volume_descriptor *volume_desc, struct pr_db_superblock *db_superblock,
			    process_entry process, void *cnxt)
{
	struct regl_cursor *cursor = regl_cursor_init(volume_desc, db_superblock);
	for (struct regl_log_entry *entry = regl_cursor_get_next(cursor); entry != NULL;
	     entry = regl_cursor_get_next(cursor)) {
		if (entry->op_type != REGL_ALLOCATE_SST && entry->op_type != REGL_FREE_SST)
			continue;
		(*process)(entry, cnxt);
	}
	return true;
}

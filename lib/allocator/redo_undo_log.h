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

#ifndef REDO_UNDO_LOG_H
#define REDO_UNDO_LOG_H
#include "../btree/conf.h"
#include <aio.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <uthash.h>
#define RUL_LOG_CHUNK_NUM 8UL
#define RUL_SEGMENT_FOOTER_SIZE_IN_BYTES (RUL_LOG_CHUNK_NUM * ALIGNMENT_SIZE)
#define RUL_LOG_CHUNK_SIZE_IN_BYTES ((SEGMENT_SIZE - RUL_SEGMENT_FOOTER_SIZE_IN_BYTES) / RUL_LOG_CHUNK_NUM)
#define RUL_LOG_CHUNK_MAX_ENTRIES (RUL_LOG_CHUNK_SIZE_IN_BYTES / sizeof(struct rul_log_entry))
#define RUL_SEGMENT_MAX_ENTRIES ((RUL_LOG_CHUNK_NUM * RUL_LOG_CHUNK_MAX_ENTRIES) - 1)

struct volume_descriptor;
struct pr_db_superblock;
struct db_descriptor;
struct rul_log_entry;

enum rul_op_type {
	RUL_ALLOCATE = 1,
	RUL_ALLOCATE_SST,
	RUL_FREE,
	RUL_COMMIT,
	RUL_SMALL_LOG_ALLOCATE,
	RUL_MEDIUM_LOG_ALLOCATE,
	RUL_LARGE_LOG_ALLOCATE,
	RUL_LOG_FREE,
	RUL_FREE_SST,
	BLOB_GARBAGE_BYTES
};

struct rul_log_info {
	uint64_t size;
	uint64_t txn_id;
	uint64_t tail_dev_offt;
	uint64_t head_dev_offt;
};

struct rul_log_entry {
	uint64_t txn_id;
	uint64_t dev_offt;
	uint32_t blob_garbage_bytes;
	char pad[4];
	enum rul_op_type op_type;
	uint32_t size;
} __attribute__((packed));

struct rul_log_segment {
	struct rul_log_entry chunk[RUL_LOG_CHUNK_NUM][RUL_LOG_CHUNK_MAX_ENTRIES];
	uint64_t next_seg_offt;
	uint64_t segment_id;
	char pad[RUL_SEGMENT_FOOTER_SIZE_IN_BYTES - (2 * sizeof(uint64_t))];
} __attribute__((packed));

#define RUL_ENTRIES_PER_TXN_BUFFER 512
struct rul_transaction {
	uint64_t txn_id;
	struct rul_transaction_buffer *head;
	struct rul_transaction_buffer *tail;
	UT_hash_handle hh;
};

struct rul_transaction_buffer {
	struct rul_log_entry txn_entry[RUL_ENTRIES_PER_TXN_BUFFER];
	struct rul_transaction_buffer *next;
	uint32_t n_entries;
};

struct rul_log_descriptor {
	struct rul_log_segment segment;
	pthread_mutex_t rul_lock;
	pthread_mutex_t trans_map_lock;
	struct aiocb aiocbp[RUL_LOG_CHUNK_NUM];
	struct rul_transaction *trans_map;
	//recoverable staff
	uint64_t size;
	uint64_t txn_id;
	uint64_t tail_dev_offt;
	uint64_t head_dev_offt;
	uint32_t pending_IO[RUL_LOG_CHUNK_NUM];
	uint32_t curr_chunk_id;
	uint32_t curr_chunk_entry;
	uint32_t curr_segment_entry;
};

typedef bool (*process_entry)(struct rul_log_entry *entry, void *cnxt);
void rul_log_init(struct db_descriptor *db_desc);
void rul_log_destroy(struct db_descriptor *db_desc);
uint64_t rul_start_txn(struct db_descriptor *db_desc);
void rul_add_entry_in_txn_buf(struct db_descriptor *db_desc, struct rul_log_entry *entry);
struct rul_log_info rul_flush_txn(struct db_descriptor *db_desc, uint64_t txn_id);
void rul_apply_txn_buf_freeops_and_destroy(struct db_descriptor *db_desc, uint64_t txn_id);
bool rul_replay_mem_guards(struct volume_descriptor *volume_desc, struct pr_db_superblock *db_superblock,
			   process_entry process, void *cnxt);
//cursor staff

enum rul_cursor_state {
	CALCULATE_CHUNKS_IN_SEGMENT,
	CALCULATE_CHUNK_ENTRIES,
	GET_NEXT_SEGMENT,
	GET_NEXT_CHUNK,
	GET_NEXT_ENTRY,
	GET_HEAD,
	EXIT
};

struct rul_cursor {
	struct volume_descriptor *volume_desc;
	struct pr_db_superblock *db_superblock;
	struct rul_log_segment *segment;
	uint32_t chunks_in_segment;
	uint32_t curr_chunk_id;
	uint32_t chunk_entries;
	uint32_t curr_entry_in_chunk;
	enum rul_cursor_state state;
	uint8_t valid : 1;
};

struct rul_cursor *rul_cursor_init(struct volume_descriptor *volume_desc, struct pr_db_superblock *db_superblock);
struct rul_log_entry *rul_cursor_get_next(struct rul_cursor *cursor);
void rul_close_cursor(struct rul_cursor *cursor);
#endif

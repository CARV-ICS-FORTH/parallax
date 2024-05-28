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

#ifndef REGION_LOG_H
#define REGION_LOG_H
#include <aio.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <uthash.h>
#define REGL_LOG_CHUNK_NUM 8UL
#define REGL_SEGMENT_FOOTER_SIZE_IN_BYTES (REGL_LOG_CHUNK_NUM * ALIGNMENT_SIZE)
#define REGL_LOG_CHUNK_SIZE_IN_BYTES ((SEGMENT_SIZE - REGL_SEGMENT_FOOTER_SIZE_IN_BYTES) / REGL_LOG_CHUNK_NUM)
#define REGL_LOG_CHUNK_MAX_ENTRIES (REGL_LOG_CHUNK_SIZE_IN_BYTES / sizeof(struct regl_log_entry))
#define REGL_SEGMENT_MAX_ENTRIES ((REGL_LOG_CHUNK_NUM * REGL_LOG_CHUNK_MAX_ENTRIES) - 1)

struct volume_descriptor;
struct pr_db_superblock;
struct db_descriptor;
struct regl_log_entry;

enum regl_op_type {
	REGL_ALLOCATE = 1,
	REGL_ALLOCATE_SST,
	REGL_FREE,
	REGL_COMMIT,
	REGL_SMALL_LOG_ALLOCATE,
	REGL_MEDIUM_LOG_ALLOCATE,
	REGL_LARGE_LOG_ALLOCATE,
	REGL_LOG_FREE,
	REGL_FREE_SST,
	BLOB_GARBAGE_BYTES
};

struct regl_log_info {
	uint64_t size;
	uint64_t txn_id;
	uint64_t tail_dev_offt;
	uint64_t head_dev_offt;
};

struct regl_log_entry {
	uint64_t txn_id;
	uint64_t dev_offt;
	uint32_t blob_garbage_bytes;
	char pad[4];
	enum regl_op_type op_type;
	uint32_t size;
} __attribute__((packed));

struct regl_log_segment {
	struct regl_log_entry chunk[REGL_LOG_CHUNK_NUM][REGL_LOG_CHUNK_MAX_ENTRIES];
	uint64_t next_seg_offt;
	uint64_t segment_id;
	char pad[REGL_SEGMENT_FOOTER_SIZE_IN_BYTES - (2 * sizeof(uint64_t))];
} __attribute__((packed));

#define REGL_ENTRIES_PER_TXN_BUFFER 512
struct regl_transaction {
	uint64_t txn_id;
	struct regl_transaction_buffer *head;
	struct regl_transaction_buffer *tail;
	UT_hash_handle hh;
};

struct regl_transaction_buffer {
	struct regl_log_entry txn_entry[REGL_ENTRIES_PER_TXN_BUFFER];
	struct regl_transaction_buffer *next;
	uint32_t n_entries;
};

struct regl_log_descriptor {
	struct regl_log_segment segment;
	pthread_mutex_t regl_lock;
	pthread_mutex_t trans_map_lock;
	struct aiocb aiocbp[REGL_LOG_CHUNK_NUM];
	struct regl_transaction *trans_map;
	//recoverable staff
	uint64_t size;
	uint64_t txn_id;
	uint64_t tail_dev_offt;
	uint64_t head_dev_offt;
	uint32_t pending_IO[REGL_LOG_CHUNK_NUM];
	uint32_t curr_chunk_id;
	uint32_t curr_chunk_entry;
	uint32_t curr_segment_entry;
};

typedef bool (*process_entry)(struct regl_log_entry *entry, void *cnxt);
void regl_log_init(struct db_descriptor *db_desc);
void regl_log_destroy(struct db_descriptor *db_desc);
uint64_t regl_start_txn(struct db_descriptor *db_desc);
void regl_add_entry_in_txn_buf(struct db_descriptor *db_desc, struct regl_log_entry *entry);
struct regl_log_info regl_flush_txn(struct db_descriptor *db_desc, uint64_t txn_id);
void regl_apply_txn_buf_freeops_and_destroy(struct db_descriptor *db_desc, uint64_t txn_id);
bool regl_replay_mem_guards(struct volume_descriptor *volume_desc, struct pr_db_superblock *db_superblock,
			    process_entry process, void *cnxt);
//cursor staff

enum regl_cursor_state {
	CALCULATE_CHUNKS_IN_SEGMENT,
	CALCULATE_CHUNK_ENTRIES,
	GET_NEXT_SEGMENT,
	GET_NEXT_CHUNK,
	GET_NEXT_ENTRY,
	GET_HEAD,
	EXIT
};

struct regl_cursor {
	struct volume_descriptor *volume_desc;
	struct pr_db_superblock *db_superblock;
	struct regl_log_segment *segment;
	uint32_t chunks_in_segment;
	uint32_t curr_chunk_id;
	uint32_t chunk_entries;
	uint32_t curr_entry_in_chunk;
	enum regl_cursor_state state;
	uint8_t valid : 1;
};

struct regl_cursor *regl_cursor_init(struct volume_descriptor *volume_desc, struct pr_db_superblock *db_superblock);
struct regl_log_entry *regl_cursor_get_next(struct regl_cursor *cursor);
void regl_close_cursor(struct regl_cursor *cursor);
#endif

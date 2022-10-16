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

#pragma once
#include "../allocator/log_structures.h"
#include "../allocator/volume_manager.h"
#include "../include/parallax/parallax.h"
#include "conf.h"
#include "kv_pairs.h"
#include "parallax/structures.h"
#include <stdbool.h>

#if ENABLE_BLOOM_FILTERS
#include <bloom.h>
#endif
#include <limits.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdlib.h>
#define PREFIX_SIZE 12
#define LSN_SIZE sizeof(uint64_t)
#define MAX_HEIGHT 9

enum KV_type { KV_FORMAT, KV_PREFIX, INDEX_KEY_TYPE, KEY_TYPE };

struct lookup_operation {
	struct db_descriptor *db_desc; /*in variable*/
	char *key_buf; /*in variable*/
	char *buffer_to_pack_kv; /*in-out variable*/
	char *key_device_address; /*out variable*/
	uint32_t size; /*in-out variable*/
	uint8_t buffer_overflow : 1; /*out variable*/
	uint8_t found : 1; /*out variable*/
	uint8_t tombstone : 1;
	uint8_t retrieve : 1; /*in variable*/
};

enum db_status { DB_START_COMPACTION_DAEMON, DB_OPEN, DB_TERMINATE_COMPACTION_DAEMON, DB_IS_CLOSING };

typedef enum {
	leafNode = 590675399,
	internalNode = 790393380,
	rootNode = 742729384,
	leafRootNode = 748939994, /*special case for a newly created tree*/
	paddedSpace = 55400000,
	invalid
} nodeType_t;

/*descriptor describing a compaction operation and its current status*/
typedef enum {
	NO_COMPACTION = 0,
	COMPACTION_IN_PROGRESS = 1,
} level_0_tree_status;

/*
 * header of segment is 4K. L0 and KV log segments are chained in a linked list
 * with next and prev
 * pointers. garbage_bytes contains info about the unused bytes in the segment
 * due to deletes/updates.
 */
typedef struct segment_header {
	void *next_segment;
	void *prev_segment;
	uint64_t segment_id;
	uint64_t segment_garbage_bytes;
	uint64_t segment_end;
	nodeType_t nodetype;
} __attribute__((packed, aligned(4096))) segment_header;

/*Note IN stands for Internal Node*/
typedef struct IN_log_header {
	nodeType_t type;
	void *next;
} IN_log_header;

/*leaf or internal node metadata, place always in the first 4KB data block*/
typedef struct node_header {
	/*internal or leaf node*/
	nodeType_t type;
	/*0 are leaves, 1 are Bottom Internal nodes, and then we have
  INs and root*/
	int32_t height;
	uint64_t fragmentation;
	union {
		/*data log info, KV log for leaves private for index*/
		/* Used by index nodes */
		uint64_t key_log_size;
		/* Used in dynamic leaves */
		uint32_t leaf_log_size;
	};
	int32_t num_entries;
	/*pad to be exacly one cache line*/
	char pad[36];

} __attribute__((packed)) node_header;

struct bt_leaf_entry_bitmap {
	unsigned char bitmap; // This bitmap informs us which kv_entry is available to store data in the static leaf.
};

struct bt_static_leaf_slot_array {
	uint32_t index;
};

struct bt_dynamic_leaf_slot_array {
	// The index points to the location of the kv pair in the leaf.
	uint16_t index : 13;
	uint16_t key_category : 2;
	// Tombstone notifies if the key is deleted.
	uint16_t tombstone : 1;
};

struct key_compare {
	char *key;
	uint64_t kv_dev_offt;
	uint32_t key_size;
	enum KV_type key_format;
	uint8_t is_NIL;
};

#define LEAF_NODE_REMAIN (LEAF_NODE_SIZE - sizeof(struct node_header))

#define LN_ITEM_SIZE (sizeof(uint64_t) + (PREFIX_SIZE * sizeof(char)))
#define KV_LEAF_ENTRY (sizeof(struct kv_seperation_splice) + sizeof(struct bt_static_leaf_slot_array) + (1 / CHAR_BIT))
#define LN_LENGTH ((LEAF_NODE_REMAIN) / (KV_LEAF_ENTRY))

struct kv_format {
	uint32_t key_size;
	char key_buf[];
} __attribute__((packed));

struct bt_static_leaf_node {
	struct node_header header;
} __attribute__((packed));

struct bt_dynamic_leaf_node {
	struct node_header header;
} __attribute__((packed));

typedef struct leaf_node {
	struct node_header header;
	uint64_t pointer[LN_LENGTH];
	char prefix[LN_LENGTH][PREFIX_SIZE];
	char __pad[LEAF_NODE_SIZE - sizeof(struct node_header) - (LN_LENGTH * LN_ITEM_SIZE)];
} __attribute__((packed)) leaf_node;

enum bsearch_status { INSERT = 0, FOUND = 1, ERROR = 2 };

/* Possible options for these defines are multiples of 4KB but they should not be more than BUFFER_SEGMENT_SIZE*/
#define PAGE_SIZE 4096
#define LEVEL0_LEAF_SIZE (PAGE_SIZE * 2)
#define LEVEL1_LEAF_SIZE (PAGE_SIZE * 2)
#define LEVEL2_LEAF_SIZE (PAGE_SIZE * 2)
#define LEVEL3_LEAF_SIZE (PAGE_SIZE * 2)
#define LEVEL4_LEAF_SIZE (PAGE_SIZE * 2)
#define LEVEL5_LEAF_SIZE (PAGE_SIZE * 2)
#define LEVEL6_LEAF_SIZE (PAGE_SIZE * 2)
#define LEVEL7_LEAF_SIZE (PAGE_SIZE * 2)

/*
 * db_descriptor is a soft state descriptor per open database. superindex
 * structure keeps a serialized form of the vital information needed to restore each
 * db_descriptor
*/

typedef struct lock_table {
	pthread_rwlock_t rx_lock;
	char pad[8];
} lock_table;

struct leaf_node_metadata {
	uint32_t bitmap_entries;
	uint32_t bitmap_offset;
	uint32_t slot_array_entries;
	uint32_t slot_array_offset;
	uint32_t kv_entries;
	uint32_t kv_entries_offset;
};

struct compaction_pairs {
	int16_t src_level;
	int16_t dst_level;
};

typedef struct level_descriptor {
#if ENABLE_BLOOM_FILTERS
	struct bloom bloom_filter[NUM_TREES_PER_LEVEL];
#endif
	pthread_t compaction_thread[NUM_TREES_PER_LEVEL];
	lock_table *level_lock_table[MAX_HEIGHT];
	node_header *root_r[NUM_TREES_PER_LEVEL];
	node_header *root_w[NUM_TREES_PER_LEVEL];
	pthread_mutex_t level_allocation_lock;
	segment_header *first_segment[NUM_TREES_PER_LEVEL];
	segment_header *last_segment[NUM_TREES_PER_LEVEL];
	uint64_t offset[NUM_TREES_PER_LEVEL];
	/*needed for L0 scanner tiering colission*/
	uint64_t epoch[NUM_TREES_PER_LEVEL];
	uint64_t scanner_epoch;
	uint64_t allocation_txn_id[NUM_TREES_PER_LEVEL];
	lock_table guard_of_level;
	uint64_t level_size[NUM_TREES_PER_LEVEL];
	uint64_t max_level_size;
	struct leaf_node_metadata leaf_offsets;
	volatile segment_header *medium_log_head;
	volatile segment_header *medium_log_tail;
	uint64_t medium_log_size;
#if MEASURE_SST_USED_SPACE
	double avg_leaf_used_space;
	double leaf_used_space;
	double count_leaves;
	double count_compactions;
#endif
	int64_t active_operations;
	/*info for trimming medium_log, used only in L_{n-1}*/
	uint64_t medium_in_place_max_segment_id;
	uint64_t medium_in_place_segment_dev_offt;
	uint32_t leaf_size;
	char tree_status[NUM_TREES_PER_LEVEL];
	uint8_t active_tree;
	uint8_t level_id;
	char in_recovery_mode;
} level_descriptor;

struct bt_kv_log_address {
	char *addr;
	struct log_descriptor *log_desc;
	uint8_t in_tail;
	uint8_t tail_id;
};

struct bt_kv_log_address bt_get_kv_medium_log_address(struct log_descriptor *log_desc, uint64_t dev_offt);
struct bt_kv_log_address bt_get_kv_log_address(struct log_descriptor *log_desc, uint64_t dev_offt);
void bt_done_with_value_log_address(struct log_descriptor *log_desc, struct bt_kv_log_address *L);

typedef struct db_descriptor {
	level_descriptor levels[MAX_LEVELS];
#if MEASURE_MEDIUM_INPLACE
	uint64_t count_medium_inplace;
#endif

	/*<new_persistent_design>*/
	pthread_mutex_t db_superblock_lock;
	struct rul_log_descriptor *allocation_log;
	struct volume_descriptor *db_volume;
	struct pr_db_superblock *db_superblock;
	uint32_t db_superblock_idx;
	/*</new_persistent_design>*/

	pthread_cond_t client_barrier;
	pthread_cond_t compaction_cond;
	pthread_mutex_t compaction_structs_lock;
	pthread_mutex_t compaction_lock;
	pthread_mutex_t lock_log;
	pthread_mutex_t client_barrier_lock;
	pthread_mutex_t segment_ht_lock;

	/*<new_persistent_design>*/
	pthread_mutex_t flush_L0_lock;
	/*</new_persistent_design>*/

	sem_t compaction_daemon_interrupts;
	sem_t compaction_sem;
	sem_t compaction_daemon_sem;
	uint64_t blocked_clients;
	uint64_t compaction_count;
	pthread_t compaction_thread;
	pthread_t compaction_daemon;
	pthread_t gc_thread;
	struct log_descriptor big_log;
	struct log_descriptor medium_log;
	struct log_descriptor small_log;
	uint64_t lsn;
	// A hash table containing every segment that has at least 1 byte of garbage data in the large log.
	struct large_log_segment_gc_entry *segment_ht;
	uint64_t gc_last_segment_id;
	uint64_t gc_count_segments;
	uint64_t gc_keys_transferred;
	/*L0 recovery log info*/
	uint64_t small_log_start_segment_dev_offt;
	uint64_t small_log_start_offt_in_segment;
	uint64_t big_log_start_segment_dev_offt;
	uint64_t big_log_start_offt_in_segment;
	unsigned int level_medium_inplace;
	int is_compaction_daemon_sleeping;
	int32_t reference_count;
	int32_t group_id;
	int32_t group_index;
	bool gc_scanning_db;
	enum db_status db_state;
	char dirty;
} db_descriptor;

typedef struct db_handle {
	par_db_options db_options;
	volume_descriptor *volume_desc;
	db_descriptor *db_desc;
} db_handle;

typedef struct recovery_request {
	volume_descriptor *volume_desc;
	db_descriptor *db_desc;
	uint64_t big_log_start_offset;
	uint64_t medium_log_start_offset;
	uint64_t small_log_start_offset;
} recovery_request;

struct log_recovery_metadata {
	segment_header *log_curr_segment;
	uint64_t log_size;
	uint64_t log_offset;
	uint64_t curr_lsn;
	uint64_t segment_id;
	uint64_t prev_segment_id;
};

struct recovery_operator {
	struct log_recovery_metadata big;
	struct log_recovery_metadata medium;
	struct log_recovery_metadata small;
};

void pr_flush_log_tail(struct db_descriptor *db_desc, struct log_descriptor *log_desc);
void init_log_buffer(struct log_descriptor *log_desc, enum log_type log_type);
void pr_read_db_superblock(struct db_descriptor *db_desc);
void pr_flush_db_superblock(struct db_descriptor *db_desc);
void pr_lock_db_superblock(struct db_descriptor *db_desc);
void pr_unlock_db_superblock(struct db_descriptor *db_desc);
void pr_flush_L0(struct db_descriptor *db_desc, uint8_t tree_id);
void pr_flush_compaction(struct db_descriptor *db_desc, uint8_t level_id, uint8_t tree_id);

/*management operations*/
db_handle *db_open(par_db_options *db_options, char **error_message);
char *db_close(db_handle *handle);

void *compaction_daemon(void *args);

typedef struct bt_mutate_req {
	struct par_put_metadata put_op_metadata;
	db_handle *handle;
	uint64_t *reorganized_leaf_pos_INnode;
	char *error_message;
	/*offset in log where the kv was written*/
	uint64_t log_offset;
	/*info for cases of segment_full_event*/
	uint64_t log_segment_addr;
	uint64_t log_offset_full_event;
	uint64_t segment_id;
	uint64_t end_of_log;
	uint32_t log_padding;
	enum kv_category cat;
	uint8_t level_id;
	/*only for inserts >= level_1*/
	uint8_t tree_id;
	uint8_t append_to_log : 1;
	uint8_t gc_request : 1;
	uint8_t recovery_request : 1;
	/*needed for distributed version of Kreon*/
	uint8_t segment_full_event : 1;
	uint8_t special_split : 1;
	uint8_t tombstone : 1;
	char key_format;
} bt_mutate_req;

typedef struct bt_insert_req {
	bt_mutate_req metadata;
	char *key_value_buf;
	//Used in some cases where the KV has been written
	uint64_t kv_dev_offt;
} bt_insert_req;

typedef struct bt_delete_request {
	bt_mutate_req metadata;
	struct index_node *parent;
	struct leaf_node *self;
	uint64_t offset; /*offset in my parent*/
	void *key_buf;
} bt_delete_request;

typedef struct log_operation {
	bt_mutate_req *metadata;
	request_type optype_tolog;
	union {
		bt_insert_req *ins_req;
		bt_delete_request *del_req;
	};
} log_operation;

/**
 * Returns the category of the KV based on its key-value size and the operation to perform.
 * @param key_size
 * @param value_size
 * @param op_type Operation to execute.(put, delete, padding)
 * @return On success return the KV category.
 */
enum kv_category calculate_KV_category(uint32_t key_size, uint32_t value_size, request_type op_type);

struct log_towrite {
	struct log_descriptor *log_desc;
	int level_id;
	enum kv_category status;
};

enum bt_rebalance_retcode {
	NO_REBALANCE_NEEDED = 0,
	/* Return codes for splits */
	LEAF_ROOT_NODE_SPLITTED,
	LEAF_NODE_SPLITTED,
	INDEX_NODE_SPLITTED,
	/* Return codes for deletes */
	ROTATE_WITH_LEFT,
	ROTATE_WITH_RIGHT,
	ROTATE_IMPOSSIBLE_TRY_TO_MERGE,
	MERGE_WITH_LEFT,
	MERGE_WITH_RIGHT,
	MERGE_IMPOSSIBLE_FATAL,
};

struct bt_rebalance_result {
	//8 bytes for the key size + value_size and 255 Bytes for the key
	char middle_key[MAX_KEY_SIZE];
	union {
		node_header *left_child;
		struct index_node *left_ichild;
		leaf_node *left_lchild;
		struct bt_static_leaf_node *left_slchild;
		struct bt_dynamic_leaf_node *left_dlchild;
	};

	union {
		node_header *right_child;
		struct index_node *right_ichild;
		leaf_node *right_lchild;
		struct bt_static_leaf_node *right_slchild;
		struct bt_dynamic_leaf_node *right_dlchild;
	};
	enum bt_rebalance_retcode stat;
};

typedef struct metadata_tologop {
	uint32_t key_len;
	uint32_t value_len;
	uint32_t kv_size;
} metadata_tologop;

struct bt_delete_marker {
	uint32_t marker_id;
	uint32_t key_size;
	char key[];
};

struct par_put_metadata insert_key_value(db_handle *handle, void *key, void *value, uint32_t key_size,
					 uint32_t value_size, request_type op_type, char *error_message);

/**
 * Inserts a serialized key value pair by using the buffer provided by the user.
 * The format of the key value pair is | key_size | value_size | key |  value |, where {key,value}_sizes are uint32_t.
 * @param handle
 * @param serialized_key_value is a buffer containing the serialized key value pair.
 * @return Returns the error message if any otherwise NULL on success.
 * */
struct par_put_metadata serialized_insert_key_value(db_handle *handle, const char *serialized_key_value,
						    char *error_message);
char *btree_insert_key_value(bt_insert_req *ins_req) __attribute__((warn_unused_result));

void *append_key_value_to_log(log_operation *req);
void find_key(struct lookup_operation *get_op);
int8_t delete_key(db_handle *handle, void *key, uint32_t size);

void init_key_cmp(struct key_compare *key_cmp, void *key_buf, char key_format);
int key_cmp(struct key_compare *key1, struct key_compare *key2);
int prefix_compare(char *l, char *r, size_t prefix_size);

void recover_L0(struct db_descriptor *db_desc);

// void free_logical_node(allocator_descriptor *allocator_desc, node_header
// *node_index);

lock_table *_find_position(const lock_table **table, node_header *node);

#define MIN(x, y) ((x > y) ? (y) : (x))
#define ABSOLUTE_ADDRESS(X) (((uint64_t)(X)) - MAPPED)
#define REAL_ADDRESS(X) ((X) ? (void *)(MAPPED + (uint64_t)(X)) : BUG_ON())
/*TODO: (@geostyl) i think we should figure out a better way to write this*/
#define SERIALIZE_KEY(buf, key, key_size)                           \
	*(uint32_t *)buf = key_size;                                \
	*(uint32_t *)((char *)buf + sizeof(uint32_t)) = UINT32_MAX; \
	memcpy((char *)buf + sizeof(uint32_t) + sizeof(uint32_t), key, key_size)
#define KV_MAX_SIZE (4096 + 8)
#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)
#define LESS_THAN_ZERO -1
#define GREATER_THAN_ZERO 1
#define EQUAL_TO_ZERO 0

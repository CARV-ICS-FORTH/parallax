/** @file btree.h
 *  @brief
 *  @author Giorgos Saloustros (gesalous@ics.forth.gr)
 *  @author Giorgos Xanthakis  (gxanth@ics.forth.gr)
 */
#pragma once
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <limits.h>
#include <bloom.h>
#include "conf.h"
#include "../allocator/allocator.h"
#define SUCCESS 4
#define FAILED 5

#define SEGMENT_SIZE 2097152

#define KREON_OK 10
#define KREON_FAILED 18
#define KREON_STANDALONE 19

#define PREFIX_SIZE 12

#define SPILL_BUFFER_SIZE 32 * 1024
#define MAX_HEIGHT 9
/**
 * FLAGS used of during _insert
 */
#define SEARCH_PERSISTENT_TREE 0x01
#define SEARCH_DIRTY_TREE 0x02

/* types used for the keys
 * KV_FORMAT: [key_len|key]
 * KV_PREFIX: [PREFIX|HASH|ADDR_TO_KV_LOG]
 */
enum KV_type { KV_FORMAT = 19, KV_PREFIX = 20 };
#define SYSTEM_ID 0

extern unsigned long long ins_prefix_hit_l0;
extern unsigned long long ins_prefix_hit_l1;
extern unsigned long long ins_prefix_miss_l0;
extern unsigned long long ins_prefix_miss_l1;

extern int32_t index_order;

/*gxanth staff structures*/
typedef struct thread_dest {
	volatile struct thread_dest *next;
	volatile void *kv_dest;
	volatile unsigned kv_size;
	volatile short ready;
	char pad[40];
} thread_dest;

struct lookup_reply {
	void *addr;
	uint8_t lc_failed;
};

typedef enum {
	leafNode = 590675399,
	internalNode = 790393380,
	rootNode = 742729384,
	leafRootNode = 748939994, /*special case for a newly created tree*/
	invalid
} nodeType_t;

typedef enum db_status { DB_OPEN, DB_IS_CLOSING } db_status;

/*descriptor describing a spill operation and its current status*/
typedef enum {
	NO_SPILLING = 0,
	SPILLING_IN_PROGRESS = 1,
} level_0_tree_status;

enum kreon_status { FAILURE = -1 };

enum db_initializers { CREATE_DB = 4, DONOT_CREATE_DB = 5 };

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
	int moved_kvs;
	int in_mem;
	char pad[4046];
} segment_header;

/*Note IN stands for Internal Node*/
typedef struct IN_log_header {
	void *next;
	/*XXX TODO XXX, add garbage info in the future?*/
} IN_log_header;

/*leaf or internal node metadata, place always in the first 4KB data block*/
typedef struct node_header {
	uint64_t epoch; /*epoch of the node. It will be used for knowing when to
                     perform copy on write*/
	uint64_t fragmentation;
	union {
		/*data log info, KV log for leaves private for index*/
		/* Used by index nodes */
		uint64_t key_log_size;
		/* Used in dynamic leaves */
		uint32_t leaf_log_size;
	};
	uint64_t num_entries;
	IN_log_header *first_IN_log_header;
	IN_log_header *last_IN_log_header;
	int32_t height; /*0 are leaves, 1 are Bottom Internal nodes, and then we have
			  INs and root*/
	nodeType_t type; /*internal or leaf node*/
	char pad[8];
} __attribute__((packed)) node_header;

typedef struct index_entry {
	uint64_t left[1];
	uint64_t pivot;
	uint64_t right[0];
} __attribute__((packed)) index_entry;

struct bt_leaf_entry {
	char prefix[PREFIX_SIZE];
	uint64_t pointer;
} __attribute__((packed));

struct bt_leaf_entry_bitmap {
	unsigned char bitmap; // This bitmap informs us which kv_entry is available to store data in the static leaf.
};

struct bt_static_leaf_slot_array {
	uint32_t index;
};

struct bt_dynamic_leaf_slot_array {
	// The index points to the location of the kv pair in the leaf.
	uint32_t index : 28;
	uint32_t key_category : 3;
	// This bitmap informs us if the index points to an in-place kv or to a pointer in the log.
	unsigned char bitmap : 1;
};

// The first enumeration should always have as a value 0.
// UNKNOWN_LOG_CATEGORY must always be the last enumeration.
enum log_category {
	SMALL_INPLACE = 0,
	SMALL_INLOG,
	MEDIUM_INPLACE,
	MEDIUM_INLOG,
	BIG_INPLACE,
	BIG_INLOG,
	UNKNOWN_LOG_CATEGORY
};

#define INDEX_NODE_REMAIN (INDEX_NODE_SIZE - sizeof(struct node_header))
#define LEAF_NODE_REMAIN (LEAF_NODE_SIZE - sizeof(struct node_header))

#define IN_LENGTH ((INDEX_NODE_REMAIN - sizeof(uint64_t)) / sizeof(struct index_entry) - 1)

#define LN_ITEM_SIZE (sizeof(uint64_t) + (PREFIX_SIZE * sizeof(char)))
#define KV_LEAF_ENTRY (sizeof(struct bt_leaf_entry) + sizeof(struct bt_static_leaf_slot_array) + (1 / CHAR_BIT))
#define LN_LENGTH ((LEAF_NODE_REMAIN) / (KV_LEAF_ENTRY))

/* this is the same as root_node */
typedef struct index_node {
	node_header header;
	index_entry p[IN_LENGTH];
	uint64_t __last_pointer; /* XXX do not use it directly! */
	char __pad[INDEX_NODE_SIZE - sizeof(struct node_header) - sizeof(uint64_t) -
		   (IN_LENGTH * sizeof(struct index_entry))];
} __attribute__((packed)) index_node;

struct kv_format {
	uint32_t key_size;
	char key_buf[];
} __attribute__((packed));

struct value_format {
	uint32_t value_size;
	char value[];
};

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

struct splice {
	uint32_t size;
	char data[0];
};

/** contains info about the part of the log which has been commited but has not
 *  been applied in the index. In particular, recovery process now will be
 *  1. Read superblock, db_descriptor
 *  2. Is commit_log equal to the snapshot log?
 *      2.1 if not
 *              mark commit log segments as reserved in the allocator bitmap
 *              apply commit log changes in the index
 *              snapshot()
 *      else
 *              recover as usual
 * We now have two functions for persistence
 *      1. snapshot() persists the allocator, index, KV log, and db's of a
 *volume--> heavy operation called in minutes granularity
 *      2. commit_log() persists KV log, assuring that data in the KV-log after
 *      this operation are recoverable
 **/
typedef struct commit_log_info {
	segment_header *big_log_head;
	segment_header *big_log_tail;
	segment_header *medium_log_head;
	segment_header *medium_log_tail;
	segment_header *small_log_head;
	segment_header *small_log_tail;
	uint64_t big_log_size;
	uint64_t medium_log_size;
	uint64_t small_log_size;
	uint64_t lsn;
	char pad[4016];
} commit_log_info;

#if 0
/*used for tiering compactions at replicas*/
#define MAX_FOREST_SIZE 124
typedef struct forest {
	node_header *tree_roots[MAX_FOREST_SIZE];
	segment_header *tree_segment_list[MAX_FOREST_SIZE];
	uint64_t total_keys_per_tree[MAX_FOREST_SIZE];
	uint64_t end_of_log[MAX_FOREST_SIZE];
	char tree_status[MAX_FOREST_SIZE];
	char pad[4];
} forest;
#endif

/**
 * db_descriptor is a soft state descriptor per open database. superindex
*structure
 * keeps a serialized from of the vital information needed to restore each
*db_descriptor
**/

typedef struct lock_table {
	pthread_rwlock_t rx_lock;
	char pad[8];
} lock_table;

typedef struct kv_location {
	void *kv_addr;
	uint64_t log_offset;
	uint32_t rdma_key;
} kv_location;

typedef struct kv_proposal {
	void *kv;
	void *master_log_addr;
	uint64_t log_offset;
} kv_proposal;

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
	pthread_t spiller[NUM_TREES_PER_LEVEL];
	pthread_mutex_t level_allocation_lock;
	segment_header *first_segment[NUM_TREES_PER_LEVEL];
	segment_header *last_segment[NUM_TREES_PER_LEVEL];
	uint64_t offset[NUM_TREES_PER_LEVEL];
	lock_table guard_of_level;
	pthread_mutex_t spill_trigger;
	//Since we perform always KV separation we express it
	//in number of keys
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
	int64_t active_writers;
	/*spilling or not?*/
	uint32_t leaf_size;
	char tree_status[NUM_TREES_PER_LEVEL];
	uint8_t active_tree;
	uint8_t level_id;
	char in_recovery_mode;
} level_descriptor;

typedef struct db_descriptor {
	char db_name[MAX_DB_NAME_SIZE];
	level_descriptor levels[MAX_LEVELS];
	struct compaction_pairs inprogress_compactions[MAX_LEVELS];
	struct compaction_pairs pending_compactions[MAX_LEVELS];
#if MEASURE_MEDIUM_INPLACE
	uint64_t count_medium_inplace;
#endif
	pthread_cond_t client_barrier;
	pthread_cond_t compaction_cond;
	pthread_mutex_t compaction_structs_lock;
	pthread_mutex_t compaction_lock;
#if LOG_WITH_MUTEX
	pthread_mutex_t lock_log;
#else
	pthread_spinlock_t lock_log;
#endif
	pthread_mutex_t client_barrier_lock;
	sem_t compaction_daemon_interrupts;
	sem_t compaction_sem;
	sem_t compaction_daemon_sem;
	uint64_t blocked_clients;
	uint64_t compaction_count;
	pthread_t compaction_thread;
	pthread_t compaction_daemon;
	pthread_t gc_thread;
	//compaction daemon staff
	volatile segment_header *big_log_head;
	volatile segment_header *big_log_tail;
	volatile uint64_t big_log_size;
	volatile segment_header *medium_log_head;
	volatile segment_header *medium_log_tail;
	volatile uint64_t medium_log_size;
	volatile segment_header *small_log_head;
	volatile segment_header *small_log_tail;
	volatile uint64_t small_log_size;
	volatile uint64_t lsn;
	segment_header *inmem_medium_log_head[NUM_TREES_PER_LEVEL];
	segment_header *inmem_medium_log_tail[NUM_TREES_PER_LEVEL];
	uint64_t inmem_medium_log_size[NUM_TREES_PER_LEVEL];
	struct db_handle *gc_db;
	char *inmem_base;
	/*coordinates of the latest persistent L0*/
	/* Shouldn't this be in level_descriptor*/
	uint64_t big_log_head_offset;
	uint64_t big_log_tail_offset;
	uint64_t medium_log_head_offset;
	uint64_t medium_log_tail_offset;
	uint64_t small_log_head_offset;
	uint64_t small_log_tail_offset;
	uint64_t gc_last_segment_id;
	uint64_t gc_count_segments;
	uint64_t gc_keys_transferred;
	commit_log_info *commit_log;
	// uint64_t spilled_keys;
	int is_compaction_daemon_sleeping;
	int32_t reference_count;
	int32_t group_id;
	int32_t group_index;
	volatile char dirty;
	enum db_status stat;
} __attribute__((aligned)) db_descriptor;

typedef struct db_handle {
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
#define NUMBER_OF_LOGS 3

void recover_region(recovery_request *rh);
void snapshot(volume_descriptor *volume_desc);
void commit_db_log(db_descriptor *db_desc, commit_log_info *info);
void commit_db_logs_per_volume(volume_descriptor *volume_desc);

typedef struct rotate_data {
	node_header *left;
	node_header *right;
	void *pivot;
	int pos_left;
	int pos_right;
} rotate_data;

typedef struct bt_spill_request {
	db_descriptor *db_desc;
	volume_descriptor *volume_desc;
	uint64_t aggregate_level_size;
	segment_header *medium_log_head;
	segment_header *medium_log_tail;
	node_header *src_root;
	void *start_key;
	void *end_key;
	uint64_t level_size;
	uint64_t medium_log_size;
	uint64_t l0_start;
	uint64_t l0_end;
	uint8_t src_level;
	uint8_t src_tree;
	uint8_t dst_level;
	uint8_t dst_tree;
} bt_spill_request;
/*client API*/
/*management operations*/
db_handle *db_open(char *volumeName, uint64_t start, uint64_t size, char *db_name, char CREATE_FLAG);
struct db_handle *bt_restore_db(struct volume_descriptor *volume_desc, struct pr_db_entry *db_entry,
				struct db_coordinates db_c);

void *compaction_daemon(void *args);
void flush_volume(volume_descriptor *volume_desc, char force_spill);
void spill_database(db_handle *handle);

typedef struct bt_mutate_req {
	db_handle *handle;
	uint64_t *reorganized_leaf_pos_INnode;
	/*offset in log where the kv was written*/
	uint64_t log_offset;
	/*info for cases of segment_full_event*/
	uint64_t log_segment_addr;
	uint64_t log_offset_full_event;
	uint64_t segment_id;
	uint64_t end_of_log;
	uint32_t log_padding;
	uint32_t kv_size;
	enum log_category cat;
	uint8_t level_id;
	/*only for inserts >= level_1*/
	uint8_t tree_id;
	uint8_t append_to_log : 1;
	uint8_t gc_request : 1;
	uint8_t recovery_request : 1;
	/*needed for distributed version of Kreon*/
	uint8_t segment_full_event : 1;
	uint8_t special_split : 1;
	char key_format;
} bt_mutate_req;

typedef struct bt_insert_req {
	bt_mutate_req metadata;
	void *key_value_buf;
} bt_insert_req;

typedef struct bt_delete_request {
	bt_mutate_req metadata;
	index_node *parent;
	struct leaf_node *self;
	uint64_t offset; /*offset in my parent*/
	void *key_buf;
} bt_delete_request;

/* In case more operations are tracked in the log in the future such as transactions
   you will need to change the request_type enumerator and the log_operation struct.
   In the request_type you will add the name of the operation i.e. transactionOp and
   in the log_operation you will add a pointer in the union with the new operation i.e. transaction_request.
*/
typedef enum { insertOp, deleteOp, unknownOp } request_type;

typedef struct log_operation {
	bt_mutate_req *metadata;
	request_type optype_tolog;
	union {
		bt_insert_req *ins_req;
		bt_delete_request *del_req;
	};
} log_operation;

struct log_towrite {
	volatile segment_header *log_head;
	volatile segment_header *log_tail;
	volatile uint64_t *log_size;
	int level_id;
	enum log_category status;
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
	/*4 bytes for the key size and 255 Bytes for the key*/
	char middle_key[259];
	union {
		node_header *left_child;
		index_node *left_ichild;
		leaf_node *left_lchild;
		struct bt_static_leaf_node *left_slchild;
		struct bt_dynamic_leaf_node *left_dlchild;
	};

	union {
		node_header *right_child;
		index_node *right_ichild;
		leaf_node *right_lchild;
		struct bt_static_leaf_node *right_slchild;
		struct bt_dynamic_leaf_node *right_dlchild;
	};
	void *middle_key_buf;
	enum bt_rebalance_retcode stat;
};

typedef struct metadata_tologop {
	uint32_t key_len;
	uint32_t value_len;
	uint32_t kv_size;
} metadata_tologop;

struct log_sequence_number {
	uint64_t id;
};

struct siblings_index_entries {
	index_entry *left_entry;
	index_entry *right_entry;
	int left_pos;
	int right_pos;
};

typedef struct spill_data_totrigger {
	db_descriptor *db_desc;
	uint64_t prev_level_size;
	int prev_active_tree;
	int active_tree;
	uint level_id;
	int tree_to_spill;
} spill_data_totrigger;

uint8_t insert_key_value(db_handle *handle, void *key, void *value, uint32_t key_size, uint32_t value_size);
uint8_t _insert_key_value(bt_insert_req *ins_req);
void *append_key_value_to_log(log_operation *req);

uint8_t _insert_index_entry(db_handle *db, kv_location *location, int INSERT_FLAGS);
void *find_key(db_handle *handle, void *key, uint32_t key_size);
void *__find_key(db_handle *handle, void *key);
int8_t delete_key(db_handle *handle, void *key, uint32_t size);

int64_t key_cmp(void *index_key_buf, void *query_key_buf, char index_key_format, char query_key_format);
int prefix_compare(char *l, char *r, size_t unused);

void free_buffered(void *_handle, void *address, uint32_t num_bytes, int height);

/*functions used from other parts except btree/btree.c*/

void *_index_node_binary_search(index_node *node, void *key_buf, char query_key_format);

// void free_logical_node(allocator_descriptor *allocator_desc, node_header
// *node_index);

lock_table *_find_position(lock_table **table, node_header *node);
#define MIN(x, y) ((x > y) ? (y) : (x))
#define KEY_SIZE(x) (*(uint32_t *)(x))
#define VALUE_SIZE(x) KEY_SIZE(x)
#define ABSOLUTE_ADDRESS(X) (((uint64_t)(X)) - MAPPED)
#define REAL_ADDRESS(X) ((void *)(uint64_t)(MAPPED + (uint64_t)(X)))
#define KEY_OFFSET(KEY_SIZE, KV_BUF) (sizeof(uint32_t) + KV_BUF)
#define VALUE_SIZE_OFFSET(KEY_SIZE, KEY) (sizeof(uint32_t) + KEY_SIZE + KEY)
#define SERIALIZE_KEY(buf, key, key_size) \
	*(uint32_t *)buf = key_size;      \
	memcpy(buf + 4, key, key_size)
#define KV_MAX_SIZE (4096 + 8)
#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)
#define LESS_THAN_ZERO -1
#define GREATER_THAN_ZERO 1
#define EQUAL_TO_ZERO 0

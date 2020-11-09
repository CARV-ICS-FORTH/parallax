/** @file btree.h
 *  @brief
 *  @author Giorgos Saloustros (gesalous@ics.forth.gr)
 *
 */
#pragma once
#include <semaphore.h>
#include "../../build/config.h"
#include "../allocator/allocator.h"
#include "uthash.h"

#include <pthread.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include "stats.h"

#define SUCCESS 4
#define FAILED 5

#define O_CREATE_REPLICA_DB 0x05
#define DYNAMIC_KEYS 0

#define SEGMENT_SIZE 2097152

#define MAX_TS 0xFFFFFFFFFFFFFFFF

#define KREON_OK 10
#define KREON_FAILED 18
#define KREON_STANDALONE 19
#define REPLICA_PENDING_SPILL 20

/*hierarchy of trees parameters*/
#define MAX_LEVELS 8
#define NUM_TREES_PER_LEVEL 2

#define MAX_COUNTER_VERSIONS 4

#define PREFIX_SIZE 12

#define SPILL_BUFFER_SIZE 32 * 1024
#define SIZEOF_SEGMENT_IN_LOG_BUFFER 2097152
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

typedef enum {
	NOT_USED = 0,
	IN_TRANSIT,
	IN_TRANSIT_DIRTY,
	READY_TO_PERSIST,
	PERSISTED,
} replica_tree_status;

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
	uint64_t garbage_bytes[2 * MAX_COUNTER_VERSIONS];
	char pad[4008];
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
	volatile uint64_t v1;
	volatile uint64_t v2;
	/*data log info, KV log for leaves private for index*/
	uint64_t key_log_size;
	uint64_t numberOfEntriesInNode;
	IN_log_header *first_IN_log_header;
	IN_log_header *last_IN_log_header;
	int32_t height; /*0 are leaves, 1 are Bottom Internal nodes, and then we have
			  INs and root*/
	uint8_t level_id;
	nodeType_t type; /*internal or leaf node*/
	char pad[8];
} __attribute__((packed)) node_header;

typedef struct index_entry {
	uint64_t left[1];
	uint64_t pivot;
	uint64_t right[0];
} __attribute__((packed)) index_entry;

typedef struct bt_leaf_entry {
	uint64_t pointer;
	char prefix[PREFIX_SIZE];
} bt_leaf_entry;

struct bt_leaf_entry_bitmap {
	unsigned char bitmap;
};

typedef struct bt_leaf_slot_array {
	uint16_t index;
} bt_leaf_slot_array;

#define INDEX_NODE_REMAIN (INDEX_NODE_SIZE - sizeof(struct node_header))
#define LEAF_NODE_REMAIN (LEAF_NODE_SIZE - sizeof(struct node_header))

#define IN_LENGTH ((INDEX_NODE_REMAIN - sizeof(uint64_t)) / sizeof(struct index_entry) - 1)

#define LN_ITEM_SIZE (sizeof(uint64_t) + (PREFIX_SIZE * sizeof(char)))
#define KV_LEAF_ENTRY (sizeof(bt_leaf_entry) + sizeof(bt_leaf_slot_array) + (1 / CHAR_BIT))
#define LN_LENGTH ((LEAF_NODE_REMAIN) / (KV_LEAF_ENTRY))

/* this is the same as root_node */
typedef struct index_node {
	node_header header;
	index_entry p[IN_LENGTH];
	uint64_t __last_pointer; /* XXX do not use it directly! */
	char __pad[INDEX_NODE_SIZE - sizeof(struct node_header) - sizeof(uint64_t) -
		   (IN_LENGTH * sizeof(struct index_entry))];
} __attribute__((packed)) index_node;

struct bt_static_leaf_node {
	struct node_header header;
} __attribute__((packed));

typedef struct leaf_node {
	struct node_header header;
	uint64_t pointer[LN_LENGTH];
	char prefix[LN_LENGTH][PREFIX_SIZE];
	char __pad[LEAF_NODE_SIZE - sizeof(struct node_header) - (LN_LENGTH * LN_ITEM_SIZE)];
} __attribute__((packed)) leaf_node;

/* Possible options for these defines are multiples of 4KB but they should not be more than BUFFER_SEGMENT_SIZE*/
#define PAGE_SIZE 4096
#define LEVEL0_LEAF_SIZE (PAGE_SIZE)
#define LEVEL1_LEAF_SIZE (PAGE_SIZE * 2)
#define LEVEL2_LEAF_SIZE (PAGE_SIZE * 3)
#define LEVEL3_LEAF_SIZE (PAGE_SIZE * 4)
#define LEVEL4_LEAF_SIZE (PAGE_SIZE)
#define LEVEL5_LEAF_SIZE (PAGE_SIZE)
#define LEVEL6_LEAF_SIZE (PAGE_SIZE)
#define LEVEL7_LEAF_SIZE (PAGE_SIZE)

/* Possible options for these defines are the values in enum bt_layout */
#define LEVEL0_LEAF_LAYOUT STATIC_LEAF
#define LEVEL1_LEAF_LAYOUT STATIC_LEAF
#define LEVEL2_LEAF_LAYOUT STATIC_LEAF
#define LEVEL3_LEAF_LAYOUT STATIC_LEAF
#define LEVEL4_LEAF_LAYOUT STATIC_LEAF
#define LEVEL5_LEAF_LAYOUT STATIC_LEAF
#define LEVEL6_LEAF_LAYOUT STATIC_LEAF
#define LEVEL7_LEAF_LAYOUT STATIC_LEAF

/* this is the same as leaf_root_node */
//__attribute__((packed))
/* this is KV_FORMAT */
struct splice {
	int32_t size;
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
	segment_header *first_kv_log;
	segment_header *last_kv_log;
	uint64_t kv_log_size;
	char pad[4072];
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

typedef struct map_entry {
	uint64_t key;
	uint64_t value;
	UT_hash_handle hh;
} map_entry;

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

enum bt_layout { STATIC_LEAF, DYNAMIC_LEAF };

typedef struct level_descriptor {
	lock_table guard_of_level;
	pthread_t compaction_thread[NUM_TREES_PER_LEVEL];
	lock_table *level_lock_table[MAX_HEIGHT];
	node_header *root_r[NUM_TREES_PER_LEVEL];
	node_header *root_w[NUM_TREES_PER_LEVEL];
	pthread_t spiller[NUM_TREES_PER_LEVEL];

	pthread_mutex_t spill_trigger;
	pthread_mutex_t level_allocation_lock;
	segment_header *first_segment[NUM_TREES_PER_LEVEL];
	segment_header *last_segment[NUM_TREES_PER_LEVEL];
	uint64_t offset[NUM_TREES_PER_LEVEL];
	//Since we perform always KV separation we express it
	//in number of keys
	uint64_t level_size[NUM_TREES_PER_LEVEL];
	uint64_t max_level_size;
	leaf_node_metadata leaf_offsets;
	int64_t active_writers;
	/*spilling or not?*/
	char tree_status[NUM_TREES_PER_LEVEL];
	uint32_t leaf_size;
	enum bt_layout node_layout;
	uint8_t active_tree;
	uint8_t level_id;
	char in_recovery_mode;
} level_descriptor;

typedef struct db_descriptor {
	char db_name[MAX_DB_NAME_SIZE];
	level_descriptor levels[MAX_LEVELS];
#if LOG_WITH_MUTEX
	pthread_mutex_t lock_log;
#else
	pthread_spinlock_t lock_log;
#endif
	//compaction daemon staff
	pthread_t compaction_daemon;
	sem_t compaction_daemon_interrupts;
	pthread_cond_t client_barrier;
	pthread_mutex_t client_barrier_lock;

	pthread_spinlock_t back_up_segment_table_lock;
	volatile segment_header *KV_log_first_segment;
	volatile segment_header *KV_log_last_segment;
	volatile uint64_t KV_log_size;
	uint64_t latest_proposal_start_segment_offset;
	/*coordinates of the latest persistent L0*/
	uint64_t L0_start_log_offset;
	uint64_t L0_end_log_offset;

	commit_log_info *commit_log;
	// uint64_t spilled_keys;
	int32_t reference_count;
	int32_t group_id;
	int32_t group_index;
	/*gxanth new staff*/
	volatile char dirty;
	enum db_status stat;
	// void *(*createEmptyNode)(allocator_descriptor *allocator_desc, db_handle
	// *handle, nodeType_t type,
	//			 char allocation_code);
} __attribute__((packed)) __attribute__((aligned)) db_descriptor;

typedef struct db_handle {
	volume_descriptor *volume_desc;
	db_descriptor *db_desc;
} db_handle;

typedef struct recovery_request {
	volume_descriptor *volume_desc;
	db_descriptor *db_desc;
	uint64_t recovery_start_log_offset;
} recovery_request;
void recovery_worker(void *);

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

/*client API*/
/*management operations*/
db_handle *db_open(char *volumeName, uint64_t start, uint64_t size, char *db_name, char CREATE_FLAG);

void *compaction_daemon(void *args);
void flush_volume(volume_descriptor *volume_desc, char force_spill);
void spill_database(db_handle *handle);

typedef struct bt_mutate_req {
	db_handle *handle;

	/*offset in log where the kv was written*/
	uint64_t log_offset;
	/*info for cases of segment_full_event*/
	uint64_t log_segment_addr;
	uint64_t log_offset_full_event;
	uint64_t segment_id;
	uint64_t end_of_log;
	uint32_t log_padding;
	uint32_t kv_size;
	uint8_t level_id;
	//uint32_t active_tree;
	/*only for inserts >= level_1*/
	uint8_t tree_id;
	char key_format;
	uint8_t append_to_log : 1;
	uint8_t gc_request : 1;
	uint8_t recovery_request : 1;
	/*needed for distributed version of Kreon*/
	uint8_t segment_full_event : 1;
	uint8_t special_split : 1;
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
	union {
		node_header *left_child;
		index_node *left_ichild;
		leaf_node *left_lchild;
		struct bt_static_leaf_node *left_slchild;
	};

	union {
		node_header *right_child;
		index_node *right_ichild;
		leaf_node *right_lchild;
		struct bt_static_leaf_node *right_slchild;
	};

	void *middle_key_buf;
	enum bt_rebalance_retcode stat;
};

typedef struct metadata_tologop {
	uint32_t key_len;
	uint32_t value_len;
	uint32_t kv_size;
} metadata_tologop;

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
char *node_type(nodeType_t type);
void *find_key(db_handle *handle, void *key, uint32_t key_size);
void *__find_key(db_handle *handle, void *key, char SEARCH_MODE);
int8_t delete_key(db_handle *handle, void *key, uint32_t size);

int64_t _tucana_key_cmp(void *index_key_buf, void *query_key_buf, char index_key_format, char query_key_format);
int prefix_compare(char *l, char *r, size_t unused);

void free_buffered(void *_handle, void *address, uint32_t num_bytes, int height);

/*functions used from other parts except btree/btree.c*/

void *_index_node_binary_search(index_node *node, void *key_buf, char query_key_format);

// void free_logical_node(allocator_descriptor *allocator_desc, node_header
// *node_index);

lock_table *_find_position(lock_table **table, node_header *node);
#define MIN(x, y) ((x > y) ? (y) : (x))
#define KEY_SIZE(x) (*(uint32_t *)x)
#define ABSOLUTE_ADDRESS(X) ((uint64_t)X - MAPPED)
#define REAL_ADDRESS(X) ((void *)(uint64_t)(MAPPED + X))
#define VALUE_SIZE_OFFSET(KEY_SIZE, KEY) (sizeof(uint32_t) + KEY_SIZE + KEY)
#define SERIALIZE_KEY(buf, key, key_size)                                                                              \
	*(uint32_t *)buf = key_size;                                                                                   \
	memcpy(buf + 4, key, key_size)
#define KV_MAX_SIZE (4096 + 8)
#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

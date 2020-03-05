/** @file btree.h
 *  @brief
 *  @author Giorgos Saloustros (gesalous@ics.forth.gr)
 *
 */
#ifndef _BTREE_H_
#define _BTREE_H_



#include "../allocator/allocator.h"
//#include "uthash.h"
#include "../../external-deps/src/uthash/src/uthash.h"



typedef struct volume_descriptor volume_descriptor;
#include <pthread.h>
#include <stdlib.h>

//#include "stats.h"



#define SUCCESS 4
#define FAILED  5

#define O_CREATE_DB 0x04
#define O_NOT_CREATE_DB 0xCE
#define O_CREATE_REPLICA_DB 0x05
#define DYNAMIC_KEYS 0

#define  MAX_TS  0xFFFFFFFFFFFFFFFF
#define  SPLIT  1
#define  COW  2
#define  NO_OP  0
#define  MERGE_WITH_LEFT  3
#define  MERGE_WITH_RIGHT  4
#define  PURGE  5
#define LEFT_ROTATE_INDEX 6
#define LEFT_ROTATE_LEAF 7
#define RIGHT_ROTATE_INDEX 8
#define RIGHT_ROTATE_LEAF 9

#define KREON_OK 10
#define KREON_FAILED 18
#define KREON_STANDALONE 19
#define REPLICA_PENDING_SPILL 20

#define KEY_NOT_FOUND 11
#define MERGE_NODE 12//?

#define QUALLIE_MASK 0x0000FFFF
#define ROW_KEY_MASK 0xFFFF0000

/*hierarchy of trees parameters*/
//gesalous dead-->#define NUM_OF_PERSISTENT_LEVELS 2
#define NUM_OF_TREES_PER_LEVEL 4
#define TOTAL_TREES 8/*that is NUM_OF_PERSISTENT_LEVELS*NUM_OF_TREES_PER_LEVEL*/
#define MAX_DB_NAME_SIZE 136
#define NUM_OF_DB_GROUPS 504
#define DB_ENTRY_SIZE 512
#define GROUP_SIZE 7

#define MAX_COUNTER_VERSIONS 4
#define HASH_SIZE 0

#define FIXED_SIZE_KEYS_NO
#define PREFIX_SIZE 12

#define COUNTER_SIZE 2097152 //stats for leaf scanner accesses
#define COUNTER_THREASHOLD 1
#define NUM_OF_SPILL_THREADS_PER_DB 1
#define SPILL_BUFFER_SIZE 32 * 1024
#define SIZEOF_LOG_BUFFER 8
#define SIZEOF_SEGMENT_IN_LOG_BUFFER 2097152
#define MAX_HEIGHT 9
#define MIN_ENTRIES_TO_SPILL NUM_OF_SPILL_THREADS_PER_DB-1
//#define FIXED_SIZE_KEYS_NO
/*INSERT_FLAGS fields
*This is an integer that the most significant byte
*encodes the tree level,next encodes to append or not to the log
*the third byte encodes the position in the db_desc->root_r and db_desc->root_w array
*where the corresponding root of the level is,the last byte is left for future extension purposes.
*/
#define INSERT_TO_L0_INDEX          0x00000000
#define INSERT_TO_L1_INDEX   0x01000000
#define INSERT_TO_REPLICA_L1_INDEX   0x02000000
#define APPEND_TO_LOG        0x00010000
#define DO_NOT_APPEND_TO_LOG 0x00020000
#define PRIMARY_L0_INSERT    0x000000AB
#define RECOVERY_OPERATION    0x000000AC
#define BACKUP_OPERATION    0x000000AF
#define SPILL_OPERATION    0x000000AA

#define KEYSIZE_BUF_DATASIZE_BUF  0x0A
#define KEYSIZE_DATASIZE_BUF 0x0F

/**
 * FLAGS used of during _insert
 */
#define SEARCH_PERSISTENT_TREE 0x01
#define SEARCH_DIRTY_TREE 0x02

/* types used for the keys
 * KV_FORMAT: [key_len|key]
 * KV_PREFIX: [PREFIX|HASH|ADDR_TO_KV_LOG]
 */
#define KV_FORMAT 19
#define KV_PREFIX 20
#define SYSTEM_ID 0
#define KV_LOG_ID 5

#define SPILL_ALL_DBS_IMMEDIATELY 0x01
#define DO_NOT_FORCE_SPILL 0x02
#define SPILLS_ISSUED 0x00

extern unsigned long long ins_prefix_hit_l0;
extern unsigned long long ins_prefix_hit_l1;
extern unsigned long long ins_prefix_miss_l0;
extern unsigned long long ins_prefix_miss_l1;

int32_t leaf_order;
int32_t index_order;

typedef enum{
	leafNode = 590675399,
	internalNode = 790393380,
	rootNode = 742729384,
	leafRootNode = 748939994/*special case for a newly created tree*/
} nodeType_t;


typedef enum{
  NOT_USED = 0,
  IN_TRANSIT,
  IN_TRANSIT_DIRTY,
  READY_TO_PERSIST,
  PERSISTED,
} replica_tree_status;

/*descriptor describing a spill operation and its current status*/
typedef enum{
	NO_SPILLING = 0,
	SPILLING_IN_PROGRESS = 1,
}level_0_tree_status;




/*
 * header of segment is 4K. L0 and KV log segments are chained in a linked list with next and prev
 * pointers. garbage_bytes contains info about the unused bytes in the segment
 * due to deletes/updates.
 */
typedef struct segment_header{
	/*LEAVE NEXT BLOCK AS IS FIRST OTHERWISE INSERTKEYATINDEX WILL FAIL FATALLY XXX TODO XXX MAYBE SOLVE IT IN THE FUTURE?*/
	void * next_segment;
	void * prev_segment;
	uint64_t segment_id;
	uint64_t garbage_bytes[2*MAX_COUNTER_VERSIONS];
	char pad[4008];
} segment_header;

/*Note IN stands for Internal Node*/
typedef struct IN_log_header{
	void *next;
	/*XXX TODO XXX, add garbage info in the future?*/
}IN_log_header;

/*leaf or internal node metadata, place always in the first 4KB data block*/
typedef struct node_header {
	uint64_t epoch; /*epoch of the node. It will be used for knowing when to perform copy on write*/
	uint64_t fragmentation;
	volatile uint64_t v1;
	volatile uint64_t v2;
	/*data log info, KV log for leaves private for index*/
	IN_log_header *first_IN_log_header;
	IN_log_header *last_IN_log_header;
	uint64_t key_log_size;
	int32_t height;/*0 are leaves, 1 are Bottom Internal nodes, and then we have INs and root*/
	nodeType_t type; /*internal or leaf node*/
	uint64_t numberOfEntriesInNode;
#ifdef SCAN_REORGANIZATION
	uint64_t leaf_id;
#else
	char pad[8];
#endif
} __attribute__((packed)) node_header;
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
 *      1. snapshot() persists the allocator, index, KV log, and db's of a volume--> heavy operation called in minutes granularity
 *      2. commit_log() persists KV log, assuring that data in the KV-log after
 *      this operation are recoverable
 **/
typedef struct commit_log_info{
  segment_header * first_kv_log;
  segment_header * last_kv_log;
  uint64_t kv_log_size;
  char pad[4072];
}commit_log_info;



/*used for tiering compactions at replicas*/
#define MAX_FOREST_SIZE 124
typedef struct forest{
  node_header * tree_roots[MAX_FOREST_SIZE];
  segment_header * tree_segment_list[MAX_FOREST_SIZE];
	uint64_t total_keys_per_tree[MAX_FOREST_SIZE];
  uint64_t end_of_log[MAX_FOREST_SIZE];
	char tree_status[MAX_FOREST_SIZE];
	char pad[4];
}forest;



struct superindex_db_entry{
  char db_name[MAX_DB_NAME_SIZE];
	uint64_t segments[TOTAL_TREES*3];
	node_header * root_r[TOTAL_TREES];
	uint64_t total_keys[TOTAL_TREES];

	/*commit log is in a different location on the device for the following reason:*
	 * In Kreon for persistence we have two persistence operations commit_log and snapshot()
	 * Commit log only commits the log and it is faster than snapshot. It actual trades performance vs recovery_time.
	 * This is because db should replay a part of its tail log to add missing index.
	 * Snapshot commits both index and log (it actually calls commit_log) and is slower but provides instant recovery.
	 * With the separation of these two techiques we are able to issue snapshot less frequent (order of minutes) without losing data
	 * */
	commit_log_info * commit_log;
	/*
	 * info to locate after a recovery which tail part 
	 * of the log is missing from the index
	 */
	uint64_t L0_start_log_offset;
	uint64_t L0_end_log_offset;
	forest * replica_forest;
	char pad[24];
};



/**
 * db_descriptor is a soft state descriptor per open database. superindex structure
 * keeps a serialized from of the vital information needed to restore each db_descriptor
**/


typedef struct lock_table{
	pthread_rwlock_t rx_lock;
	char pad[8];
}lock_table;

typedef struct map_entry{
	uint64_t key;
	uint64_t value;
	UT_hash_handle hh;
}map_entry;

typedef struct kv_location{
	void *kv_addr;
	uint64_t log_offset;
	uint32_t rdma_key;
}kv_location;

typedef struct kv_proposal{
	void *kv;
	void * master_log_addr;
	uint64_t log_offset;
}kv_proposal;

typedef struct db_descriptor{
#ifdef KREONR
  forest replica_forest;
  /*used in replicas*/
	void* log_buffer;
	struct connection_rdma ** data_conn;
	char * region_min_key;
	uint64_t last_master_segment;
	uint64_t last_local_mapping;
	/*segment mappings kept only by replica, soft state*/
	volatile map_entry * backup_segment_table;/*used at apply proposal*/
	volatile	map_entry * spill_segment_table;/*used during remote spills*/
  uint64_t latest_proposal_start_segment_offset;
#endif
	char db_name[MAX_DB_NAME_SIZE];
	node_header * root_r[TOTAL_TREES];
	node_header * root_w[TOTAL_TREES];
	uint64_t segments[TOTAL_TREES*3];
	int64_t total_keys[TOTAL_TREES];
	pthread_t spiller[NUM_OF_SPILL_THREADS_PER_DB];
#if LOG_WITH_MUTEX
	pthread_mutex_t lock_log;
#else
	pthread_spinlock_t lock_log;
#endif
	pthread_spinlock_t back_up_segment_table_lock;
	lock_table* multiwrite_level_0[MAX_HEIGHT];
	lock_table* multiwrite_level_1[MAX_HEIGHT];
	lock_table guard_level_0;
	lock_table guard_level_1;
	int64_t count_writers_level_0;
	int64_t count_writers_level_1;
	int64_t count_active_spillers;
	char tree_status[TOTAL_TREES];
	uint64_t zero_level_memory_size;

	volatile segment_header * KV_log_first_segment;
	volatile segment_header * KV_log_last_segment;
	volatile uint64_t KV_log_size;
	/*coordinates of the latest persistent L0*/
	uint64_t L0_start_log_offset;
	uint64_t L0_end_log_offset;

	commit_log_info * commit_log;
 #ifdef SCAN_REORGANIZATION
	uint64_t leaf_id;
#endif
	//uint64_t spilled_keys;
	int32_t reference_count;
	int32_t group_id;
	int32_t group_index;
	volatile int32_t active_tree;/*in which tree of the zero level the inserts take place(0,3)*/
	char dirty;
  /*primary or back_up db, instructed from zookeeper*/
	char db_mode;
} __attribute__((packed)) __attribute__ ((aligned)) db_descriptor;



struct db_handle{
	volume_descriptor *volume_desc;
	db_descriptor *db_desc;
};

/**
 * function pointers, their puprose is the following:
 * Each mutate request (insert, delete, split and other rebalanace ops)
 * when they need to allocate/free space will:
 * When operating in the global tree granularity they ll use allocator's function for
 * allocating/freeing space. When operation inside a tucana buffer they ll use the internal functions
 **/
typedef struct allocator_descriptor
{
	/*function pointer to appropriate allocate function*/
	void * (*allocate_space)(void *, uint64_t, int, char);
	/*function pointer to appropriate free function*/
	void   (*free_space)(void *, void *, uint32_t, int);
	void * handle;/*points either to the volume_desc or db_desc*/
	int32_t level_id;
}allocator_descriptor;


typedef struct insertKV_request {
	allocator_descriptor allocator_desc;
	db_handle *handle;
	void* key_value_buf;
	void* log_address;/*used from RDMA server*/
	lock_table** level_lock_table;
	lock_table* guard_of_level;

	int level_id;
	int insert_flags;/*used either by RDMA server or recovery*/
	char key_format;
} insertKV_request;



typedef struct delete_request{
	allocator_descriptor allocator_desc;
	db_handle * handle;
	node_header * parent;
	uint64_t offset;/*offset in my parent*/
	node_header * self;
}delete_request;

typedef struct delete_reply{
	node_header * new_self;/*in case of COW*/
	node_header * new_left_brother;/*in case of COW*/
	node_header * new_right_brother;/*in case of COW*/
	void * key;
	int status;
}delete_reply;


typedef struct split_request{
	allocator_descriptor allocator_desc;
	db_handle * handle;
	node_header * node;
	char insert_mode;
} split_request;


typedef struct split_reply{
	node_header * left_child;
	node_header * right_child;
	void * middle_key_buf;
} split_reply;


typedef struct spill_request{
	db_descriptor* db_desc;
	volume_descriptor * volume_desc;
	node_header * src_root;
	int32_t src_tree_id;
	int32_t dst_tree_id;
	void * start_key;
	void * end_key;
	uint64_t l0_start;
	uint64_t l0_end;
}spill_request;

/*client API*/
/*management operations*/
db_handle * db_open(char * volumeName, uint64_t start, uint64_t size, char * db_name, char CREATE_FLAG);
char db_close(db_handle *handle);

  

void flush_volume(volume_descriptor * volume_desc, char force_spill);
void spill_database(db_handle * handle);
void split_spill_requests(node_header * root,spill_request * spill_req);
/*data path related staff*/
/**
 * Structure used for multimutations operations (put/deletes)
 *
**/
typedef struct mutation_batch
{
	uint32_t num_of_mutations;
	uint32_t position;
	uint32_t size;
	uint32_t type;/*two types STATIC -- buffer is malloced -- DYNAMIC buffer is given from application*/
	void * buffer;
} mutation_batch;


uint8_t insert_key_value(db_handle * handle, void *key, void * value, uint32_t key_size, uint32_t value_size);
uint8_t insert_write_batch(db_handle * handle, mutation_batch * ops);

void _append_key_value_to_log(db_handle *handle, void *key_value, char KEY_VALUE_FORMAT, kv_location * location, int32_t append_flags);
uint8_t _insert_index_entry(db_handle *db, kv_location * location, int INSERT_FLAGS);


#ifdef KREONR
/*replica stuff*/
void init_backup_db_segment_table(db_handle *);
void register_thread(db_handle *, int);
int flush_replica_log_buffer(db_handle * handle, segment_header * master_log_segment, void * buffer, uint64_t end_of_log, uint64_t bytes_to_pad, uint64_t segment_id);
void init_tree_node(db_handle * handle, node_header * node, int type);
int commit_kv_log_metadata(db_handle * handle);
#endif

/**
* this is for local ycsb
**/
mutation_batch * create_mutation_batch(int32_t size);

/**
	* This for network integration
	*
**/
mutation_batch * create_mutation_batch_from_buffer(void * buffer, uint32_t size, uint32_t num_of_items);
void initiate_mutation_batch_from_buffer(mutation_batch *batch,void * buffer,int32_t size,int32_t num_of_mutations);


void clear_mutation_batch(mutation_batch *mutation);
void destroy_mutation_batch(mutation_batch *mutation);
uint8_t add_mutation(mutation_batch * batch, void * key, void *data, uint32_t key_size, uint32_t data_size);

void * find_key(db_handle *handle, void *key, uint32_t key_size);
uint8_t delete_key(db_handle *handle, void *key, uint32_t size);

int64_t _tucana_key_cmp(void *index_key_buf, void *query_key_buf, char index_key_format, char query_key_format);
int prefix_compare(char *l, char *r, size_t unused);

void free_buffered(void *_handle, void *address, uint32_t num_bytes, int height);

void parse_deleted_keys(db_descriptor *db_desc);

/*functions used from other parts except btree/btree.c*/
uint8_t _writers_join_as_readers(insertKV_request * req);
uint8_t _concurrent_insert(insertKV_request * req);
void * __findKey(db_handle * handle, void *key_buf, char dirty); // dirty 0
void *  _index_node_binary_search(node_header * node, void * key_buf, char query_key_format);

void free_logical_node(allocator_descriptor * allocator_desc, node_header * node_index);

int insertKVAtLeaf(insertKV_request *req,  node_header * leaf, char allocation_code);

node_header * findLeafNode(node_header * root, void *key_buf);
void print_node(node_header * node);
void print_key(const char *, void *);
/*Gxanth lock_table stuff*/
void _init_locktable(db_descriptor* database);
void _destroy_locktable(db_descriptor* database);
lock_table * _find_position(lock_table ** table,node_header* node);



#define SPINLOCK_INIT(L,attr) pthread_spin_init(L,attr)
#define SPIN_LOCK(L) pthread_spin_lock(L)
#define SPIN_UNLOCK(L) pthread_spin_unlock(L)

/*Important note Condition variables are not defined*/
#define MUTEX_INIT(L,attr) pthread_mutex_init(L,attr)
#define MUTEX_LOCK(L) pthread_mutex_lock(L)
#define MUTEX_UNLOCK(L) pthread_mutex_unlock(L)

#define RWLOCK_INIT(L,attr) pthread_rwlock_init(L,attr)
#define RWLOCK_WRLOCK(L) pthread_rwlock_wrlock(L)
#define RWLOCK_RDLOCK(L) pthread_rwlock_rdlock(L)
#define RWLOCK_UNLOCK(L) pthread_rwlock_unlock(L)

#endif /* _BTREE_H_ */

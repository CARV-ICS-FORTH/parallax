/** @file btree.h
 *  @brief
 *  @author Giorgos Saloustros (gesalous@ics.forth.gr)
 *
 */
#pragma once
#include "../log/src/log.h"
#include "../allocator/allocator.h"
#include "uthash.h"

typedef struct volume_descriptor volume_descriptor;
#include <pthread.h>
#include <stdlib.h>

#include "stats.h"
#include "locks.h"

#define USER_MCS

#define SUCCESS 4
#define FAILED  5

#define O_CREATE_DB 0x04
#define O_NOT_CREATE_DB 0xCE
#define O_CREATE_REPLICA_DB 0x05
#define DYNAMIC_KEYS 0

#define TUCANA_2
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
#define KEY_NOT_FOUND 11
#define MERGE_NODE 12//?

#define QUALLIE_MASK 0x0000FFFF
#define ROW_KEY_MASK 0xFFFF0000

/*hierarchy of trees parameters*/
#define NUM_OF_PERSISTENT_LEVELS 2
#define NUM_OF_TREES_PER_LEVEL 4
#define TOTAL_TREES 8/*that is NUM_OF_PERSISTENT_LEVELS*NUM_OF_TREES_PER_LEVEL*/
#define MAX_DB_NAME_SIZE 152
#define NUM_OF_DB_GROUPS 504
#define DB_ENTRY_SIZE 512
#define GROUP_SIZE 7

#define MAX_COUNTER_VERSIONS 4

#define PREFIX_SIZE 12

#define COUNTER_SIZE 2097152 //stats for leaf scanner accesses
#define COUNTER_THREASHOLD 1
#define NUM_OF_SPILL_THREADS_PER_DB 2
#define MAX_HEIGHT 9
#define MIN_ENTRIES_TO_SPILL NUM_OF_SPILL_THREADS_PER_DB-1

/*INSERT_FLAGS fields
*This is an integer that the most significant byte
*encodes the tree level,next encodes to append or not to the log
*the third byte encodes the position in the db_desc->root_r and db_desc->root_w array
*where the corresponding root of the level is,the last byte is left for future extension purposes.
*/
#define INSERT_TO_L0_INDEX   0x00000000
#define INSERT_TO_L1_INDEX   0x01000000
#define INSERT_TO_L2_INDEX   0x02000000
#define APPEND_TO_LOG        0x00010000
#define DO_NOT_APPEND_TO_LOG 0x00020000


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

typedef enum{
	leafNode = 590675399,
	internalNode = 790393380,
	rootNode = 742729384,
	leafRootNode = 748939994/*special case for a newly created tree*/
} nodeType_t;


typedef struct block_header{
	/*LEAVE NEXT BLOCK AS IS FIRST OTHERWISE INSERTKEYATINDEX WILL FAIL FATALLY XXX TODO XXX MAYBE SOLVE IT IN THE FUTURE?*/

	void * next_block;
	uint64_t garbage_bytes[2*MAX_COUNTER_VERSIONS];
	char pad[4024];
} block_header;

/*leaf or internal node metadata, place always in the first 4KB data block*/
typedef struct node_header
{
	uint64_t epoch; /*epoch of the node. It will be used for knowing when to perform copy on write*/
	uint64_t fragmentation;
	volatile uint64_t v1;
	volatile uint64_t v2;
	/*data log info, KV log for leaves private for index*/
	block_header *first_key_block;
	block_header *last_key_block;
	uint64_t key_log_size;
	int32_t height;/*0 are leaves, 1 are Bottom Internal nodes, and then we have INs and root*/
	nodeType_t type; /*internal or leaf node*/
	uint64_t num_entries;
#ifdef SCAN_REORGANIZATION
	uint64_t leaf_id;
#else
	char pad[8];
#endif
} __attribute__((packed)) node_header;

#define NODE_REMAIN		(NODE_SIZE - sizeof(struct node_header))

#define IN_LENGTH			( (NODE_REMAIN - sizeof(uint64_t)) / sizeof(struct index_entry) - 1)

#define LN_ITEM_SIZE	(sizeof(uint64_t) + (PREFIX_SIZE * sizeof(char)))
#define LN_LENGTH			(NODE_REMAIN / LN_ITEM_SIZE)

/* this is KV_PREFIX */
typedef struct kv_prefix {
	char prefix[PREFIX_SIZE];
	uint64_t pointer;
} __attribute__((packed)) kv_prefix;

/* this is KV_FORMAT */
struct splice{
	int32_t size;
	char data[0];
};

typedef struct index_entry {
	uint64_t left[1];
	uint64_t pivot;
	uint64_t right[0];
} __attribute__((packed)) index_entry;

/* this is the same as root_node */
typedef struct index_node{
	node_header header;
	index_entry p[IN_LENGTH];
	uint64_t __last_pointer; /* XXX do not use it directly! */
	char __pad[NODE_SIZE - sizeof(struct node_header) - sizeof(uint64_t) - (IN_LENGTH * sizeof(struct index_entry))];
} __attribute__((packed)) index_node;

/* this is the same as leaf_root_node */
#ifdef NEW_LEAF_LAYOUT
typedef struct leaf_entry
{
	uint64_t pointer;
	char prefix[PREFIX_SIZE];
} __attribute__((packed)) leaf_entry;

typedef struct leaf_node
{
	node_header header;
	leaf_entry p[LN_LENGTH];
	char __pad[NODE_SIZE - sizeof(struct node_header) - (LN_LENGTH * LN_ITEM_SIZE)];
} leaf_node;
#else
typedef struct leaf_node{
	struct node_header header;
	uint64_t pointer[LN_LENGTH];
	char prefix[LN_LENGTH][PREFIX_SIZE];
	char __pad[NODE_SIZE - sizeof(struct node_header) - (LN_LENGTH * LN_ITEM_SIZE)];
} __attribute__((packed)) leaf_node;
#endif


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
        block_header * first_kv_log;
        block_header * last_kv_log;
        uint64_t kv_log_size;
	char pad[4072];
}__attribute__((packed)) commit_log_info;

struct superindex_db_entry
{
	char db_name[MAX_DB_NAME_SIZE];
	uint64_t segments[TOTAL_TREES*3];
	node_header * root_r[TOTAL_TREES];
	uint64_t total_keys[TOTAL_TREES];
	/*log info contained in the latest snapshot*/
	block_header * g_first_kv_log;
	block_header * g_last_kv_log;
	uint64_t g_kv_log_size;
	/*kv log, should be equal or ahead of the above*/
	commit_log_info * commit_log;
#ifdef SCAN_REORGANIZATION
	uint64_t leaf_id;
#else
	char pad[8];
#endif

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

typedef struct db_descriptor{
#ifdef SCAN_REORGANIZATION
	char			scan_access_counter[COUNTER_SIZE];
#endif
	node_header *		root_r[TOTAL_TREES];
	node_header *		root_w[TOTAL_TREES];
	char			db_name[MAX_DB_NAME_SIZE];
	uint64_t		segments[TOTAL_TREES*3];
	int64_t			total_keys[TOTAL_TREES];
	pthread_t		spiller[NUM_OF_SPILL_THREADS_PER_DB];
	pthread_mutex_t		rcu_root;
	pthread_mutex_t         rcu_root_lv1;
	pthread_mutex_t         spill_trigger;
#ifdef LOG_WITH_MUTEX
	pthread_mutex_t		lock_log;
#elif SPINLOCK
	pthread_spinlock_t	lock_log;
#else
	lock_queue_t	        lock_log;
#endif
	//mcs_lock lock_log;
	volatile uint64_t	rcu_root_v1;
	volatile uint64_t	rcu_root_v2;
	volatile uint64_t	spill_v1;
	volatile uint64_t	spill_v2;
	lock_table*		multiwrite_level_0[MAX_HEIGHT];
	lock_table*		multiwrite_level_1[MAX_HEIGHT];
	int64_t			count_writers_level_0;
	int64_t			count_writers_level_1;
	int64_t			count_active_spillers;
	char			tree_status[TOTAL_TREES];
	uint64_t		zero_level_memory_size;
	volatile uint64_t       atomic_spill;
	block_header *		g_first_kv_log;
	block_header *		g_last_kv_log;
	uint64_t		g_kv_log_size;
	/*used only for backup db, marks the first last and log size up to which it has built and persist index*/
	block_header *		g_first_backup_kv_log;
	block_header *		g_last_backup_kv_log;
	uint64_t		g_backup_kv_log_size;
	commit_log_info *	commit_log;
	/*segment mappings kept only by replica*/
	//clht_t * backup_segment_table;
	map_entry *		backup_segment_table;	//free this also
#ifdef SCAN_REORGANIZATION
	uint64_t		leaf_id;
#endif
	//uint64_t spilled_keys;
	int32_t			reference_count;
	int32_t			group_id;
	int32_t			group_index;
	volatile int32_t	active_tree;	/*in which tree of the zero level the inserts take place(0,3)*/
	char			dirty;
	char			db_mode;	/*primary or back_up db, instructed from zookeeper*/
        void *(*createEmptyNode) (allocator_descriptor * allocator_desc, db_handle *handle, nodeType_t type, char allocation_code);	/*This will not work as intended when used with more than one allocators. */
} __attribute__((packed)) __attribute__ ((aligned)) db_descriptor;

/**
 * rev1.0   22/07/2014 11:13
  * rev1.1   13/01/2015 14:31
  * Handle for client is kept as soft state
 **/
struct db_handle{
	volume_descriptor *volume_desc;
	db_descriptor *db_desc;
};



typedef struct insertKV_request {
	allocator_descriptor	allocator_desc;
	db_handle *		handle;
	void *			key_value_buf;
	void *			log_address;	/*used from RDMA server*/
	int			level_id;
	int			gc_request;
	int			insert_mode;	/*used either by RDMA server or recovery*/
	char			key_format;
} insertKV_request;

typedef struct rotate_data{
	node_header*	left;
        node_header*	right;
	void*		pivot;
	int		pos_left;
	int		pos_right;
}rotate_data;

typedef struct ancestors{
	rotate_data	neighbors[MAX_HEIGHT];
	node_header*	parent[MAX_HEIGHT];
	int8_t		node_has_key[MAX_HEIGHT];
	int		size;
}ancestors;

typedef struct delete_request{
	allocator_descriptor	allocator_desc;
	db_handle *		handle;
	ancestors*		ancs;
	index_node *		parent;
	leaf_node *		self;
	uint64_t		offset;	/*offset in my parent*/
	int			level_id;
	void *			key_buf;
	char			key_format;
}delete_request;

typedef struct delete_reply{
	node_header *	new_self;	/*in case of COW*/
	node_header *	new_left_brother;	/*in case of COW*/
	node_header *	new_right_brother;	/*in case of COW*/
	void *		key;
	int		status;
}delete_reply;


typedef struct split_request
{
	allocator_descriptor allocator_desc;
	db_handle *handle;

	union {
		node_header *node;
		index_node *inode;
		leaf_node *lnode;
	};
	char insert_mode;
} split_request;


typedef struct split_reply
{
	union {
		node_header *left_child;
		index_node *left_ichild;
		leaf_node *left_lchild;
	};

	union {
		node_header *right_child;
		index_node *right_ichild;
		leaf_node *right_lchild;
	};

	void *middle_key_buf;
} split_reply;

typedef struct split_data{
	node_header* father;
	node_header* son;
}split_data;

typedef struct spill_request{

	db_handle *handle;
	node_header * src_root;
	int32_t src_tree_id;
	int32_t dst_tree_id;
	void * start_key;
	void * end_key;
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
uint8_t _insert_key_value(db_handle *db, void *key_value_buf,int INSERT_FLAGS);
uint8_t update_key_value_pointer(db_handle * handle, void *key, void * value, uint32_t key_size, uint32_t value_size);
uint8_t _update_key_value_pointer(db_handle *db, void *key_value_buf,int INSERT_FLAGS);
uint8_t insert_write_batch(db_handle * handle, mutation_batch * ops);
void * append_key_value_to_log(db_handle *handle, void *key_value, char KEY_VALUE_FORMAT);
void * gc_log_entries(void* v_desc);

/*replica staff*/
int apply_proposal(db_handle *handle, void *kv_proposal, char KEY_VALUE_FORMAT, void *master_log_segment);
void init_backup_db_segment_table(db_handle *);
void register_thread(db_handle *, int);
void apply_spill_buffer(db_handle *, void *);
void init_remote_spill(db_handle *);

void complete_remote_spill(db_handle *);
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
int8_t delete_key(db_handle *handle, void *key, uint32_t size);

int64_t _tucana_key_cmp(void *index_key_buf, void *query_key_buf, char index_key_format, char query_key_format);
int prefix_compare(char *l, char *r, size_t unused);

void free_buffered(void *_handle, void *address, uint32_t num_bytes, int height);

void parse_deleted_keys(db_descriptor *db_desc);

/*functions used from other parts except btree/btree.c*/
uint8_t _writers_join_as_readers(insertKV_request * req);
uint8_t _concurrent_insert(insertKV_request * req);
void *__findKey(db_handle * handle, void *key_buf, char dirty); // dirty 0
void *_index_node_binary_search(index_node *node, void * key_buf, char query_key_format);

void free_logical_node(allocator_descriptor * allocator_desc, node_header * node_index);

int insertKVAtLeaf(insertKV_request *req,  node_header * leaf, char allocation_code);

node_header * findLeafNode(node_header * root, void *key_buf);
void print_node(node_header * node);
void print_key(const char *, void *);
/*Gxanth lock_table stuff*/
void _init_locktable(db_descriptor* database);
void _destroy_locktable(db_descriptor* database);
lock_table * _find_position(lock_table ** table,node_header* node,db_descriptor* db);
void _unlock_upper_levels(lock_table * node[],unsigned size,unsigned release);
void init_index(db_handle* handle);


/*bayern's optimization solution*/
#define PTHREAD_LOCKS

#define SPINLOCK_INIT(L,attr) pthread_spin_init(L,attr)
#define SPIN_LOCK(L) pthread_spin_lock(L)
#define SPIN_UNLOCK(L) pthread_spin_unlock(L)

#define MUTEX_INIT(L,attr) pthread_mutex_init(L,attr)
#define MUTEX_LOCK(L) pthread_mutex_lock(L)
#define MUTEX_TRYLOCK(L) pthread_mutex_trylock(L)
#define MUTEX_UNLOCK(L) pthread_mutex_unlock(L)

#define RWLOCK_INIT(L,attr) pthread_rwlock_init(L,attr)
#define RWLOCK_WRLOCK(L) pthread_rwlock_wrlock(L)
#define RWLOCK_RDLOCK(L) pthread_rwlock_rdlock(L)
#define RWLOCK_UNLOCK(L) pthread_rwlock_unlock(L)

//MACROS
#define MIN(x,y) ((x > y)?(y):(x))
#define KEY_SIZE(x) (*(uint32_t *)x)
#define KV_MAX_SIZE (4096 + 8)
#define ABSOLUTE_ADDRESS(X) (X-MAPPED)
#define REAL_ADDRESS(X) (MAPPED+X)
#define VALUE_SIZE_OFFSET(K) (sizeof(uint32_t)+K)

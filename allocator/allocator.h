#pragma once

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/fs.h>


#include "list.h"
#include "../btree/conf.h"
typedef struct db_handle db_handle;
#include "../btree/btree.h"

#define off64_t unsigned long long
#define FREE_BLOCK 124
#define DELETE_KEY 100

#define VOLUME_IS_OPEN 0x00
#define VOLUME_IS_CLOSING 0x01
#define VOLUME_IS_CLOSED 0x02

#define ALL_DBS 0x01
#define UNIQUE_DB 0x02
#define UNIQUE_DB_ALREADY_LOCKED 0x03

/**
	* Type of allocations.
	* Most significant bit 1 --> allocation for internal tree
	* Most signinificant bit 0 --> allocation for outer tree
	* Rest of bits(common for the two categories above denote the purpose of allocation
**/

#define COW_FOR_LEAF 0x00
#define COW_FOR_INDEX 0x01
#define KEY_LOG_EXPANSION 0x03
#define KV_LOG_EXPANSION 0x04
#define KEY_LOG_SPLIT 0x05
#define INDEX_SPLIT 0x06
#define LEAF_SPLIT 0x07
#define NOT_IMPLEMENTED_YET 0x08
#define NEW_ROOT 0x0A
#define NEW_SUPERINDEX 0x0B
#define GROUP_COW 0x0E
#define NEW_GROUP 0x0F
#define NEW_COMMIT_LOG_INFO 0x1A
#define NEW_LEVEL_0_TREE 0x10   /* used for level-0 tree allocations */
#define NEW_LEVEL_1_TREE 0x20   /* used for level-1 tree allocations */
#define EXTEND_BUFFER 0x0D /* same as above */
#define REORGANIZATION 0x02
#define DELETE_LOG_EXPANSION 0xA3
#define SUPERINDEX_SIZE 4096

#define SNAP_INTERRUPT_ENABLE 0x0A
#define SNAP_INTERRUPT_DISABLE 0x0B


#define PRIMARY_DB 0x05
#define BACKUP_DB_NO_PENDING_SPILL 0x06
#define BACKUP_DB_PENDING_SPILL 0x07
#define DB_IS_CLOSING 0x08

extern LIST * mappedVolumes;

/*the global mountpoint of a Tucana volume*/
extern uint64_t MAPPED;
extern int32_t FD;

typedef struct superindex_db_entry superindex_db_entry;

typedef struct superindex_db_group{
	uint64_t epoch;
	uint64_t future_extensions[63];
	superindex_db_entry  db_entries[GROUP_SIZE];
} superindex_db_group;

typedef struct superindex{
	uint64_t epoch;/*latest synced epoch of the superblock*/
	/*head and tail of the free log, keeps acounting of the free operations*/
	uint64_t free_log_position;
	uint64_t free_log_last_free;
	uint64_t segments[3];/*all allocations even for system should be aligned in BUFFER_SEGMENT_SIZE*/
	superindex_db_group * db_group_index[NUM_OF_DB_GROUPS];/*relative addresses are stored here*/
} superindex;


/*volume superblock*/
typedef struct superblock
{
  superindex * super_index;/*address of the superindex. superindex can be anywhere. It is crucial to be written atomic*/
  /*accounting information */
  int64_t bitmap_size_in_blocks;
  int64_t dev_size_in_blocks;
  int64_t dev_addressed_in_blocks;
  int64_t unmapped_blocks;
	char pad[4056];
}superblock;

struct volume_descriptor{
	superindex * soft_superindex; /*dirty version on the device of the volume's db catalogue*/
	superindex * dev_superindex; /*location in the volume where superindex is */
	pthread_t log_cleaner; /* handle for the log cleaner thread. 1 cleaner per volume */
	pthread_t gc_log_cleaner; /* handle for the garbage collection thread. 1 gc thread per region */
	pthread_cond_t  cond; /* conditional wait, used for cleaner*/
	pthread_cond_t  gc_cond; /* conditional wait, used for garbage collection thread*/
	pthread_mutex_t mutex;/* mutex, used for cleaner */
	pthread_mutex_t gc_mutex;/* mutex, used for garbage collection thread */
	pthread_mutex_t FREE_LOG_LOCK; /*lock used for protecting adding entries to the free log of the allocator*/
	pthread_mutex_t allocator_lock;  /* lock used for threads allocating space in the same volume */
	pthread_mutex_t lock_log;  /* lock used for threads allocating space in the same volume */
	uint64_t last_snapshot;/* timestamp of when last snapshot took place*/
	uint64_t last_commit;
	uint64_t last_sync;/*latest sync timestamp*/
	char * volume_id; /* name of the volume's id, dynamically allocated */
	char * volume_name; /*name of the volume without the id*/
	void * start_addr;/*starting addr of the specific Eugenea partition*/
	uint64_t offset;
	uint64_t size; /* size of volume in bytes */
	void * bitmap_start; /* address of where volume's bitmap starts*/
	void * bitmap_end; /* address of where volume's bitmap ends */
	/*
	* @allocator_state
	* Contains 2 bits per metadata block pair.
	* 00 -> read left/write left
	* 01 read left/write right
	* 10 read right/write left
	* 11 read right/write right
	*/
	unsigned char *allocator_state;
	unsigned char * sync_signal;/* used for efficient snapshot*/
	superblock * volume_superblock;/*address of volume's superblock*/
	LIST * open_databases;
	/*<log_size for free ops start and end>*/
	uint64_t log_size;
	uint64_t start;
	uint64_t end;
	/*</log_size for free ops start and end>*/
	void * latest_addr;/* location, where the last allocation took place */
	uint32_t full; /* value is set to 2 after a non-successfull allocation operation for a given size.*/
	int64_t max_suffix;/*After a non successfull allocation op, this value is set to max_suffix found.
                      This is used for indicating to future allocation operations if they should search
                      a given bitmap-zone or not.*/
	uint16_t * segment_utilization_vector;
	uint64_t segment_ulitization_vector_size;
	/*<stats counters>*/
	uint64_t collisions;
	uint64_t hits;
	uint64_t free_ops;
	/*</stats counters>*/
	int32_t reference_count;
	int32_t allocator_size;
	int32_t fd;/* volume file descriptor */
	int32_t id_pilar;/*volume id */
	volatile char state;/*used for signaling log cleaner when volume is closing*/
	volatile char snap_preemption;
};


typedef struct key_deletion_request
{
	uint64_t epoch;
	void * deleted_kv_addr;
} key_deletion_request;

typedef struct recovery_request{
	volume_descriptor * volume_desc;
	db_descriptor * db_desc;
}recovery_request;
void recovery_worker(void *);


/*
 * @dev_name The device name
 * @start The beginning offset in bytes
 * @size The size of the device in bytes
 * @typeOfVolume Unused
 *
 * @return >= 0 in case of success. < 0 otherwise.
 */
int32_t volume_init(char * dev_name, int64_t start, int64_t size, int typeOfVolume);

void destoy_db_list_node(NODE * node);
void destroy_volume_node(NODE *node);

void allocator_init(volume_descriptor * volume_desc);
void mark_block(volume_descriptor * , void *, uint32_t, char, uint64_t *);

void set_priority(uint64_t pageno, char allocation_code, uint64_t num_bytes);
void *allocate(void * _volume_desc, uint64_t num_bytes, int extensions, char allocation_code);
void* allocate_segment(void * _handle, uint64_t num_bytes, int level_id, char allocation_code);

void free_block(void * _volume_desc, void *block_address, uint32_t length, int height);

void cow_nodes_related_toroot(db_descriptor* db_desc,node_header * node);

void snapshot(volume_descriptor * volume_desc);
void commit_kv_log(volume_descriptor * volume_desc, db_descriptor * db_desc, int which_dbs);
uint64_t get_timestamp();
/*function for spinning located in spin_loop.c compiled with O1 to prevent gcc
 * from optimizing it*/
void spin_loop(int64_t * counter, uint64_t threashold);

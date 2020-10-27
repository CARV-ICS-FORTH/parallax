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

#include "../../utilities/list.h"
#include "../../utilities/spin_loop.h"
#include "../btree/conf.h"

#define off64_t unsigned long long
#define FREE_BLOCK 124
#define DELETE_KEY 100

typedef enum volume_state { VOLUME_IS_OPEN = 0x00, VOLUME_IS_CLOSING = 0x01, VOLUME_IS_CLOSED = 0x02 } volume_state;

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
#define NEW_LEVEL_0_TREE 0x10 /* used for level-0 tree allocations */
#define NEW_LEVEL_1_TREE 0x20 /* used for level-1 tree allocations */
#define NEW_REPLICA_FOREST_TREE 0x30 /* used for level-1 tree allocations */
#define SPACE_FOR_FOREST_TREE 0x30 /* used for level-1 tree allocations */
#define EXTEND_BUFFER 0x0D /* same as above */
#define REORGANIZATION 0x02
#define DELETE_LOG_EXPANSION 0xA3

#define SNAP_INTERRUPT_ENABLE 0x0A
#define SNAP_INTERRUPT_DISABLE 0x0B

typedef enum db_status { DB_OPEN, DB_IS_CLOSING } db_status;

extern LIST *mappedVolumes;

/*the global mountpoint of a volume*/
extern uint64_t MAPPED;
extern int32_t FD;

typedef struct pr_db_entry {
	char db_name[MAX_DB_NAME_SIZE];
	uint64_t root_r[TOTAL_TREES];
	uint64_t first_segment[TOTAL_TREES];
	uint64_t last_segment[TOTAL_TREES];
	uint64_t offset[TOTAL_TREES];
	//expressed in keys per level per tree
	uint64_t level_size[TOTAL_TREES];

	/*commit log is in a different location on the device for the following reason:*
	 * In Kreon for persistence we have two persistence operations commit_log and snapshot()
	 * Commit log only commits the log and it is faster than snapshot. It actual trades performance vs recovery_time.
	 * This is because db should replay a part of its tail log to add missing index.
	 * Snapshot commits both index and log (it actually calls commit_log) and is slower but provides instant recovery.
	 * With the separation of these two techiques we are able to issue snapshot less frequent (order of minutes) without losing data
	 * */
	uint64_t commit_log;
	/*
	 * info to locate after a recovery which tail part
	 * of the log is missing from the index
	 */
	uint64_t L0_start_log_offset;
	uint64_t L0_end_log_offset;
	uint32_t valid;
	//forest *replica_forest;
	char pad[36];
} pr_db_entry; //768 bytes or 12 cache lines

typedef struct pr_db_group {
	uint64_t epoch;

	pr_db_entry db_entries[GROUP_SIZE];

	char pad[4096 - ((GROUP_SIZE * sizeof(pr_db_entry)) + sizeof(uint64_t))];
} pr_db_group;

typedef struct pr_system_catalogue {
	/*latest synced epoch of the superblock*/
	uint64_t epoch;
	/*head and tail of the free log, keeps acounting of the free operations*/
	uint64_t free_log_position;
	uint64_t free_log_last_free;
	uint64_t first_system_segment;
	uint64_t last_system_segment;
	uint64_t offset;
	pr_db_group *db_group_index[NUM_OF_DB_GROUPS]; /*relative addresses are stored here*/
} pr_system_catalogue;

/*volume superblock*/
typedef struct superblock {
	pr_system_catalogue *system_catalogue;
	/*accounting information */
	int64_t bitmap_size_in_blocks;
	int64_t dev_size_in_blocks;
	int64_t dev_addressed_in_blocks;
	int64_t unmapped_blocks;
	char pad[4056];
} superblock;

typedef struct volume_descriptor {
	/*dirty version on the device of the volume's db catalogue*/
	pr_system_catalogue *mem_catalogue;
	/*location in the volume where superindex is */
	pr_system_catalogue *dev_catalogue;
	pthread_t log_cleaner; /* handle for the log cleaner thread. 1 cleaner per volume */
	pthread_cond_t cond; /* conditional wait, used for cleaner*/
	pthread_mutex_t mutex; /* mutex, used for cleaner */
	pthread_mutex_t gc_mutex; /* mutex, used for garbage collection thread */
	pthread_cond_t gc_cond; /* conditional wait, used for garbage collection thread*/

	pthread_mutex_t FREE_LOG_LOCK; /*lock used for protecting adding entries to the free log of the allocator*/
	pthread_mutex_t allocator_lock; /* lock used for threads allocating space in the same volume */
	uint64_t last_snapshot; /* timestamp of when last snapshot took place*/
	uint64_t last_commit;
	uint64_t last_sync; /*latest sync timestamp*/
	char *volume_id; /* name of the volume's id, dynamically allocated */
	char *volume_name; /*name of the volume without the id*/
	void *start_addr; /*starting addr of the specific Eugenea partition*/
	uint64_t offset;
	uint64_t size; /* size of volume in bytes */
	void *bitmap_start; /* address of where volume's bitmap starts*/
	void *bitmap_end; /* address of where volume's bitmap ends */
	/*
	* @allocator_state
	* Contains 2 bits per metadata block pair.
	* 00 -> read left/write left
	* 01 read left/write right
	* 10 read right/write left
	* 11 read right/write right
	*/
	unsigned char *allocator_state;
	unsigned char *sync_signal; /* used for efficient snapshot*/
	superblock *volume_superblock; /*address of volume's superblock*/
	LIST *open_databases;
	/*<log_size for free ops start and end>*/
	uint64_t log_size;
	uint64_t start;
	uint64_t end;
	/*</log_size for free ops start and end>*/
	void *latest_addr; /* location, where the last allocation took place */
	uint32_t full; /* value is set to 2 after a non-successfull allocation operation for a given size.*/
	int64_t max_suffix; /*After a non successfull allocation op, this value is set to max_suffix found.
			      This is used for indicating to future allocation operations if they should search
			      a given bitmap-zone or not.*/
	uint16_t *segment_utilization_vector;
	uint64_t segment_utilization_vector_size;
	/*<stats counters>*/
	uint64_t collisions;
	uint64_t hits;
	uint64_t free_ops;
	/*</stats counters>*/
	int32_t reference_count;
	int32_t allocator_size;
	int32_t fd; /* volume file descriptor */
	volatile char state; /*used for signaling log cleaner when volume is closing*/
	volatile char snap_preemption;
} volume_descriptor;

typedef struct key_deletion_request {
	uint64_t epoch;
	void *deleted_kv_addr;
} key_deletion_request;

/*
 * @dev_name The device name
 * @start The beginning offset in bytes
 * @size The size of the device in bytes
 * @typeOfVolume Unused
 *
 * @return >= 0 in case of success. < 0 otherwise.
 */
int32_t volume_init(char *dev_name, int64_t start, int64_t size, int typeOfVolume);

void destoy_db_list_node(NODE *node);
void destroy_volume_node(NODE *node);

void allocator_init(volume_descriptor *volume_desc);
void mark_block(volume_descriptor *, void *, uint32_t, char, uint64_t *);

void set_priority(uint64_t pageno, char allocation_code, uint64_t num_bytes);
void *allocate(void *_volume_desc, uint64_t num_bytes, int extensions, char allocation_code);
void *allocate_segment(void *_handle, uint64_t num_bytes, int level_id, char allocation_code);

void free_block(void *_volume_desc, void *block_address, uint32_t length, int height);

uint64_t get_timestamp(void);

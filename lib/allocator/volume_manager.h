// Copyright [2020] [FORTH-ICS]
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
#include <stdint.h>
#include <pthread.h>
#include "device_structures.h"
#include "../btree/conf.h"
#define MAGIC_NUMBER 2036000000
/*size in 4KB blocks of the log used for marking the free ops*/
#define FREE_LOG_SIZE_IN_BLOCKS 512000

typedef enum volume_state { VOLUME_IS_OPEN = 0x00, VOLUME_IS_CLOSING = 0x01, VOLUME_IS_CLOSED = 0x02 } volume_state;

/**
        * Type of allocations.
        * Most significant bit 1 --> allocation for internal tree
        * Most signinificant bit 0 --> allocation for outer tree
        * Rest of bits(common for the two categories above denote the purpose of
*allocation
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
#define EXTEND_BUFFER 0x0D /* same as above */
#define REORGANIZATION 0x02
#define DELETE_LOG_EXPANSION 0xA3

#define SNAP_INTERRUPT_ENABLE 0x0A
#define SNAP_INTERRUPT_DISABLE 0x0B

/*the global mountpoint of a volume*/
extern uint64_t MAPPED;
extern int FD;

/*<new_persistent_design>*/
#if 0
enum pr_region_operation { ALLOCATE_SEGMENT, FREE_SEGMENT };

struct pr_region_operation_entry {
	uint32_t size;
	enum pr_region_operation op;
} __attribute__((packed, aligned(8)));

struct pr_region_allocation_log {
	uint32_t start;
	uint32_t end;
	uint32_t size;
	uint32_t extensions;
} __attribute__((packed, aligned(16)));

struct mem_region_superblock {
	char region_name[MAX_DB_NAME_SIZE];
	struct segment_header *first_segment[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	struct segment_header *last_segment[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint64_t offset[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint64_t level_size[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	struct pr_region_allocation_log allocation_log;
	pthread_mutex_t superblock_lock;
	struct bt_log_descriptor big_log;
	struct bt_log_descriptor medium_log;
	struct bt_log_descriptor small_log;
	uint64_t lsn;
	uint32_t region_name_size;
	uint32_t id;//in the array
	uint32_t reference_count;
	uint32_t valid;
}__attribute__((packed, aligned(4096)));

struct pr_region_superblock {
	char region_name[MAX_DB_NAME_SIZE];
	uint64_t first_segment[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint64_t last_segment[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint64_t offset[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint64_t level_size[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	struct pr_region_allocation_log allocation_log;
	uint64_t big_log_head_offt;
	uint64_t big_log_tail_offt;
	uint64_t big_log_size;
	uint64_t medium_log_head_offt;
	uint64_t medium_log_tail_offt;
	uint64_t medium_log_size;
	uint64_t small_log_head_offt;
	uint64_t small_log_tail_offt;
	uint64_t small_log_size;
	uint64_t lsn;
	uint32_t region_name_size;
	uint32_t id;//in the array
	uint32_t valid;
}__attribute__((packed, aligned(4096)));

struct mem_superblock_array {
	uint32_t size;
	struct mem_region_superblock region[];
};

struct pr_superblock_array {
	uint32_t size;
	struct pr_region_superblock region[];
};

struct pr_region_bitmap {
	uint32_t size;
	char persistent_bitmap[];
};
#endif
/*</new_persistent_design>*/

#define WORDS_PER_BITMAP_BUDDY ((DEVICE_BLOCK_SIZE / sizeof(uint64_t)) - 1)
struct bitmap_buddy {
	uint64_t epoch;
	uint64_t word[WORDS_PER_BITMAP_BUDDY];
};

struct bitmap_buddy_pair {
	struct bitmap_buddy buddy[2];
};

struct bitmap_position {
	int buddy_pair;
	int word_id;
};

#define BITMAP_BUDDY_PAIRS_PER_CELL 4
struct bitmap_buddies_cell {
	uint8_t b0 : 2;
	uint8_t b1 : 2;
	uint8_t b2 : 2;
	uint8_t b3 : 2;
};

struct bitmap_buddies_state {
	uint32_t size;
	struct bitmap_buddies_cell buddy[];
};

typedef struct volume_descriptor {
	/*<new_persistent_design>*/
	struct mem_superblock_array *mem_regions;
	struct pr_superblock_array *pr_regions;
	pthread_mutex_t region_array_lock;
	/*</new_persistent_design>*/

	// dirty version on the device of the volume's db catalogue
	struct pr_system_catalogue *mem_catalogue;
	// location in the volume where superindex is
	struct pr_system_catalogue *dev_catalogue;
	pthread_t log_cleaner; /* handle for the log cleaner thread. 1 cleaner per
                            volume */
	pthread_cond_t cond; /* conditional wait, used for cleaner*/
	pthread_mutex_t mutex; /* mutex, used for cleaner */
	pthread_mutex_t gc_mutex; /* mutex, used for garbage collection thread */
	pthread_cond_t gc_cond; /* conditional wait, used for garbage collection
                             thread*/

	pthread_mutex_t free_log_lock; /*lock used for protecting adding entries to
                                    the free log of the allocator*/
	pthread_mutex_t bitmap_lock; /* lock used for threads allocating space in the same volume */
	uint64_t last_snapshot; /* timestamp of when last snapshot took place*/
	uint64_t last_commit;
	uint64_t last_sync; /*latest sync timestamp*/
	char *volume_id; /* name of the volume's id, dynamically allocated */
	char *volume_name; /*name of the volume without the id*/
	void *start_addr;
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
	struct bitmap_buddies_state *buddies_vector;

	struct superblock *volume_superblock; /*address of volume's superblock*/
	struct klist *open_databases;

	/*free log start*/
	uint64_t log_size;
	uint64_t start;
	uint64_t end;
	/*free log end*/
	/*Location of last allocation*/
	struct bitmap_position b_pos;
	/* value is set to 2 after a non-successfull allocation operation for a given
   * size.*/
	uint32_t full;
	/*After a non successfull allocation op, this value is set to max_suffix
   found.
   This is used for indicating to future allocation operations if they should
   search
   a given bitmap-zone or not.*/
	uint64_t max_suffix;
	// uint16_t *segment_utilization_vector;
	// uint64_t segment_utilization_vector_size;
	/*<stats counters>*/
	uint64_t collisions;
	uint64_t hits;
	uint64_t free_ops;
	/*</stats counters>*/
	int32_t reference_count;
	int32_t allocator_size;
	volatile char state; /*used for signaling log cleaner when volume is closing*/
	volatile char snap_preemption;
	char force_snapshot;
} volume_descriptor;

/*
 * @dev_name The device name
 * @start The beginning offset in bytes
 * @size The size of the device in bytes
 * @typeOfVolume Unused
 *
 * @return >= 0 in case of success. < 0 otherwise.
 */

struct volume_descriptor *get_volume_desc(char *volume_name, uint64_t start_offt, char create);
struct db_coordinates {
	int found;
	int new_db;
	int out_of_space;
	int group_id;
	int index;
};

struct db_coordinates locate_db(struct volume_descriptor *volume_desc, char *db_name, char create_db);

int32_t volume_init(char *dev_name, int64_t start, int64_t size, int typeOfVolume);

void force_snapshot(volume_descriptor *volume_desc);
void snapshot(volume_descriptor *volume_desc);

void allocator_init(volume_descriptor *volume_desc);

void set_priority(uint64_t pageno, char allocation_code, uint64_t num_bytes);
void *allocate(struct volume_descriptor *volume_desc, uint64_t num_bytes);

void free_block(struct volume_descriptor *volume_desc, void *address, uint32_t length);
void bitmap_set_buddies_immutable(struct volume_descriptor *volume_desc);
void bitmap_mark_block_free(struct volume_descriptor *volume_desc, void *addr);

void mark_page(volume_descriptor *volume_desc, void *block_address, char free, uint64_t *bit_idx);

uint64_t get_timestamp(void);

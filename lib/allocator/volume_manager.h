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
#include "../btree/conf.h"
#include "device_structures.h"
#include "mem_structures.h"
#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>

#define BIT_MASK(X) (1 << X)
#define INV_BIT_MASK(X) (~BIT_MASK(X))
#define SET_BIT(X, Y) (*X = *X | BIT_MASK(Y))
#define CLEAR_BIT(X, Y) (*X = *X & INV_BIT_MASK(Y))
#define GET_BIT(X, Y) ((X & (1 << Y)) >> Y)
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

#define INDEX_SPLIT 0x06
#define NEW_ROOT 0x0A

/*the global mountpoint of a volume*/
extern uint64_t MAPPED;
extern int FD;

typedef struct volume_descriptor {
	/*<new_persistent_design>*/
	struct superblock vol_superblock;
	struct pr_superblock_array *pr_regions;
	uint64_t *mem_volume_bitmap;
	int mem_volume_bitmap_size;
	struct mem_bitmap_word curr_word;
	pthread_mutex_t db_array_lock;
	pthread_mutex_t *db_superblock_lock;
	int vol_fd;
	/*</new_persistent_design>*/

	// dirty version on the device of the volume's db catalogue
	struct pr_system_catalogue *mem_catalogue;
	// location in the volume where superindex is
	struct pr_system_catalogue *dev_catalogue;
	pthread_cond_t cond; /* conditional wait, used for cleaner*/
	pthread_mutex_t mutex; /* mutex, used for cleaner */
	pthread_mutex_t gc_mutex; /* mutex, used for garbage collection thread */
	pthread_cond_t gc_cond; /* conditional wait, used for garbage collection
                         thread*/

	pthread_mutex_t free_log_lock; /*lock used for protecting adding entries to
                              the free log of the allocator*/
	pthread_mutex_t bitmap_lock; /* lock used for threads allocating space in the
                                  same volume */
	uint64_t last_commit;
	uint64_t last_sync; /*latest sync timestamp*/
	char *volume_id; /* name of the volume's id, dynamically allocated */
	char *volume_name; /*name of the volume without the id*/
	void *start_addr;
	uint64_t offset;
	uint64_t size; /* size of volume in bytes */
	void *bitmap_start; /* address of where volume's bitmap starts*/
	void *bitmap_end; /* address of where volume's bitmap ends */

	struct superblock *volume_superblock; /*address of volume's superblock, delete it*/
	struct klist *open_databases;

	/* value is set to 2 after a non-successfull allocation operation for a given
   * size.*/
	//	uint32_t full;
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
	// Variable that notifies the volume if a gc has been spawned.
	// We should have one GC thread per volume!
	uint8_t gc_thread_spawned;
	/*used for signaling log cleaner when volume is closing*/
	volatile char state;
	volatile char snap_preemption;
} volume_descriptor;

enum allocation_log_cursor_state {
	CALCULATE_CHUNKS_IN_SEGMENT,
	CALCULATE_CHUNK_ENTRIES,
	GET_NEXT_SEGMENT,
	GET_NEXT_CHUNK,
	GET_NEXT_ENTRY,
	GET_HEAD,
	EXIT
};

struct allocation_log_cursor {
	struct volume_descriptor *volume_desc;
	struct pr_db_superblock *db_superblock;
	struct rul_log_segment *segment;
	uint32_t chunks_in_segment;
	uint32_t curr_chunk_id;
	uint32_t chunk_entries;
	uint32_t curr_entry_in_chunk;
	enum allocation_log_cursor_state state;
	uint8_t valid : 1;
};

struct volume_descriptor *mem_get_volume_desc(char *volume_name);

uint64_t mem_allocate(struct volume_descriptor *volume_desc, uint64_t num_bytes);

void mem_bitmap_mark_block_free(struct volume_descriptor *volume_desc, uint64_t dev_offt);

struct pr_db_superblock *get_db_superblock(struct volume_descriptor *volume_desc, const char *db_name,
					   uint32_t db_name_size, uint8_t allocate, uint8_t *new_db);

struct allocation_log_cursor *init_allocation_log_cursor(struct volume_descriptor *volume_desc,
							 struct pr_db_superblock *db_superblock);

void close_allocation_log_cursor(struct allocation_log_cursor *cursor);

struct rul_log_entry *get_next_allocation_log_entry(struct allocation_log_cursor *cursor);

/**
  * Reads size bytes from the device/file dev_offt into the in memory buffer.
**/
int read_dev_offt_into_buffer(char *buffer, const uint32_t start, const uint32_t size, const off_t dev_offt,
			      const int fd);

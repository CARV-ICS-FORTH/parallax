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

#ifndef DEVICE_STRUCTURES_H
#define DEVICE_STRUCTURES_H
#define ALLOW_RAW_VOLUMES 1
#define MIN_VOLUME_SIZE (8 * 1024 * 1024 * 1024L)
#include "../btree/conf.h"
#include "../btree/lsn.h"
#include <pthread.h>
#include <stdint.h>

/*physics bitch!*/
#define FINE_STRUCTURE_CONSTANT 72973525664
struct pr_db_entry {
	char db_name[MAX_DB_NAME_SIZE];
	/*index staff*/
	uint64_t root_r[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint64_t first_segment[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint64_t last_segment[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint64_t offset[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint64_t level_size[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint64_t big_log_head_offt;
	uint64_t big_log_tail_offt;
	uint64_t big_log_size;
	uint64_t medium_log_head_offt;
	uint64_t medium_log_tail_offt;
	uint64_t medium_log_size;
	uint64_t small_log_head_offt;
	uint64_t small_log_tail_offt;
	uint64_t small_log_size;
	struct lsn lsn;
	uint32_t valid;
}; // 768 bytes or 12 cache lines

/*volume superblock*/
struct superblock {
	/*accounting information*/
	int64_t bitmap_size_in_blocks;
	int64_t dev_size_in_blocks;
	int64_t dev_addressed_in_blocks;
	int64_t unmapped_blocks;
	int64_t magic_number;
	/*<new_persistent_design>*/
	uint64_t volume_size;
	uint32_t max_regions_num;
	uint64_t regions_log_size;
	uint64_t volume_metadata_size;
	uint64_t bitmap_size_in_words;
	uint64_t unmappedSpace;
	uint64_t paddedSpace;
	/*</new_persistent_design>*/
} __attribute__((packed, aligned(4096)));

//<new_persistent_design>
enum pr_region_operation { ALLOCATE_SEGMENT, FREE_SEGMENT };

struct pr_region_operation_entry {
	uint32_t size;
	enum pr_region_operation op;
} __attribute__((packed, aligned(8)));

struct pr_region_allocation_log {
	uint64_t head_dev_offt;
	uint64_t tail_dev_offt;
	uint64_t size;
	uint64_t txn_id;
} __attribute__((packed));

struct pr_db_superblock {
	char db_name[MAX_DB_NAME_SIZE];
	struct pr_region_allocation_log allocation_log;
	uint64_t root_r[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint64_t first_segment[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint64_t last_segment[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint64_t offset[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint64_t level_size[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint64_t bloom_filter_hash[MAX_LEVELS][NUM_TREES_PER_LEVEL];

	uint64_t big_log_head_offt;
	uint64_t big_log_tail_offt;
	uint64_t big_log_size;
	uint64_t medium_log_head_offt;
	uint64_t medium_log_tail_offt;
	uint64_t medium_log_size;
	uint64_t small_log_head_offt;
	uint64_t small_log_tail_offt;
	uint64_t small_log_size;
	uint64_t small_log_start_segment_dev_offt;
	uint64_t small_log_offt_in_start_segment;
	uint64_t big_log_start_segment_dev_offt;
	uint64_t big_log_offt_in_start_segment;
	struct lsn last_lsn;
	uint8_t bloom_filter_valid[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint32_t db_name_size;
	uint32_t id; //in the array
	uint32_t valid;

} __attribute__((packed, aligned(4096)));

struct pr_superblock_array {
	uint32_t size;
	struct pr_db_superblock db[];
};

struct pr_ownership_registry {
	uint32_t size;
	char persistent_bitmap[];
};
#endif // DEVICE_STRUCTURES_H

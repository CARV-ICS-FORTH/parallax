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
#include "../btree/conf.h"

struct pr_db_entry {
	char db_name[MAX_DB_NAME_SIZE];
	// index staff
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
	uint64_t lsn;
	uint32_t valid;
}; // 768 bytes or 12 cache lines

struct pr_db_group {
	uint64_t epoch;
	struct pr_db_entry db_entries[GROUP_SIZE];
} __attribute__((packed, aligned(4096)));

struct pr_system_catalogue {
	/*latest synced epoch of the superblock*/
	uint64_t epoch;
	/*head and tail of the free log, keeps acounting of the free operations*/
	uint64_t free_log_position;
	uint64_t free_log_last_free;
	uint64_t first_system_segment;
	uint64_t last_system_segment;
	uint64_t offset;
	// relative addresses are stored here
	struct pr_db_group *db_group_index[NUM_OF_DB_GROUPS];
} __attribute__((packed, aligned(4096)));

/*volume superblock*/
struct superblock {
	struct pr_system_catalogue *system_catalogue;
	/*accounting information */
	int64_t bitmap_size_in_blocks;
	int64_t dev_size_in_blocks;
	int64_t dev_addressed_in_blocks;
	int64_t unmapped_blocks;
	int64_t magic_number;
} __attribute__((packed, aligned(4096)));

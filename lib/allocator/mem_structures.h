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
#include "log_structures.h"
#include <pthread.h>
#include <stdint.h>

//<new_persistent_design>
#define MEM_WORD_SIZE_IN_BITS 64

struct mem_bitmap_word {
	uint64_t *word_addr;
	uint32_t start_bit;
	uint32_t end_bit;
	int word_id;
};

#if 0
struct mem_region_superblock {
	char region_name[MAX_DB_NAME_SIZE];
	struct segment_header *first_segment[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	struct segment_header *last_segment[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint64_t offset[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	uint64_t level_size[MAX_LEVELS][NUM_TREES_PER_LEVEL];
	struct pr_region_allocation_log allocation_log;
	pthread_mutex_t superblock_lock;
	struct log_descriptor big_log;
	struct log_descriptor medium_log;
	struct log_descriptor small_log;
	uint64_t lsn;
	uint32_t region_name_size;
	uint32_t id; //in the array
	uint32_t reference_count;
	uint32_t valid;
} __attribute__((packed, aligned(4096)));

struct mem_superblock_array {
	uint32_t size;
	struct mem_region_superblock region[];
};
#endif

//</new_persistent_design>

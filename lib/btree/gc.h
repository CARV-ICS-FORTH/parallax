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
#include "conf.h"
#include <stdint.h>
#include <uthash.h>

typedef struct log_segment {
	char data[SEGMENT_SIZE];
} log_segment;

/* The smallest entry in log that can exist  is a key and value of size 1.
 That means  the key + value size = 2 and the sizeof 2 integers = 8 */
#define STACK_SIZE ((SEGMENT_SIZE / 10) + 1)

typedef struct stack {
	void *valid_pairs[STACK_SIZE];
	int size;
} stack;

struct large_log_segment_gc_entry {
	uint64_t segment_dev_offt;
	unsigned garbage_bytes;
	unsigned segment_moved;
	UT_hash_handle hh;
} __attribute__((aligned(128)));

#define GC_SEGMENT_THRESHOLD (10 / 100)
#define SEGMENTS_TORECLAIM 100000
#define LOG_DATA_OFFSET (SEGMENT_SIZE)
void *gc_log_entries(void *hd);
uint8_t is_gc_executed(void);
void disable_gc(void);

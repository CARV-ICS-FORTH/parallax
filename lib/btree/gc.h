#pragma once
#include "btree.h"
#include "conf.h"
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

struct gc_value {
	int group_id;
	int index;
};

struct large_log_segment_gc_entry {
	uint64_t segment_dev_offt;
	unsigned garbage_bytes;
	unsigned segment_moved;
	UT_hash_handle hh;
} __attribute__((aligned(128)));

#define SYSTEMDB "systemdb"
#define GC_SEGMENT_THRESHOLD (10 / 100)
#define SEGMENTS_TORECLAIM 100000
#define LOG_DATA_OFFSET (SEGMENT_SIZE)
void *gc_log_entries(void *db_handle);

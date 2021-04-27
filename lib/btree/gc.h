#pragma once
#include "btree.h"
#include "conf.h"

typedef struct log_segment {
	segment_header metadata;
	char data[SEGMENT_SIZE - sizeof(segment_header)];
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
	int moved;
};
#define SYSTEMDB "systemdb"
#define GC_SEGMENT_THRESHOLD (10 / 100)
#define SEGMENTS_TORECLAIM 100000
#define LOG_DATA_OFFSET (SEGMENT_SIZE - sizeof(segment_header))
void *gc_log_entries(void *db_handle);

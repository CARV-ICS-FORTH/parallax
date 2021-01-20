#pragma once
#include "btree.h"
#include <assert.h>
#include <log.h>

typedef struct log_segment {
	segment_header metadata;
	char data[BUFFER_SEGMENT_SIZE - sizeof(segment_header)];
} log_segment;

/* The smallest entry in log that can exist  is a key and value of size 1.
 That means  the key + value size = 2 and the sizeof 2 integers = 8 */
#define STACK_SIZE ((BUFFER_SEGMENT_SIZE / 10) + 1)

typedef struct stack {
	void *valid_pairs[STACK_SIZE];
	int size;
} stack;

#define LOG_DATA_OFFSET (BUFFER_SEGMENT_SIZE - sizeof(segment_header))
void *gc_log_entries(void *db_handle);

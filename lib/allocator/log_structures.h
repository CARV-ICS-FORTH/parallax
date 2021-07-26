#pragma once
#include <stdint.h>
#include <pthread.h>
#include "../btree/conf.h"
struct log_tail {
	char buf[SEGMENT_SIZE];
	uint32_t bytes_in_chunk[SEGMENT_SIZE / LOG_CHUNK_SIZE];
	uint64_t dev_offt;
	uint64_t start;
	uint64_t end;
	uint32_t pending_readers;
	uint32_t free;
	uint32_t IOs_completed_in_tail;
	int fd;
};

struct log_descriptor {
	pthread_rwlock_t log_tail_buf_lock;
	char pad[8];
	struct log_tail *tail[LOG_TAIL_NUM_BUFS];
	uint64_t head_dev_offt;
	uint64_t tail_dev_offt;
	uint64_t size;
	uint64_t curr_tail_id;
};

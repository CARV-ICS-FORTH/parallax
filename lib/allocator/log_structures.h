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
#include <pthread.h>
#include <stdint.h>

enum log_type { BIG_LOG, MEDIUM_LOG, SMALL_LOG };
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
	enum log_type my_type;
};

// Copyright [2023] [FORTH-ICS]
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
#include "log_structures.h"
#include "../btree/conf.h"
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

struct log_buffer_iterator {
	struct log_descriptor *log_desc;
	uint32_t curr_buf;
	bool is_valid;
};
// cppcheck-suppress unusedFunction
struct log_buffer_iterator *log_buffer_iterator_init(struct log_descriptor *log_desc)
{
	struct log_buffer_iterator *iter = (struct log_buffer_iterator *)calloc(1, sizeof(struct log_buffer_iterator));
	iter->is_valid = true;
	iter->log_desc = log_desc;
	iter->curr_buf = 0;
	return iter;
}

// cppcheck-suppress unusedFunction
bool log_buffer_iterator_next(struct log_buffer_iterator *iter)
{
	assert(iter);
	return ++iter->curr_buf < LOG_TAIL_NUM_BUFS ? true : false;
}

// cppcheck-suppress unusedFunction
bool log_buffer_iterator_is_valid(struct log_buffer_iterator *iter)
{
	assert(iter);
	return iter->curr_buf < LOG_TAIL_NUM_BUFS ? true : false;
}

// cppcheck-suppress unusedFunction
char *log_buffer_iterator_get_buffer(struct log_buffer_iterator *iter)
{
	assert(iter);
	return iter->log_desc->tail[iter->curr_buf]->buf;
}

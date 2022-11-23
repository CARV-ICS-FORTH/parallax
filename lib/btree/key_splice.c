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
#include "key_splice.h"
#include <assert.h>
#include <log.h>
#include <stdlib.h>
#include <string.h>
#define T int32_t
#define T_MAX INT32_MAX
#define KV_SPLICE_MAX_KEY_SIZE 255UL
// This struct defines the key abstraction of the system and it's irrelevant from splice format
struct key_splice {
	T key_size;
	char data[];
} __attribute__((packed));

extern struct key_splice *key_splice_create(char *key, int32_t key_size, char *buffer, int32_t buffer_size,
					    bool *malloced)
{
	*malloced = false;
	if (key_size >= T_MAX) {
		log_debug("Possible overflow key_size is %d max size is %d", key_size, T_MAX);
		return NULL;
	}
	if (buffer_size >= T_MAX) {
		log_debug("Possible overflow buffer_size is %d max size is %d", key_size, T_MAX);
		return NULL;
	}
	struct key_splice *key_splice = (struct key_splice *)buffer;
	uint32_t key_splice_size = sizeof(struct key_splice) + key_size;
	if ((int32_t)key_splice_size > buffer_size) {
		// log_debug("Buffer is not large enough to host a key_splice needs: %lu has: %u",
		// 	  sizeof(struct key_splice) + key_size, buffer_size);
		key_splice = calloc(1UL, sizeof(struct key_splice) + key_size);
		*malloced = true;
	}
	key_splice->key_size = key_size;
	memcpy(key_splice->data, key, key_size);
	return key_splice;
}
struct key_splice *key_splice_create_smallest(char *buffer, int32_t buffer_size, bool *malloced)
{
	char key[8] = { 0 };
	int32_t key_size = 1;
	return key_splice_create(key, key_size, buffer, buffer_size, malloced);
}

inline T key_splice_get_key_size(struct key_splice *key)
{
	return key->key_size;
}

inline char *key_splice_get_key_offset(struct key_splice *key)
{
	return key->data;
}

inline void key_splice_set_key_size(struct key_splice *key, T key_size)
{
	key->key_size = key_size;
}

inline void key_splice_set_key_offset(struct key_splice *key, char *key_buf)
{
	memcpy(key_splice_get_key_offset(key), key_buf, key_splice_get_key_size(key));
}

inline T key_splice_get_metadata_size(void)
{
	return sizeof(struct key_splice);
}

// cppcheck-suppress unusedFunction
uint32_t key_splice_get_max_size(void)
{
	return KV_SPLICE_MAX_KEY_SIZE + sizeof(struct key_splice);
}
#undef T
#undef T_MAX

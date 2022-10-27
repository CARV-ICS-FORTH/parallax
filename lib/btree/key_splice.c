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

extern key_splice_t create_key_splice(char *key, int32_t key_size, char *buffer, int32_t buffer_size, bool *malloced)
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
	key_splice_t key_splice = (key_splice_t)buffer;
	if (sizeof(struct key_splice) + key_size > buffer_size) {
		log_debug("Buffer is not large enough to host a key_splice needs: %lu has: %u",
			  sizeof(struct key_splice) + key_size, buffer_size);
		assert(0);
		key_splice = calloc(1UL, sizeof(struct key_splice) + key_size);
		*malloced = true;
	}
	key_splice->key_size = key_size;
	memcpy(key_splice->data, key, key_size);
	return key_splice;
}
key_splice_t create_smallest_key(char *buffer, int32_t buffer_size, bool *malloced)
{
	char key[8] = { 0 };
	int32_t key_size = 1;
	return create_key_splice(key, key_size, buffer, buffer_size, malloced);
}

inline T get_key_splice_key_size(key_splice_t key)
{
	return key->key_size;
}

inline char *get_key_splice_key_offset(key_splice_t key)
{
	return key->data;
}

inline void set_key_size_of_key_splice(key_splice_t key, T key_size)
{
	key->key_size = key_size;
}

inline void set_key_splice_key_offset(key_splice_t key, char *key_buf)
{
	memcpy(get_key_splice_key_offset(key), key_buf, get_key_splice_key_size(key));
}

inline T get_key_splice_metadata_size(void)
{
	return sizeof(struct key_splice);
}

uint32_t get_key_splice_max_size(void)
{
	return KV_SPLICE_MAX_KEY_SIZE + sizeof(struct key_splice);
}
#undef T
#undef T_MAX

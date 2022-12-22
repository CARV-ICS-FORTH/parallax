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
#include "kv_pairs.h"
#include "key_splice.h"
#include "parallax/structures.h"
#include <assert.h>
#include <log.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DELETE_MARKER_ID (INT32_MAX)

inline int32_t get_key_size(struct kv_splice *kv_pair)
{
	return kv_pair->key_size;
}

inline int32_t get_value_size(struct kv_splice *kv_pair)
{
	return is_tombstone_kv_pair(kv_pair) ? 0 : kv_pair->value_size;
}

// cppcheck-suppress unusedFunction
inline int32_t get_value_size_with_metadata(struct kv_splice *kv_pair)
{
	return sizeof(kv_pair->value_size) + get_value_size(kv_pair);
}

inline int32_t get_kv_metadata_size(void)
{
	int32_t kv_pair_metadata_size = sizeof(struct kv_splice);
	return kv_pair_metadata_size;
}

inline int32_t get_kv_size(struct kv_splice *kv_pair)
{
	return get_key_size(kv_pair) + get_value_size(kv_pair) + get_kv_metadata_size();
}

inline void set_key_size(struct kv_splice *kv_pair, int32_t key_size)
{
	kv_pair->key_size = key_size;
}

inline void set_key(struct kv_splice *kv_pair, char *key, int32_t key_size)
{
	kv_pair->key_size = key_size;
	memcpy(get_key_offset_in_kv(kv_pair), key, key_size);
}

inline void set_value_size(struct kv_splice *kv_pair, int32_t value_size)
{
	kv_pair->value_size = value_size;
}

inline void set_value(struct kv_splice *kv_pair, char *value, int32_t value_size)
{
	if (is_tombstone_kv_pair(kv_pair))
		return;
	kv_pair->value_size = value_size;
	memcpy(get_value_offset_in_kv(kv_pair, kv_pair->key_size), value, value_size);
}

inline char *get_key_offset_in_kv(struct kv_splice *kv_pair)
{
	return kv_pair->data;
}

inline char *get_value_offset_in_kv(struct kv_splice *kv_pair, int32_t key_size)
{
	return is_tombstone_kv_pair(kv_pair) ? NULL : kv_pair->data + key_size;
}

inline int32_t get_kv_seperated_key_size(struct kv_seperation_splice *kv_pair)
{
	return get_key_size((struct kv_splice *)kv_pair->dev_offt);
}

inline int32_t get_kv_seperated_value_size(struct kv_seperation_splice *kv_pair)
{
	return get_value_size((struct kv_splice *)kv_pair->dev_offt);
}

inline int32_t get_kv_seperated_kv_size(struct kv_seperation_splice *kv_pair)
{
	return get_kv_size((struct kv_splice *)kv_pair->dev_offt);
}

inline int32_t get_kv_seperated_splice_size(void)
{
	return sizeof(struct kv_seperation_splice);
}

inline char *get_kv_seperated_prefix(struct kv_seperation_splice *kv_pair)
{
	return NULL != kv_pair ? kv_pair->prefix : NULL;
}

inline uint64_t get_kv_seperated_device_offt(struct kv_seperation_splice *kv_pair)
{
	return NULL != kv_pair ? kv_pair->dev_offt : UINT64_MAX;
}

inline void set_kv_seperated_device_offt(struct kv_seperation_splice *kv_pair, uint64_t dev_offt)
{
	NULL != kv_pair ? kv_pair->dev_offt = dev_offt : dev_offt;
}

inline int32_t get_kv_seperated_prefix_size(void)
{
	return PREFIX_SIZE;
}

inline bool is_tombstone_kv_pair(struct kv_splice *kv_pair)
{
	return DELETE_MARKER_ID == kv_pair->value_size;
}

inline void set_non_tombstone(struct kv_splice *kv_pair)
{
	kv_pair->value_size = 0;
}

inline void set_tombstone(struct kv_splice *kv_pair)
{
	kv_pair->value_size = DELETE_MARKER_ID;
}

void serialize_key(char *buf, void *key, uint32_t key_size)
{
	struct kv_splice *kv_splice = (struct kv_splice *)buf;
	set_key_size(kv_splice, key_size);
	set_value_size(kv_splice, INT32_MAX);
	set_key(kv_splice, (char *)key, key_size);
}

void serialize_kv_splice_to_key_splice(char *buf, struct kv_splice *kv_pair)
{
	struct key_splice *key_splice = (struct key_splice *)buf;
	int32_t key_size = get_key_size(kv_pair);
	char *key = get_key_offset_in_kv(kv_pair);
	key_splice_set_key_size(key_splice, key_size);
	memcpy(key_splice_get_key_offset(key_splice), key, key_size);
}

int32_t get_min_possible_kv_size(void)
{
	return sizeof(int32_t) + 1;
}
//gesalous

char *kv_sep2_get_key(struct kv_seperation_splice2 *kv_sep2)
{
	return kv_sep2->key;
}

int32_t kv_sep2_get_key_size(struct kv_seperation_splice2 *kv_sep2)
{
	return kv_sep2->key_size;
}

uint64_t kv_sep2_get_value_offt(struct kv_seperation_splice2 *kv_sep2)
{
	return kv_sep2->value_offt;
}

int32_t kv_sep2_get_total_size(struct kv_seperation_splice2 *kv_sep2)
{
	return sizeof(kv_sep2->key_size) + kv_sep2->key_size + sizeof(kv_sep2->value_offt);
}

bool kv_sep2_serialize(struct kv_seperation_splice2 *splice, char *dest, int32_t dest_size)
{
	if (kv_sep2_get_total_size(splice) > dest_size) {
		log_warn("Denied serialization to avoid buffer overflow");
		return false;
	}
	assert(splice->key_size > 0);
	uint32_t idx = 0;
	memcpy(dest, &splice->value_offt, sizeof(splice->value_offt));
	idx += sizeof(splice->value_offt);
	memcpy(&dest[idx], &splice->key_size, sizeof(splice->key_size));
	idx += sizeof(splice->key_size);
	memcpy(&dest[idx], splice->key, splice->key_size);

	return true;
}

struct kv_seperation_splice2 *kv_sep2_create(int32_t key_size, char *key, uint64_t value_offt, char *buf,
					     int32_t buf_size)
{
	assert(key_size > 0);
	if (buf_size < sizeof(struct kv_seperation_splice2) + key_size) {
		log_fatal("Buffer not enough");
		_exit(EXIT_FAILURE);
		return NULL;
	}
	struct kv_seperation_splice2 *kv_sep2 = (struct kv_seperation_splice2 *)buf;
	kv_sep2->key_size = key_size;
	kv_sep2->value_offt = value_offt;
	memcpy(kv_sep2->key, key, key_size);

	return kv_sep2;
}

struct kv_seperation_splice2 *kv_sep2_alloc_and_create(int32_t key_size, char *key, uint64_t value_offt)
{
	char *buf = calloc(1UL, sizeof(struct kv_seperation_splice2) + key_size);
	return kv_sep2_create(key_size, key, value_offt, buf, sizeof(struct kv_seperation_splice2) + key_size);
}

int32_t kv_splice_calculate_size(int32_t key_size, int32_t value_size)
{
	return key_size + value_size + sizeof(struct kv_seperation_splice);
}

int32_t kv_sep2_calculate_size(int32_t key_size)
{
	return key_size + sizeof(struct kv_seperation_splice2);
}

struct kv_splice *kv_splice_create(int32_t key_size, char *key, int32_t value_size, char *value)
{
	struct kv_splice *kv_splice = calloc(1UL, sizeof(*kv_splice) + key_size + value_size);
	kv_splice->key_size = key_size;
	kv_splice->value_size = value_size;
	memcpy(kv_splice->data, key, key_size);
	memcpy(&kv_splice->data[key_size], value, value_size);
	return kv_splice;
}

void kv_splice_serialize(struct kv_splice *splice, char *dest)
{
	assert(splice->key_size > 0);
	uint32_t idx = 0;
	memcpy(dest, &splice->key_size, sizeof(splice->key_size));
	idx += sizeof(splice->key_size);
	memcpy(&dest[idx], &splice->value_size, sizeof(splice->value_size));
	idx += sizeof(splice->value_size);
	memcpy(&dest[idx], splice->data, get_key_size(splice) + get_value_size(splice));
}
// kv general splice methods
int32_t kv_general_splice_get_size(struct kv_general_splice *splice)
{
	if (splice->cat == SMALL_INPLACE || splice->cat == MEDIUM_INPLACE)
		return get_kv_size(splice->kv_splice);
	if (splice->cat == MEDIUM_INLOG || splice->cat == BIG_INLOG)
		return kv_sep2_get_total_size(splice->kv_sep2);
	return -1;
}

int32_t kv_general_splice_get_key_size(struct kv_general_splice *splice)
{
	if (splice->cat == SMALL_INPLACE || splice->cat == MEDIUM_INPLACE)
		return get_key_size(splice->kv_splice);
	if (splice->cat == MEDIUM_INLOG || splice->cat == BIG_INLOG)
		return kv_sep2_get_key_size(splice->kv_sep2);
	return -1;
}

char *kv_general_splice_get_key_buf(struct kv_general_splice *splice)
{
	if (splice->cat == SMALL_INPLACE || splice->cat == MEDIUM_INPLACE)
		return get_key_offset_in_kv(splice->kv_splice);
	if (splice->cat == MEDIUM_INLOG || splice->cat == BIG_INLOG)
		return kv_sep2_get_key(splice->kv_sep2);
	return NULL;
}

static void kv_general_splice_fill_key(struct kv_general_splice *splice, char **key, int32_t *key_size)
{
	if (splice->cat == SMALL_INPLACE || splice->cat == MEDIUM_INPLACE) {
		*key = get_key_offset_in_kv(splice->kv_splice);
		*key_size = get_key_size(splice->kv_splice);
		return;
	}

	if (splice->cat == MEDIUM_INLOG || splice->cat == BIG_INLOG) {
		*key = kv_sep2_get_key(splice->kv_sep2);
		*key_size = kv_sep2_get_key_size(splice->kv_sep2);
		return;
	}
	*key = NULL;
	*key_size = -1;
}

int kv_general_splice_compare(struct kv_general_splice *sp1, struct kv_general_splice *sp2)
{
	char *key1 = NULL;
	int32_t key_size1 = -1;
	kv_general_splice_fill_key(sp1, &key1, &key_size1);

	char *key2 = NULL;
	int32_t key_size2 = -1;
	kv_general_splice_fill_key(sp2, &key2, &key_size2);

	int ret = memcmp(key1, key2, key_size1 <= key_size2 ? key_size1 : key_size2);
	return ret == 0 ? key_size1 - key_size2 : ret;
}

int32_t kv_general_splice_calculate_size(struct kv_general_splice *general_splice)
{
	if (general_splice->cat == SMALL_INPLACE || general_splice->cat == MEDIUM_INPLACE)
		return get_kv_size(general_splice->kv_splice);
	if (general_splice->cat == MEDIUM_INLOG || general_splice->cat == BIG_INLOG)
		return kv_sep2_get_total_size(general_splice->kv_sep2);
	return -1;
}

char *kv_general_splice_get_reference(struct kv_general_splice *splice)
{
	if (splice->cat == SMALL_INPLACE || splice->cat == MEDIUM_INPLACE)
		return (char *)splice->kv_splice;
	if (splice->cat == MEDIUM_INLOG || splice->cat == BIG_INLOG)
		return (char *)splice->kv_sep2;
	log_fatal("Corrupted kv category");
	_exit(EXIT_FAILURE);
}

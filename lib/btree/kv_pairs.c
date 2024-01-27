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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DELETE_MARKER_ID (INT32_MAX)
#define VALUE_OFFT_SIZE sizeof(uint64_t)

inline enum kv_category kv_meta_get_cat(struct kv_splice_meta *meta)
{
	return meta->kv_cat;
}

inline bool kv_meta_is_tombstone(struct kv_splice_meta *meta)
{
	return meta->tombstone;
}

inline bool kv_meta_is_kv_format(struct kv_splice_meta *meta)
{
	return meta->kv_format;
}

inline bool kv_meta_set_cat(struct kv_splice_meta *meta, enum kv_category cat)
{
	meta->kv_cat = cat;
	return true;
}

inline bool kv_meta_set_tombstone(struct kv_splice_meta *meta, bool val)
{
	meta->tombstone = val;
	return true;
}

inline bool kv_meta_set_kv_format(struct kv_splice_meta *meta, bool val)
{
	meta->kv_format = val;
	return true;
}

inline bool kv_meta_set_prev_kv_size(struct kv_splice_meta *meta, uint16_t size)
{
	if (size > KV_META_MAX_PREV_SIZE) {
		log_fatal("Overflow");
		_exit(EXIT_FAILURE);
	}
	meta->unreserved = size;
	return true;
}

inline uint16_t kv_meta_get_prev_kv_size(struct kv_splice_meta *meta)
{
	return meta->unreserved;
}

inline int32_t kv_splice_get_key_size(struct kv_splice *kv_pair)
{
	// assert(kv_pair->key_size > 0);
	return kv_pair->key_size;
}

inline int32_t kv_splice_get_value_size(struct kv_splice *kv_pair)
{
	return kv_splice_is_tombstone_kv_pair(kv_pair) ? 0 : kv_pair->value_size;
}

// cppcheck-suppress unusedFunction
inline int32_t kv_splice_get_value_size_with_metadata(struct kv_splice *kv_pair)
{
	return sizeof(kv_pair->value_size) + kv_splice_get_value_size(kv_pair);
}

inline int32_t kv_splice_get_kv_size(struct kv_splice *kv_pair)
{
	// log_debug("Splice size is %u key_size: %u value_size: %u",
	// 	  kv_splice_get_key_size(kv_pair) + kv_splice_get_value_size(kv_pair) + kv_splice_get_metadata_size(),
	// 	  kv_splice_get_key_size(kv_pair), kv_splice_get_value_size(kv_pair));
	//  log_debug("Key is: %s",kv_splice_get_key_offset_in_kv(kv_pair));
	return kv_splice_get_key_size(kv_pair) + kv_splice_get_value_size(kv_pair) + kv_splice_get_metadata_size();
}

inline int32_t kv_splice_get_tail_size(void)
{
	return sizeof(uint8_t);
}

inline void kv_splice_set_key_size(struct kv_splice *kv_pair, int32_t key_size)
{
	kv_pair->key_size = key_size;
}

inline void kv_splice_set_key(struct kv_splice *kv_pair, char *key, int32_t key_size)
{
	kv_pair->key_size = key_size;
	memcpy(kv_splice_get_key_offset_in_kv(kv_pair), key, key_size);
}

inline void kv_splice_set_value_size(struct kv_splice *kv_pair, int32_t value_size)
{
	kv_pair->value_size = value_size;
}

inline void kv_splice_set_value(struct kv_splice *kv_pair, char *value, int32_t value_size)
{
	if (kv_splice_is_tombstone_kv_pair(kv_pair))
		return;
	kv_pair->value_size = value_size;
	memcpy(kv_splice_get_value_offset_in_kv(kv_pair, kv_pair->key_size), value, value_size);
}

inline char *kv_splice_get_key_offset_in_kv(struct kv_splice *kv_pair)
{
	return kv_pair->data;
}

inline char *kv_splice_get_value_offset_in_kv(struct kv_splice *kv_pair, int32_t key_size)
{
	return kv_splice_is_tombstone_kv_pair(kv_pair) ? NULL : kv_pair->data + key_size;
}

inline bool kv_splice_is_tombstone_kv_pair(struct kv_splice *kv_pair)
{
	return DELETE_MARKER_ID == kv_pair->value_size;
}

inline void kv_splice_set_non_tombstone(struct kv_splice *kv_pair)
{
	kv_pair->value_size = 0;
}

inline void kv_splice_set_tombstone(struct kv_splice *kv_pair)
{
	kv_pair->value_size = DELETE_MARKER_ID;
}

uint32_t kv_splice_get_min_possible_kv_size(void)
{
	return kv_splice_get_metadata_size() + 1;
}

inline int32_t kv_splice_get_metadata_size(void)
{
#if TEBIS_FORMAT
	int32_t kv_pair_metadata_size = sizeof(struct kv_splice) + kv_splice_get_tail_size();
#else
	int32_t kv_pair_metadata_size = sizeof(struct kv_splice);
#endif
	return kv_pair_metadata_size;
}

struct kv_splice *kv_splice_create(int32_t key_size, char *key, int32_t value_size, char *value)
{
	struct kv_splice *kv_splice = calloc(1UL, key_size + value_size + kv_splice_get_metadata_size());
	kv_splice->key_size = key_size;
	kv_splice->value_size = value_size;

	memcpy(kv_splice->data, key, key_size);
	memcpy(&kv_splice->data[key_size], value, value_size);
#if TEBIS_FORMAT
	set_sizes_tail(kv_splice, INT8_MAX);
	set_payload_tail(kv_splice, INT8_MAX);
#endif

	return kv_splice;
}

void kv_splice_serialize(struct kv_splice *splice, char *dest)
{
	uint32_t num_bytes = kv_splice_get_kv_size(splice);
	assert(splice->key_size > 0);
	//uint32_t idx = 0;
	memcpy(dest, splice, num_bytes);
	/*idx += sizeof(splice->key_size);
	memcpy(&dest[idx], &splice->value_size, sizeof(splice->value_size));
	idx += sizeof(splice->value_size);
	memcpy(&dest[idx], splice->data, kv_splice_get_key_size(splice) + kv_splice_get_value_size(splice));
	*/
}

void kv_splice_serialize_to_key_splice(char *buf, struct kv_splice *kv_pair)
{
	struct key_splice *key_splice = (struct key_splice *)buf;
	int32_t key_size = kv_splice_get_key_size(kv_pair);
	char *key = kv_splice_get_key_offset_in_kv(kv_pair);
	key_splice_set_key_size(key_splice, key_size);
	memcpy(key_splice_get_key_offset(key_splice), key, key_size);
}

uint32_t kv_splice_calculate_size(int32_t key_size, int32_t value_size)
{
	if (value_size == DELETE_MARKER_ID)
		value_size = 0;
	return key_size + value_size + kv_splice_get_metadata_size();
}

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

// cppcheck-suppress unusedFunction
void kv_sep2_set_value_offt(struct kv_seperation_splice2 *kv_sep2, uint64_t value_offt)
{
	kv_sep2->value_offt = value_offt;
}

int32_t kv_sep2_get_total_size(struct kv_seperation_splice2 *kv_sep2)
{
	// return sizeof(kv_sep2->key_size) + kv_sep2->key_size + sizeof(kv_sep2->value_offt);
	return sizeof(*kv_sep2) + kv_sep2->key_size;
}

bool kv_sep2_serialize(struct kv_seperation_splice2 *splice, char *dest, int32_t dest_size)
{
	if (kv_sep2_get_total_size(splice) > dest_size) {
		log_warn("Denied serialization to avoid buffer overflow");
		return false;
	}
	assert(splice->key_size > 0);
	// uint32_t idx = 0;
	// memcpy(dest, &splice->value_offt, sizeof(splice->value_offt));
	// idx += sizeof(splice->value_offt);
	// memcpy(&dest[idx], &splice->key_size, sizeof(splice->key_size));
	// idx += sizeof(splice->key_size);
	// memcpy(&dest[idx], splice->key, splice->key_size);

	uint32_t idx = 0;
	memcpy(dest, splice, sizeof(*splice));
	idx += sizeof(*splice);
	memcpy(&dest[idx], splice->key, splice->key_size);
	return true;
}

struct kv_seperation_splice2 *kv_sep2_create(int32_t key_size, char *key, uint64_t value_offt, char *buf,
					     uint32_t buf_size)
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

uint32_t kv_sep2_calculate_size(int32_t key_size)
{
	return key_size + sizeof(struct kv_seperation_splice2);
}

static inline bool kv_splice_base_is_kv_format(struct kv_splice_base *splice)
{
	assert(splice);
	assert(splice->kv_type == KV_FORMAT || splice->kv_type == KV_PREFIX);
	return splice->kv_type == KV_FORMAT ? true : false;
}

// kv general splice methods
int32_t kv_splice_base_get_size(struct kv_splice_base *splice)
{
	assert(splice);
	return kv_splice_base_is_kv_format(splice) ? kv_splice_get_kv_size(splice->kv_splice) :
						     kv_sep2_get_total_size(splice->kv_sep2);
}

int32_t kv_splice_base_get_key_size(struct kv_splice_base *splice)
{
	assert(splice);
	return kv_splice_base_is_kv_format(splice) ? kv_splice_get_key_size(splice->kv_splice) :
						     kv_sep2_get_key_size(splice->kv_sep2);
}

int32_t kv_splice_base_get_value_size(struct kv_splice_base *splice)
{
	assert(splice);
	// return kv_splice_base_is_kv_format(splice) ? kv_splice_get_value_size(splice->kv_splice) :
	// 					     (int32_t)sizeof(splice->kv_sep2->value_offt);
	return kv_splice_base_is_kv_format(splice) ? kv_splice_get_value_size(splice->kv_splice) :
						     (int32_t)VALUE_OFFT_SIZE;
}

char *kv_splice_base_get_key_buf(struct kv_splice_base *splice)
{
	assert(splice);
	return kv_splice_base_is_kv_format(splice) ? kv_splice_get_key_offset_in_kv(splice->kv_splice) :
						     kv_sep2_get_key(splice->kv_sep2);
}

static void kv_splice_base_fill_key(struct kv_splice_base *splice, char **key, int32_t *key_size)
{
	assert(splice);
	if (kv_splice_base_is_kv_format(splice)) {
		*key = kv_splice_get_key_offset_in_kv(splice->kv_splice);
		*key_size = kv_splice_get_key_size(splice->kv_splice);
		return;
	}
	*key = kv_sep2_get_key(splice->kv_sep2);
	*key_size = kv_sep2_get_key_size(splice->kv_sep2);
}

int kv_splice_base_compare(struct kv_splice_base *sp1, struct kv_splice_base *sp2)
{
	assert(sp1 && sp2);
	assert(sp1->kv_type == KV_FORMAT || sp1->kv_type == KV_PREFIX);
	assert(sp2->kv_type == KV_FORMAT || sp2->kv_type == KV_PREFIX);
	char *key1 = NULL;
	int32_t key_size1 = -1;
	kv_splice_base_fill_key(sp1, &key1, &key_size1);

	char *key2 = NULL;
	int32_t key_size2 = -1;
	kv_splice_base_fill_key(sp2, &key2, &key_size2);

	assert(key_size1 >= 0);
	assert(key_size2 >= 0);

	int ret = memcmp(key1, key2, key_size1 <= key_size2 ? key_size1 : key_size2);
	return ret == 0 ? key_size1 - key_size2 : ret;
}

int32_t kv_splice_base_calculate_size(struct kv_splice_base *splice)
{
	return kv_splice_base_is_kv_format(splice) ? kv_splice_get_kv_size(splice->kv_splice) :
						     kv_sep2_get_total_size(splice->kv_sep2);
}

// cppcheck-suppress unusedFunction
char *kv_splice_base_get_reference(struct kv_splice_base *splice)
{
	return (kv_splice_base_is_kv_format(splice)) ? (char *)splice->kv_splice : (char *)splice->kv_sep2;
}

void kv_splice_base_serialize(struct kv_splice_base *splice_base, char *dest, int32_t dest_size)
{
	assert(splice_base && dest);
	assert(splice_base->kv_type == KV_PREFIX || splice_base->kv_type == KV_FORMAT);
	if (splice_base->kv_type == KV_FORMAT)
		kv_splice_serialize(splice_base->kv_splice, dest);
	else
		kv_sep2_serialize(splice_base->kv_sep2, dest, dest_size);
}

#if TEBIS_FORMAT
inline void set_sizes_tail(struct kv_splice *kv_pair, uint8_t tail)
{
	kv_pair->tail_for_sizes = tail;
}

inline void set_payload_tail(struct kv_splice *kv_pair, uint8_t tail)
{
	char *payload = kv_pair->data;
	int32_t key_size = kv_splice_get_key_size(kv_pair);
	int32_t value_size = kv_splice_get_value_size(kv_pair);
	payload[key_size + value_size] = tail;
}
#endif

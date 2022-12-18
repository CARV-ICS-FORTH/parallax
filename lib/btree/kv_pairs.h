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
#ifndef KV_PAIRS_H
#define KV_PAIRS_H
#include "../include/parallax/structures.h"
#include <stdbool.h>
#include <stdint.h>
#define PREFIX_SIZE 12
enum KV_type { KV_FORMAT, KV_PREFIX, INDEX_KEY_TYPE, KEY_TYPE };

#define KV_SEP2_MAX_SIZE 512 //(sizeof(uint64_t) + sizeof(int32_t) + MAX_KEY_SIZE)

// KVs in Parallax follow | key_size | value_size | key | value | layout
struct kv_splice {
	int32_t key_size;
	int32_t value_size;
	char data[];
} __attribute__((packed));

struct kv_seperation_splice {
	char prefix[PREFIX_SIZE];
	uint64_t dev_offt;
} __attribute__((packed));

struct kv_seperation_splice2 {
	uint64_t value_offt;
	int32_t key_size;
	char key[];
} __attribute__((packed));

struct kv_general_splice {
	enum kv_category cat;
	bool is_tombstone;
	union {
		struct kv_splice *kv_splice;
		struct kv_seperation_splice2 *kv_sep2;
	};
};

/**
 * @brief Returns a pointer to the key
 * @param kv_sep2 pointer to the splice
 * @return pointer to the key
 */
char *kv_sep2_get_key(struct kv_seperation_splice2 *kv_sep2);

/**
 * @brief Returns the size of the key
 */
int32_t kv_sep2_get_key_size(struct kv_seperation_splice2 *kv_sep2);
uint64_t kv_sep2_get_value_offt(struct kv_seperation_splice2 *kv_sep2);
int32_t kv_sep2_get_total_size(struct kv_seperation_splice2 *kv_sep2);
bool kv_sep2_serialize(struct kv_seperation_splice2 *splice, char *dest, int32_t dest_size);
void kv_splice_serialize(struct kv_splice *splice, char *dest);
struct kv_seperation_splice2 *kv_sep2_alloc_and_create(int32_t key_size, char *key, uint64_t value_offt);
struct kv_seperation_splice2 *kv_sep2_create(int32_t key_size, char *key, uint64_t value_offt, char *buf,
					     int32_t buf_size);

struct kv_splice *kv_splice_create(int32_t key_size, char *key, int32_t value_size, char *value);
int32_t kv_general_splice_get_size(struct kv_general_splice *splice);
int32_t kv_general_splice_get_key_size(struct kv_general_splice *splice);
char *kv_general_splice_get_key_buf(struct kv_general_splice *splice);
int kv_general_splice_compare(struct kv_general_splice *sp1, struct kv_general_splice *sp2);
int32_t kv_general_splice_calculate_size(struct kv_general_splice *general_splice);
char *kv_general_splice_get_reference(struct kv_general_splice *splice);

/**
 * Calculates key_size given a splice formated key
 * @param key: a KV_FORMATED key
 * @return key size
 */
int32_t get_key_size(struct kv_splice *kv_pair);
/**
 * Returns the value_size given a splice formated key
 * @param value: a spliced (KV_FORMATED) kv ptr
 */
int32_t get_value_size(struct kv_splice *kv_pair);
/**
 * Calculates the value_size  + metadata given a splice formated key
 * @param value: a spliced (KV_FORMATED) kv ptr
 */
int32_t get_value_size_with_metadata(struct kv_splice *kv_pair);
/**
 * Calculates sizeof(splice.value_size) + sizeof(splice.key_size)
 */
int32_t get_kv_metadata_size(void);
/**
 * Calculates the key value pair size (with its metadata) for KV_FORMAT
 * @param kv: a spliced (KV_FORMATED) kv ptr
 */
int32_t get_kv_size(struct kv_splice *kv_pair);
/**
 * Sets the key size given a splice formated kv
 * @param kv: a spliced (KV_FORMATED) kv ptr, where key_size will be set
 * @param key_size: the new size to be set
 */
void set_key_size(struct kv_splice *kv_pair, int32_t key_size);

/**
  * Copies the key buffer to the kv pair
  * @param kv_pair: a KV_FORMAT kv_pair
  * @param key_size: size of the key buffer
  * @parama key: pointer to the key buffer
  */
void set_key(struct kv_splice *kv_pair, char *key, int32_t key_size);

/**
 * Sets the value size given a splice formated kv
 * @param kv: a spliced (KV_FORMATED) kv ptr, where value_size will be set
 * @param value_size: the new size to be set
 */
void set_value_size(struct kv_splice *kv_pair, int32_t value_size);

/**
  * Copies the value buffer to the kv pair
  * @param kv_pair: a KV_FORMAT kv_pair
  * @param key_size: size of the key buffer
  * @parama key: pointer to the key buffer
  */
void set_value(struct kv_splice *kv_pair, char *value, int32_t value_size);

/**
 * Calculates the starting offset of the key part of a given splice kv
 * @param kv: a spliced (KV_FORMATED) kv ptr, from which the key is retrieved
 */
char *get_key_offset_in_kv(struct kv_splice *kv_pair);
/**
 * Calculates the starting offset of the value part of a given splice kv
 * @param kv: a spliced (KV_FORMATED) kv ptr, from which the key is retrieved
 * @param key_size: the key size of this kv
 */
char *get_value_offset_in_kv(struct kv_splice *kv_pair, int32_t key_size);
/**
 * Calculates the key_size of the actual struct splice kv following the ptr of the  kv_seperated kv
 * @param kv: a kv-seperated splice kv ptr
 */
int32_t get_kv_seperated_key_size(struct kv_seperation_splice *kv_pair);
/**
 * Calculates the value_size of the actual struct splice kv following the ptr of the  kv_seperated kv
 * @param kv: a kv-seperated splice kv ptr
 */
int32_t get_kv_seperated_value_size(struct kv_seperation_splice *kv_pair);
/**
 * Calculates the kv_size of the actual struct splice kv following the ptr of the  kv_seperated kv
 * @param kv: a kv-seperated splice kv ptr
 */
int32_t get_kv_seperated_kv_size(struct kv_seperation_splice *kv_pair);
/**
 * Returns the size of kv_seperation splice
 */
int32_t get_kv_seperated_splice_size(void);

/**
 * Returns the starting address of the buffer that stores the prefix
 * @param Pointer to the kv_seperated kv_pair
 */
char *get_kv_seperated_prefix(struct kv_seperation_splice *kv_pair);

/**
 * Return the size of the PREFIX
 */
int32_t get_kv_seperated_prefix_size(void);

/**
 * Returns the device offset where this kv_seperation_splice is actually stored
 * @param Pointer to the kv_seperated_kv_pair
*/
uint64_t get_kv_seperated_device_offt(struct kv_seperation_splice *kv_pair);

/**
 * Sets the device offset where this kv_seperation_splice is actually stored
 * @param Pointer to the kv_seperated_kv_pair
 * @param The device offset to set
*/
void set_kv_seperated_device_offt(struct kv_seperation_splice *kv_pair, uint64_t dev_offt);

/**
  * Examines a KV pair to see if it is a delete marker
  */
bool is_tombstone_kv_pair(struct kv_splice *kv_pair);

void set_tombstone(struct kv_splice *kv_pair);

void set_non_tombstone(struct kv_splice *kv_pair);

void serialize_key(char *buf, void *key, uint32_t key_size);
void serialize_kv_splice_to_key_splice(char *buf, struct kv_splice *kv_pair);

int32_t get_min_possible_kv_size(void);

int32_t kv_splice_calculate_size(int32_t key_size, int32_t value_size);
int32_t kv_sep2_calculate_size(int32_t key_size);

#endif // KV_PAIRS_H_

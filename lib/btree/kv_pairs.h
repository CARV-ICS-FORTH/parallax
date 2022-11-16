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
#include <stdbool.h>
#include <stdint.h>
#define PREFIX_SIZE 12
enum KV_type { KV_FORMAT, KV_PREFIX, INDEX_KEY_TYPE, KEY_TYPE };

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

/**
 * Calculates key_size given a splice formated key
 * @param key: a KV_FORMATED key
 * @return key size
 */
int32_t get_key_size(struct kv_splice *kv_pair);
/**
 * Returns the key_size + metadata given a splice formated key
 * @param key: a spliced (KV_FORMATED) key ptr
 */
int32_t get_key_size_with_metadata(struct kv_splice *kv_pair);
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
uint32_t get_kv_seperated_prefix_size(void);

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

#endif // KV_PAIRS_H_

#ifndef KV_PAIRS_H_
#define KV_PAIRS_H_
#include <stdbool.h>
#include <stdint.h>
#define PREFIX_SIZE 12
#define DELETE_MARKER_ID (UINT32_MAX)

// KVs in Parallax follow | key_size | value_size | key | value | layout
struct splice {
	uint32_t key_size;
	uint32_t value_size;
	char data[]; //kv payload
} __attribute__((packed));

// TODO (@geostyl) should we replace all the bt_leaf_entry structs with this one? @gesalous yes
struct kv_seperation_splice {
	char prefix[PREFIX_SIZE];
	uint64_t dev_offt;
} __attribute__((packed));

// This struct defines the key abstraction of the system and it's irrelevant from splice format
struct key_splice {
	uint32_t key_size;
	char data[];
} __attribute__((packed));

#define GET_MIN_POSSIBLE_KV_SIZE() (sizeof(uint32_t) + 1)

/**
 * Calculates key_size given a splice formated key
 * @param key: a KV_FORMATED key
 * @return key size
 */
uint32_t get_key_size(struct splice *kv_pair);
/**
 * Returns the key_size + metadata given a splice formated key
 * @param key: a spliced (KV_FORMATED) key ptr
 */
uint32_t get_key_size_with_metadata(struct splice *kv_pair);
/**
 * Returns the value_size given a splice formated key
 * @param value: a spliced (KV_FORMATED) kv ptr
 */
uint32_t get_value_size(struct splice *kv_pair);
/**
 * Calculates the value_size  + metadata given a splice formated key
 * @param value: a spliced (KV_FORMATED) kv ptr
 */
uint32_t get_value_size_with_metadata(struct splice *kv_pair);
/**
 * Calculates sizeof(splice.value_size) + sizeof(splice.key_size)
 */
uint32_t get_kv_metadata_size(void);
/**
 * Calculates the kv size given a splice formated kv
 * @param kv: a spliced (KV_FORMATED) kv ptr
 */
uint32_t get_kv_size(struct splice *kv_pair);
/**
 * Sets the key size given a splice formated kv
 * @param kv: a spliced (KV_FORMATED) kv ptr, where key_size will be set
 * @param key_size: the new size to be set
 */
void set_key_size(struct splice *kv_pair, uint32_t key_size);

/**
  * Copies the key buffer to the kv pair
  * @param kv_pair: a KV_FORMAT kv_pair
  * @param key_size: size of the key buffer
  * @parama key: pointer to the key buffer
  */
void set_key(struct splice *kv_pair, char *key, uint32_t key_size);

/**
 * Sets the value size given a splice formated kv
 * @param kv: a spliced (KV_FORMATED) kv ptr, where value_size will be set
 * @param value_size: the new size to be set
 */
void set_value_size(struct splice *kv_pair, uint32_t value_size);

/**
  * Copies the value buffer to the kv pair
  * @param kv_pair: a KV_FORMAT kv_pair
  * @param key_size: size of the key buffer
  * @parama key: pointer to the key buffer
  */
void set_value(struct splice *kv_pair, char *value, uint32_t value_size);

/**
 * Calculates the starting offset of the key part of a given splice kv
 * @param kv: a spliced (KV_FORMATED) kv ptr, from which the key is retrieved
 */
char *get_key_offset_in_kv(struct splice *kv_pair);
/**
 * Calculates the starting offset of the value part of a given splice kv
 * @param kv: a spliced (KV_FORMATED) kv ptr, from which the key is retrieved
 * @param key_size: the key size of this kv
 */
char *get_value_offset_in_kv(struct splice *kv_pair, uint32_t key_size);
/**
 * Calculates the key_size of the actual struct splice kv following the ptr of the  kv_seperated kv
 * @param kv: a kv-seperated splice kv ptr
 */
uint32_t get_key_size_kv_seperated(struct kv_seperation_splice *kv_pair);
/**
 * Calculates the value_size of the actual struct splice kv following the ptr of the  kv_seperated kv
 * @param kv: a kv-seperated splice kv ptr
 */
uint32_t get_value_size_kv_seperated(struct kv_seperation_splice *kv_pair);
/**
 * Calculates the kv_size of the actual struct splice kv following the ptr of the  kv_seperated kv
 * @param kv: a kv-seperated splice kv ptr
 */
uint32_t get_kv_size_kv_seperated(struct kv_seperation_splice *kv_pair);

/**
  * Examines a KV pair to see if it is a delete marker
  */
bool is_a_tombstone_kv_pair(struct splice *kv_pair);

void set_tombstone(struct splice *kv_pair);

void set_non_tombstone(struct splice *kv_pair);

uint32_t get_key_size_of_key_splice(struct key_splice *key);

char *get_key_offset_of_key_splice(struct key_splice *key);
#endif // KV_PAIRS_H_

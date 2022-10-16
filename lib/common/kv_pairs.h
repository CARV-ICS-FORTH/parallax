#ifndef KV_PAIRS_H_
#define KV_PAIRS_H_
#include <stdint.h>
#define PREFIX_SIZE 12

// KVs in Parallax follow | key_size | value_size | key | value | layout
struct splice {
	uint32_t key_size;
	uint32_t value_size;
	char data[]; //kv payload
} __attribute__((packed));

// TODO (@geostyl) should we replace all the bt_leaf_entry structs with this one?
struct kv_seperation_splice {
	char prefix[PREFIX_SIZE];
	uint64_t dev_offt;
} __attribute__((packed));

/**
 * Function returning the key_size given a splice formated key
 * @param key: a spliced (KV_FORMATED) key ptr
 */
uint32_t get_key_size(struct splice *key);
/**
 * Function returning the key_size + metadata given a splice formated key
 * @param key: a spliced (KV_FORMATED) key ptr
 */
uint32_t get_key_size_with_metadata(struct splice *key);
/**
 * Function returning the value_size given a splice formated key
 * @param value: a spliced (KV_FORMATED) kv ptr
 */
uint32_t get_value_size(struct splice *value);
/**
 * Function returning the value_size  + metadata given a splice formated key
 * @param value: a spliced (KV_FORMATED) kv ptr
 */
uint32_t get_value_size_with_metadata(struct splice *value);
/**
 * Function returning sizeof(splice.value_size) + sizeof(splice.key_size)
 */
uint32_t get_kv_metadata_size(void);
/**
 * Function returning the kv size given a splice formated kv
 * @param kv: a spliced (KV_FORMATED) kv ptr
 */
uint32_t get_kv_size(struct splice *kv);
/**
 * Function setting the key size given a splice formated kv
 * @param kv: a spliced (KV_FORMATED) kv ptr, where key_size will be set
 * @param key_size: the new size to be set
 */
void set_key_size(struct splice *kv, uint32_t key_size);
/**
 * Function setting the value size given a splice formated kv
 * @param kv: a spliced (KV_FORMATED) kv ptr, where value_size will be set
 * @param value_size: the new size to be set
 */
void set_value_size(struct splice *kv, uint32_t value_size);
/**
 * Function returning the starting offset of the key part of a given splice kv
 * @param kv: a spliced (KV_FORMATED) kv ptr, from which the key is retrieved
 */
char *get_key_offset_in_kv(struct splice *kv);
/**
 * Function returning the starting offset of the value part of a given splice kv
 * @param kv: a spliced (KV_FORMATED) kv ptr, from which the key is retrieved
 * @param key_size: the key size of this kv
 */
char *get_value_offset_in_kv(struct splice *kv, uint32_t key_size);
/**
 * Function returning the key_size of the actual struct splice kv following the ptr of the  kv_seperated kv
 * @param kv: a kv-seperated splice kv ptr
 */
uint32_t get_key_size_kv_seperated(struct kv_seperation_splice *kv);
/**
 * Function returning the value_size of the actual struct splice kv following the ptr of the  kv_seperated kv
 * @param kv: a kv-seperated splice kv ptr
 */
uint32_t get_value_size_kv_seperated(struct kv_seperation_splice *kv);
/**
 * Function returning the kv_size of the actual struct splice kv following the ptr of the  kv_seperated kv
 * @param kv: a kv-seperated splice kv ptr
 */
uint32_t get_kv_size_kv_seperated(struct kv_seperation_splice *kv);
#endif // KV_PAIRS_H_

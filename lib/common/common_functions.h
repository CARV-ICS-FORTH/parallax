#ifndef COMMON_FUNCTIONS_H_
#define COMMON_FUNCTIONS_H_
#include <stdint.h>
#define PREFIX_SIZE 12
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

uint32_t get_key_size(struct splice *key);
uint32_t get_key_size_with_metadata(struct splice *key);
uint32_t get_value_size(struct splice *value);
uint32_t get_value_size_with_metadata(struct splice *value);

uint32_t get_kv_metadata_size(void);
uint32_t get_kv_size(struct splice *kv);
void set_key_size(struct splice *kv, uint32_t key_size);
void set_value_size(struct splice *kv, uint32_t value_size);
char *get_key_offset_in_kv(struct splice *kv);
char *get_value_offset_in_kv(struct splice *kv);

uint32_t get_key_size_kv_seperated(struct kv_seperation_splice *kv);
uint32_t get_value_size_kv_seperated(struct kv_seperation_splice *kv);
uint32_t get_kv_size_kv_seperated(struct kv_seperation_splice *kv);
#endif // COMMON_FUNCTIONS_H_

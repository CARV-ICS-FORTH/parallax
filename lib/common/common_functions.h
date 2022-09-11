#ifndef COMMON_FUNCTIONS_H_
#define COMMON_FUNCTIONS_H_

#include <stdint.h>
struct splice {
	uint32_t key_size;
	uint32_t value_size;
	char data[];
};

uint32_t get_key_size(struct splice *key);
uint32_t get_key_size_with_metadata(struct splice *key);
uint32_t get_value_size(struct splice *value);
uint32_t get_value_size_with_metadata(struct splice *value);
#endif // COMMON_FUNCTIONS_H_

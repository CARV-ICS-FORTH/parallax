#include "common_functions.h"

uint32_t get_key_size(struct splice *key)
{
	return key->size;
}

uint32_t get_key_size_with_metadata(struct splice *key)
{
	return sizeof(key->size) + key->size;
}

uint32_t get_value_size(struct splice *value)
{
	return value->size;
}

uint32_t get_value_size_with_metadata(struct splice *value)
{
	return sizeof(value->size) + value->size;
}

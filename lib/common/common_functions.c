#include "common_functions.h"

uint32_t get_key_size(struct splice *kv)
{
	return kv->key_size;
}

uint32_t get_key_size_with_metadata(struct splice *kv)
{
	return sizeof(kv->key_size) + kv->key_size;
}

uint32_t get_value_size(struct splice *kv)
{
	return kv->value_size;
}

uint32_t get_value_size_with_metadata(struct splice *kv)
{
	return sizeof(kv->value_size) + kv->value_size;
}

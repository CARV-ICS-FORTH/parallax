#include "common_functions.h"
#include <assert.h>

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

// Returns the size of a kv_formated kv
// TODO (geostyl) FIXME add proper documentation
uint32_t get_kv_metadata_size(void)
{
	// size of key_size + value_size of splice
	// this assert will fail if key_size or value_size change in splcie.
	uint32_t kv_metadata_size = sizeof(struct splice);
	uint32_t expected_metadata_size = sizeof(uint32_t) + sizeof(uint32_t);
	assert(kv_metadata_size == expected_metadata_size);

	return kv_metadata_size;
}

uint32_t get_kv_size(struct splice *kv)
{
	return kv->key_size + kv->value_size + get_kv_metadata_size();
}

void set_key_size(struct splice *kv, uint32_t key_size)
{
	kv->key_size = key_size;
}

void set_value_size(struct splice *kv, uint32_t value_size)
{
	kv->value_size = value_size;
}

char *get_key_offset_in_kv(struct splice *kv)
{
	return kv->data;
}
char *get_value_offset_in_kv(struct splice *kv)
{
	return kv->data + kv->key_size;
}

uint32_t get_key_size_kv_seperated(struct kv_seperation_splice *kv)
{
	return get_key_size((struct splice *)kv->dev_offt);
}

uint32_t get_value_size_kv_seperated(struct kv_seperation_splice *kv)
{
	return get_value_size((struct splice *)kv->dev_offt);
}

uint32_t get_kv_size_kv_seperated(struct kv_seperation_splice *kv)
{
	return get_kv_size((struct splice *)kv->dev_offt);
}

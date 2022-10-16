#include "common_functions.h"
#include <assert.h>

inline uint32_t get_key_size(struct splice *kv)
{
	return kv->key_size;
}

inline uint32_t get_key_size_with_metadata(struct splice *kv)
{
	return sizeof(kv->key_size) + kv->key_size;
}

inline uint32_t get_value_size(struct splice *kv)
{
	return kv->value_size;
}

inline uint32_t get_value_size_with_metadata(struct splice *kv)
{
	return sizeof(kv->value_size) + kv->value_size;
}

// Returns the size of a kv_formated kv
// TODO (geostyl) FIXME add proper documentation
inline uint32_t get_kv_metadata_size(void)
{
	uint32_t kv_metadata_size = sizeof(struct splice);
	return kv_metadata_size;
}

inline uint32_t get_kv_size(struct splice *kv)
{
	return kv->key_size + kv->value_size + get_kv_metadata_size();
}

inline void set_key_size(struct splice *kv, uint32_t key_size)
{
	kv->key_size = key_size;
}

inline void set_value_size(struct splice *kv, uint32_t value_size)
{
	kv->value_size = value_size;
}

inline char *get_key_offset_in_kv(struct splice *kv)
{
	return kv->data;
}

inline char *get_value_offset_in_kv(struct splice *kv, uint32_t key_size)
{
	return kv->data + key_size;
}

inline uint32_t get_key_size_kv_seperated(struct kv_seperation_splice *kv)
{
	return get_key_size((struct splice *)kv->dev_offt);
}

inline uint32_t get_value_size_kv_seperated(struct kv_seperation_splice *kv)
{
	return get_value_size((struct splice *)kv->dev_offt);
}

inline uint32_t get_kv_size_kv_seperated(struct kv_seperation_splice *kv)
{
	return get_kv_size((struct splice *)kv->dev_offt);
}

#include "kv_pairs.h"
#include <assert.h>
#include <string.h>
inline uint32_t get_key_size(struct splice *kv_pair)
{
	return kv_pair->key_size;
}

inline uint32_t get_key_size_with_metadata(struct splice *kv_pair)
{
	return sizeof(kv_pair->key_size) + kv_pair->key_size;
}

inline uint32_t get_value_size(struct splice *kv_pair)
{
	return is_a_tombstone_kv_pair(kv_pair) ? 0 : kv_pair->value_size;
}

inline uint32_t get_value_size_with_metadata(struct splice *kv_pair)
{
	return sizeof(kv_pair->value_size) + get_value_size(kv_pair);
}

// Returns the size of a kv_pair_formated kv_pair
// TODO (geostyl) FIXME add proper documentation
inline uint32_t get_kv_metadata_size(void)
{
	uint32_t kv_pair_metadata_size = sizeof(struct splice);
	return kv_pair_metadata_size;
}

inline uint32_t get_kv_size(struct splice *kv_pair)
{
	return get_key_size(kv_pair) + get_value_size(kv_pair) + get_kv_metadata_size();
}

inline void set_key_size(struct splice *kv_pair, uint32_t key_size)
{
	kv_pair->key_size = key_size;
}

inline void set_key(struct splice *kv_pair, char *key, uint32_t key_size)
{
	kv_pair->key_size = key_size;
	memcpy(get_key_offset_in_kv(kv_pair), key, key_size);
}

inline void set_value_size(struct splice *kv_pair, uint32_t value_size)
{
	kv_pair->value_size = value_size;
}

inline void set_value(struct splice *kv_pair, char *value, uint32_t value_size)
{
	if (is_a_tombstone_kv_pair(kv_pair))
		return;
	kv_pair->value_size = value_size;
	memcpy(get_value_offset_in_kv(kv_pair, kv_pair->key_size), value, value_size);
}

inline char *get_key_offset_in_kv(struct splice *kv_pair)
{
	return kv_pair->data;
}

inline char *get_value_offset_in_kv(struct splice *kv_pair, uint32_t key_size)
{
	return is_a_tombstone_kv_pair(kv_pair) ? NULL : kv_pair->data + key_size;
}

inline uint32_t get_key_size_kv_seperated(struct kv_seperation_splice *kv_pair)
{
	return get_key_size((struct splice *)kv_pair->dev_offt);
}

inline uint32_t get_value_size_kv_seperated(struct kv_seperation_splice *kv_pair)
{
	return get_value_size((struct splice *)kv_pair->dev_offt);
}

inline uint32_t get_kv_size_kv_seperated(struct kv_seperation_splice *kv_pair)
{
	return get_kv_size((struct splice *)kv_pair->dev_offt);
}

inline bool is_a_tombstone_kv_pair(struct splice *kv_pair)
{
	return DELETE_MARKER_ID == kv_pair->value_size ? true : false;
}

inline void set_non_tombstone(struct splice *kv_pair)
{
	kv_pair->value_size = 0;
}

void set_tombstone(struct splice *kv_pair)
{
	kv_pair->value_size = DELETE_MARKER_ID;
}

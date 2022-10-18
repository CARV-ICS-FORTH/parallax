#include "kv_pairs.h"
#include <assert.h>
#include <string.h>
inline int32_t get_key_size(struct kv_splice *kv_pair)
{
	return kv_pair->key_size;
}

// cppcheck-suppress unusedFunction
inline int32_t get_key_size_with_metadata(struct kv_splice *kv_pair)
{
	return sizeof(kv_pair->key_size) + kv_pair->key_size;
}

inline int32_t get_value_size(struct kv_splice *kv_pair)
{
	return is_tombstone_kv_pair(kv_pair) ? 0 : kv_pair->value_size;
}

// cppcheck-suppress unusedFunction
inline int32_t get_value_size_with_metadata(struct kv_splice *kv_pair)
{
	return sizeof(kv_pair->value_size) + get_value_size(kv_pair);
}

inline int32_t get_kv_metadata_size(void)
{
	int32_t kv_pair_metadata_size = sizeof(struct kv_splice);
	return kv_pair_metadata_size;
}

inline int32_t get_kv_size(struct kv_splice *kv_pair)
{
	return get_key_size(kv_pair) + get_value_size(kv_pair) + get_kv_metadata_size();
}

inline void set_key_size(struct kv_splice *kv_pair, int32_t key_size)
{
	kv_pair->key_size = key_size;
}

inline void set_key(struct kv_splice *kv_pair, char *key, int32_t key_size)
{
	kv_pair->key_size = key_size;
	memcpy(get_key_offset_in_kv(kv_pair), key, key_size);
}

inline void set_value_size(struct kv_splice *kv_pair, int32_t value_size)
{
	kv_pair->value_size = value_size;
}

inline void set_value(struct kv_splice *kv_pair, char *value, int32_t value_size)
{
	if (is_tombstone_kv_pair(kv_pair))
		return;
	kv_pair->value_size = value_size;
	memcpy(get_value_offset_in_kv(kv_pair, kv_pair->key_size), value, value_size);
}

inline char *get_key_offset_in_kv(struct kv_splice *kv_pair)
{
	return kv_pair->data;
}

inline char *get_value_offset_in_kv(struct kv_splice *kv_pair, int32_t key_size)
{
	return is_tombstone_kv_pair(kv_pair) ? NULL : kv_pair->data + key_size;
}

inline int32_t get_kv_seperated_key_size(struct kv_seperation_splice *kv_pair)
{
	return get_key_size((struct kv_splice *)kv_pair->dev_offt);
}

inline int32_t get_kv_seperated_value_size(struct kv_seperation_splice *kv_pair)
{
	return get_value_size((struct kv_splice *)kv_pair->dev_offt);
}

inline int32_t get_kv_seperated_kv_size(struct kv_seperation_splice *kv_pair)
{
	return get_kv_size((struct kv_splice *)kv_pair->dev_offt);
}

inline bool is_tombstone_kv_pair(struct kv_splice *kv_pair)
{
	return DELETE_MARKER_ID == kv_pair->value_size;
}

inline void set_non_tombstone(struct kv_splice *kv_pair)
{
	kv_pair->value_size = 0;
}

inline void set_tombstone(struct kv_splice *kv_pair)
{
	kv_pair->value_size = DELETE_MARKER_ID;
}

inline int32_t get_key_splice_key_size(struct key_splice *key)
{
	return key->key_size;
}

inline char *get_key_splice_key_offset(struct key_splice *key)
{
	return key->data;
}

inline void set_key_size_of_key_splice(struct key_splice *key, int32_t key_size)
{
	key->key_size = key_size;
}

inline void set_key_splice_key_offset(struct key_splice *key, char *key_buf)
{
	memcpy(get_key_splice_key_offset(key), key_buf, get_key_splice_key_size(key));
}

void serialize_key(char *buf, void *key, uint32_t key_size)
{
	struct kv_splice *kv_splice = (struct kv_splice *)buf;
	set_key_size(kv_splice, key_size);
	set_value_size(kv_splice, INT32_MAX);
	set_key(kv_splice, (char *)key, key_size);
}

void serialize_kv_splice_to_key_splice(char *buf, struct kv_splice *kv)
{
	struct key_splice *key_splice = (struct key_splice *)buf;
	int32_t key_size = get_key_size(kv);
	char *key = get_key_offset_in_kv(kv);
	set_key_size_of_key_splice(key_splice, key_size);
	memcpy(get_key_splice_key_offset(key_splice), key, key_size);
}

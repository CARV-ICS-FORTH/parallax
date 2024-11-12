#include "par_net_scan.h"
#include "../lib/btree/kv_pairs.h"
#include "par_net_close.h"
#include "parallax/structures.h"
#include <log.h>
#include <stdint.h>
#include <string.h>
struct par_net_scan_req {
	uint64_t region_id;
	par_seek_mode mode;
	uint32_t key_size;
	uint32_t max_kv_pairs;
} __attribute((packed));

struct par_net_scan_rep {
	uint32_t num_kv_pairs;
	uint32_t max_kv_pairs;
	uint32_t size;
	uint32_t max_size;
	uint32_t curr_splice_offt;
	uint32_t last_splice_offt;
	bool end_of_region;
} __attribute((packed));

inline size_t par_net_scan_req_calc_size(uint32_t key_size)
{
	return sizeof(struct par_net_scan_req) + key_size;
}

inline size_t par_net_scan_rep_header_calc_size(void)
{
	return sizeof(struct par_net_scan_rep);
}

uint64_t par_net_scan_req_get_region_id(struct par_net_scan_req *request)
{
	return request->region_id;
}

par_seek_mode par_net_scan_req_get_seek_mode(struct par_net_scan_req *request)
{
	return request->mode;
}

uint32_t par_net_scan_req_get_key_size(struct par_net_scan_req *request)
{
	return request->key_size;
}

const char *par_net_scan_req_get_key(struct par_net_scan_req *request)
{
	return &((char *)request)[sizeof(struct par_net_scan_req)];
}

uint32_t par_net_scan_req_get_max_entries(struct par_net_scan_req *request)
{
	return request->max_kv_pairs;
}

struct par_net_scan_req *par_net_scan_req_create(uint64_t region_id, struct par_key *key, uint32_t max_kv_pairs,
						 par_seek_mode mode, char *buffer, size_t buffer_len)
{
	if (buffer_len < par_net_scan_req_calc_size(key ? key->size : 1)) {
		log_warn("Buffer too small to create a scan requests needs: %lu B got: %lu B",
			 par_net_scan_req_calc_size(key->size), buffer_len);
		return NULL;
	}
	struct par_net_scan_req *request = (struct par_net_scan_req *)buffer;
	request->region_id = region_id;
	request->mode = mode;
	request->key_size = key ? key->size : 1;
	request->max_kv_pairs = max_kv_pairs;
	if (key) {
		memcpy(&buffer[sizeof(struct par_net_scan_req)], key->data, key->size);
	} else {
		buffer[sizeof(struct par_net_scan_req)] = 0;
	}
	return request;
}

//--- reply staff follows
bool par_net_scan_rep_has_more(struct par_net_scan_rep *reply)
{
	return reply->curr_splice_offt < reply->size ? true : reply->end_of_region;
}

inline void par_net_scan_rep_set_valid(struct par_net_scan_rep *reply, bool valid)
{
	reply->end_of_region = valid;
}

inline bool par_net_scan_rep_is_valid(struct par_net_scan_rep *reply)
{
	return reply->end_of_region;
}

inline uint32_t par_net_scan_rep_get_size(struct par_net_scan_rep *reply)
{
	return sizeof(*reply) + reply->size;
}

struct par_net_scan_rep *par_net_scan_rep_create(uint32_t max_kv_pairs, char *buffer, size_t buffer_len)
{
	if (buffer_len < par_net_scan_rep_header_calc_size()) {
		log_debug("Buffer too small");
		return NULL;
	}
	struct par_net_scan_rep *scan_reply = (struct par_net_scan_rep *)buffer;

	scan_reply->max_size = buffer_len - par_net_scan_rep_header_calc_size();
	scan_reply->size = 0;
	scan_reply->max_kv_pairs = max_kv_pairs;
	scan_reply->num_kv_pairs = 0;
	scan_reply->curr_splice_offt = UINT32_MAX;
	scan_reply->last_splice_offt = UINT32_MAX;
	return scan_reply;
}

bool par_net_scan_rep_append_splice(struct par_net_scan_rep *reply, int32_t key_size, const char *key,
				    int32_t value_size, const char *value)
{
	if (reply->num_kv_pairs >= reply->max_kv_pairs)
		return false;

	char *buffer = &((char *)reply)[sizeof(struct par_net_scan_rep) + reply->size];
	struct kv_splice *kv_splice =
		kv_splice_create2(key_size, key, value_size, value, buffer, reply->max_size - reply->size);
	if (NULL == kv_splice)
		return false;

	log_debug("Scan reply appending kv_splice of size: %u key is %.*s", kv_splice_get_size(kv_splice),
		  kv_splice_get_key_size(kv_splice), kv_splice_get_key_offset_in_kv(kv_splice));
	reply->last_splice_offt = reply->size;
	reply->size += kv_splice_get_size(kv_splice);
	++reply->num_kv_pairs;
	return true;
}

uint32_t par_net_scan_rep_get_num_entries(struct par_net_scan_rep *reply)
{
	return reply->num_kv_pairs;
}

bool par_net_scan_rep_seek2_to_first(struct par_net_scan_rep *reply)
{
	if (0 == reply->num_kv_pairs)
		return false;
	reply->curr_splice_offt = 0;
	return true;
}

struct kv_splice *par_net_scan_rep_get_curr_splice(struct par_net_scan_rep *reply)
{
	char *buffer = (char *)reply;
	return (struct kv_splice *)&buffer[sizeof(*reply) + reply->curr_splice_offt];
}

struct kv_splice *par_net_scan_rep_get_last_splice(struct par_net_scan_rep *reply)
{
	char *buffer = (char *)reply;
	return (struct kv_splice *)&buffer[sizeof(*reply) + reply->last_splice_offt];
}

bool par_net_scan_rep_seek2_next_splice(struct par_net_scan_rep *reply)
{
	if (reply->curr_splice_offt >= reply->size) {
		log_debug("No more KV pairs in local buffer");
		return false;
	}
	char *buffer = (char *)reply;
	struct kv_splice *kv_pair =
		(struct kv_splice *)&buffer[sizeof(struct par_net_scan_rep) + reply->curr_splice_offt];

	reply->curr_splice_offt += kv_splice_get_size(kv_pair);

	if (reply->curr_splice_offt >= reply->size) {
		log_debug("No more KV pairs in local buffer");
		return false;
	}

	// log_debug("Current splice offset = %u total size = %u", reply->curr_splice_offt, reply->size);
	return true;
}

struct kv_splice *par_net_scan_rep_get_splice(struct par_net_scan_rep *reply)
{
	char *buffer = (char *)reply;
	return (struct kv_splice *)&buffer[sizeof(*reply) + reply->curr_splice_offt];
}

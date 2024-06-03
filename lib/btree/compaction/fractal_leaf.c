// Copyright [2021] [FORTH-ICS]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include "../btree/kv_pairs.h"
#include "../btree_node.h"
#include "../conf.h"
#include "device_level.h"
#include "parallax/structures.h"
#include <assert.h>
#include <log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef enum {
	FRAC_TAIL_OFFT = 0,
	FRAC_FIRST_SPLICE_OFFT,
	FRAC_PIVOT_TAIL_OFFT,
	FRAC_LEAF_FULL,
	FRAC_BLOCK_ID,
	FRAC_NUM_PIVOTS,
	FRAC_SIZE
} counter_name_e;

struct leaf_node {
	struct node_header header;
	uint64_t next_leaf_offt;
	uint16_t counters[FRAC_SIZE];
} __attribute__((packed));

struct leaf_iterator {
	struct kv_splice_base curr_splice;
	struct leaf_node *leaf;
	uint16_t splice_offt;
};

struct leaf_pivot {
	uint16_t splice_idx;
	uint8_t size;
	unsigned char key[];
} __attribute__((packed));

#define FRAC_BLOCK_SIZE 256UL

static inline void frac_set_leaf_node_type(struct leaf_node *leaf, nodeType_t node_type)
{
	if (NULL == leaf)
		return;
	leaf->header.type = node_type;
}

static uint32_t frac_leaf_get_node_size(struct leaf_node *leaf)
{
	return leaf->header.node_size;
}

void frac_init_leaf(struct leaf_node *leaf, uint32_t leaf_size)
{
	if (NULL == leaf)
		return;

	frac_set_leaf_node_type(leaf, leafNode);
	leaf->header.log_size = leaf_size;
	leaf->header.node_size = leaf_size;

	leaf->counters[FRAC_LEAF_FULL] = 0;
	leaf->counters[FRAC_PIVOT_TAIL_OFFT] = sizeof(struct leaf_node);
	leaf->counters[FRAC_TAIL_OFFT] = LEAF_NODE_SIZE;
	leaf->counters[FRAC_BLOCK_ID] = (leaf->counters[FRAC_TAIL_OFFT] / FRAC_BLOCK_SIZE) - 1;

	leaf->header.num_entries = 0;
	leaf->counters[FRAC_NUM_PIVOTS] = 0;
}

int frac_comparator(const void *key1, const void *key2, int32_t key1_size, int32_t key2_size)
{
	int ret = memcmp(key1, key2, key1_size <= key2_size ? key1_size : key2_size);
	return ret ? ret : key1_size - key2_size;
}

static inline bool frac_get_splice(struct leaf_node *leaf, struct kv_splice_base *splice, uint16_t offt)
{
	char *leaf_buf = (char *)leaf;
	const struct kv_splice_meta *meta = (struct kv_splice_meta *)&leaf_buf[offt];
	splice->kv_cat = kv_meta_get_cat(meta);
	splice->is_tombstone = kv_meta_is_tombstone(meta);
	splice->kv_type = kv_meta_is_kv_format(meta) ? KV_FORMAT : KV_PREFIX;
	if (KV_FORMAT == splice->kv_type)
		splice->kv_splice = (struct kv_splice *)&leaf_buf[offt];
	else
		splice->kv_sep2 = (struct kv_seperation_splice2 *)&leaf_buf[offt];
	return true;
}

/**
 * @brief Seeks a key within a leaf. If it finds a key greater or equal it it
 * fills the splice and returns splice_idx. Additionally, if there is an exact match
 * it fills the exact_match flag appropriately. It returns 0 if no key greater
 * or equal is found.
 * @param leaf pointer to the leaf object
 * @param key pointer to the key object to search for
 * @param key_size size of the key in bytes
 * @param exact_match indicates if we have an exact match or not
 * @param splice pointer to the splice object to be filled
 */
static uint16_t frac_leaf_seek(struct leaf_node *leaf, const char *key, int32_t key_size, bool *exact_match,
			       struct kv_splice_base *splice)
{
	char *leaf_buf = (char *)leaf;

	uint16_t pivot_offt_a = sizeof(struct leaf_node);
	uint16_t pivot_offt_b = 0;

	// uint64_t num_cmp_piv = 0;
	const struct leaf_pivot *pivot = (struct leaf_pivot *)&leaf_buf[pivot_offt_a];
	int ret = 0;
	for (uint32_t i = 0; i < leaf->counters[FRAC_NUM_PIVOTS]; i++) {
		ret = frac_comparator(pivot->key, key, pivot->size, key_size);
		// num_cmp_piv++;
		// log_debug("Comparing pivot_key: %.*s with key: %.*s ret is %d", pivot->size, pivot->key, key_size, key,
		// 	  ret);

		if (ret > 0)
			break;

		if (ret == 0) {
			pivot_offt_b = pivot_offt_a;
			break;
		}

		pivot_offt_b = pivot_offt_a;
		pivot_offt_a += sizeof(struct leaf_pivot) + pivot->size;
		pivot = (struct leaf_pivot *)&leaf_buf[pivot_offt_a];
	}
	uint16_t splice_idx_a = 0 == pivot_offt_b ? leaf->counters[FRAC_FIRST_SPLICE_OFFT] :
						    ((struct leaf_pivot *)(&leaf_buf[pivot_offt_b]))->splice_idx;

	assert(splice_idx_a < frac_leaf_get_node_size(leaf));

	// uint64_t num_cmp_sp = 0;
	/*now continue in kv section*/
	for (; frac_get_splice(leaf, splice, splice_idx_a);) {
		ret = frac_comparator(kv_splice_base_get_key_buf(splice), key, kv_splice_base_get_key_size(splice),
				      key_size);

		// num_cmp_sp++;
		// log_debug("Comparing key: %.*s with splice: %d content: %.*s ret is %d", key_size, key,
		// 	  kv_splice_base_get_key_size(splice), kv_splice_base_get_key_size(splice),
		// 	  kv_splice_base_get_key_buf(splice), ret);

		if (ret > 0)
			break;

		if (ret == 0) {
			*exact_match = true;
			break;
		}
		uint16_t prev_size = kv_meta_get_prev_kv_size(&splice->kv_splice->meta);
		if (prev_size == 0)
			break;
		splice_idx_a -= prev_size;
	}
	// log_debug("Seek pivot total comparisons: %lu splice total comparisons: %lu num pivots: %u", num_cmp_piv,
	// 	  num_cmp_sp, leaf->counters[FRAC_NUM_PIVOTS]);
	return ret < 0 ? 0 : splice_idx_a;
}

struct kv_splice_base frac_find_kv_leaf(struct leaf_node *leaf, const char *key, int32_t key_size, const char **error)
{
	struct kv_splice_base splice = { 0 };
	bool exact_match = false;
	uint16_t splice_idx = frac_leaf_seek(leaf, key, key_size, &exact_match, &splice);
	if (!exact_match)
		*error = "KV pair not found";
	else
		frac_get_splice(leaf, &splice, splice_idx);
	return splice;
}

/**
 * @brief Reports if the leaf can fit the splice with size kv_size.
 * Now in this case we do not calculate the possible pivot that we
 * may need. Later, if we need to add a pivot and there is no space
 * we mark the leaf as full. So, this function first check leaf_is_full
 * flag and then calculates if the kv_size fits.
 * @param leaf pointer to the leaf object
 * @param kv_size size of the kv
 * @return true if the kv fits or false otherwise
 */
static bool frac_is_leaf_full(struct leaf_node *leaf, uint32_t kv_size)
{
	// log_debug("FRAC_TAIL_OFFT: %u FRAC_PIVOT_TAIL_OFFT: %u kv_size: %u", leaf->counters[FRAC_TAIL_OFFT],
	//    leaf->counters[FRAC_PIVOT_TAIL_OFFT], kv_size);
	//  log_debug("Is leaf full from previous round? %s",leaf->counters[FRAC_LEAF_FULL]?"yes":"no");

	if (leaf->counters[FRAC_LEAF_FULL] || (leaf->counters[FRAC_TAIL_OFFT] <= leaf->counters[FRAC_PIVOT_TAIL_OFFT]))
		return true;

	uint32_t remaining_space = leaf->counters[FRAC_TAIL_OFFT] - leaf->counters[FRAC_PIVOT_TAIL_OFFT];
	// if (ret)
	// log_debug("Full leaf num entries are: %u remaing space is %u frac_tail_offt: %u pivot_tail_offt: %u",
	// 	  leaf->header.num_entries,
	// 	  leaf->counters[FRAC_TAIL_OFFT] - leaf->counters[FRAC_PIVOT_TAIL_OFFT],
	// 	  leaf->counters[FRAC_TAIL_OFFT], leaf->counters[FRAC_PIVOT_TAIL_OFFT]);

	return remaining_space < kv_size;
}

static bool frac_create_pivot(struct kv_splice_base *last_splice, struct kv_splice_base *new_splice,
			      struct leaf_pivot *pivot, size_t max_pivot_size)
{
	int32_t key_left_len = kv_splice_base_get_key_size(last_splice);
	const char *key_left = kv_splice_base_get_key_buf(last_splice);
	int32_t key_right_len = kv_splice_base_get_key_size(new_splice);
	const char *key_right = kv_splice_base_get_key_buf(new_splice);
	int32_t min_len = key_left_len < key_right_len ? key_left_len : key_right_len;

	// Find the common prefix length
	int32_t idx = 0;
	for (; idx < min_len && key_left[idx] == key_right[idx]; ++idx)
		;

	if (idx == key_left_len || idx == key_right_len) {
		//just use the new_splice as pivot do not bother
		if (max_pivot_size < kv_splice_base_get_key_size(new_splice) + sizeof(struct leaf_pivot))
			return false;
		pivot->size = kv_splice_base_get_key_size(new_splice);
		memcpy(pivot->key, kv_splice_base_get_key_buf(new_splice), pivot->size);
		return pivot;
	}

	if (max_pivot_size < kv_splice_base_get_key_size(new_splice) + 1 + sizeof(struct leaf_pivot))
		return false;

	pivot->size = idx + 1;
	memcpy(pivot->key, key_left, idx);

	// Add an extra character
	pivot->key[idx] = (key_left[idx] + 1 < key_right[idx]) ? key_left[idx] + 1 : key_right[idx];
	return true;
}

static bool frac_add_pivot(struct leaf_node *leaf, struct kv_splice_base *new_splice, uint16_t max_pivot_size)
{
	char *leaf_buf = (char *)leaf;
	struct leaf_pivot *leaf_pivot = (struct leaf_pivot *)&leaf_buf[leaf->counters[FRAC_PIVOT_TAIL_OFFT]];
	struct kv_splice_base last_splice = { 0 };
	frac_get_splice(leaf, &last_splice, leaf->counters[FRAC_TAIL_OFFT]);

	if (false == frac_create_pivot(&last_splice, new_splice, leaf_pivot, max_pivot_size))
		return false;
	// log_debug("Created pivot of size: %u last_splice was: %.*s new splice: %.*s", leaf_pivot->size,
	// 	  kv_splice_base_get_key_size(&last_splice), kv_splice_base_get_key_buf(&last_splice),
	// 	  kv_splice_base_get_key_size(new_splice), kv_splice_base_get_key_buf(new_splice));
	assert(leaf->counters[FRAC_TAIL_OFFT] != LEAF_NODE_SIZE);
	leaf_pivot->splice_idx = leaf->counters[FRAC_TAIL_OFFT];
	leaf->counters[FRAC_PIVOT_TAIL_OFFT] += sizeof(struct leaf_pivot) + leaf_pivot->size;
	++leaf->counters[FRAC_NUM_PIVOTS];
	return true;
}

inline static enum KV_type frac_calc_category(const struct kv_splice_base *general_splice)
{
	switch (general_splice->kv_cat) {
	case MEDIUM_INLOG:
	case BIG_INLOG:
		return KV_PREFIX;
	case MEDIUM_INPLACE:
	case SMALL_INPLACE:
		return KV_FORMAT;
	default:
		log_fatal("KV category corruption");
		_exit(EXIT_FAILURE);
	}
}
/**
 * @brief Appends a splice in the leaf. Decides if it should also add a pivot or not for it.
 * @param leaf pointer to the leaf object
 * @param general_splice pointer to the splice object
 * @param is_tombstone indicates if the splice is a tombstone or not
 */
bool frac_append_splice_in_leaf(struct leaf_node *leaf, struct kv_splice_base *general_splice, bool is_tombstone)
{
	int32_t kv_size = kv_splice_base_calculate_size(general_splice);
	// log_debug("Kv size is %d",kv_size);
	if (frac_is_leaf_full(leaf, kv_size)) {
		log_warn("Leaf is full cannot serve request");
		return false;
	}
	char *leaf_buf = (char *)leaf;
	char *splice_addr = &leaf_buf[leaf->counters[FRAC_TAIL_OFFT] - kv_size];
	kv_splice_base_serialize(general_splice, splice_addr, kv_size);

	kv_meta_set_tombstone((struct kv_splice_meta *)splice_addr, is_tombstone);
	kv_meta_set_cat((struct kv_splice_meta *)splice_addr, general_splice->kv_cat);
	kv_meta_set_kv_format((struct kv_splice_meta *)splice_addr, frac_calc_category(general_splice) == KV_FORMAT);
	kv_meta_set_prev_kv_size((struct kv_splice_meta *)splice_addr, 0);

	uint32_t block_id = (leaf->counters[FRAC_TAIL_OFFT] - kv_size) / FRAC_BLOCK_SIZE;

	if (leaf->header.num_entries == 0 || block_id == leaf->counters[FRAC_BLOCK_ID])
		goto exit_append;

	// log_debug("Going to add a pivot  curr block id is: %u last block id is: %u", block_id,
	// 	  leaf->counters[FRAC_BLOCK_ID]);

	uint16_t max_pivot_size = (leaf->counters[FRAC_TAIL_OFFT] - kv_size) - leaf->counters[FRAC_PIVOT_TAIL_OFFT];
	if (false == frac_add_pivot(leaf, general_splice, max_pivot_size))
		//failed to add due to space mark as full
		leaf->counters[FRAC_LEAF_FULL] = 1;
	else
		leaf->counters[FRAC_BLOCK_ID] = block_id;

exit_append:
	if (leaf->header.num_entries > 0) {
		splice_addr = &((char *)leaf)[leaf->counters[FRAC_TAIL_OFFT]];
		kv_meta_set_prev_kv_size((struct kv_splice_meta *)splice_addr, kv_size);
	}

	leaf->counters[FRAC_TAIL_OFFT] -= kv_size;

	if (1 == ++leaf->header.num_entries)
		leaf->counters[FRAC_FIRST_SPLICE_OFFT] = leaf->counters[FRAC_TAIL_OFFT];

	// struct kv_splice_base debug;
	// frac_get_splice(leaf, &debug, leaf->counters[FRAC_TAIL_OFFT]);
	// log_debug("Inserted splice of key size: %d content: %.*s", kv_splice_base_get_key_size(&debug),
	// 	  kv_splice_base_get_key_size(&debug), kv_splice_base_get_key_buf(&debug));
	return true;
}

static inline nodeType_t frac_get_leaf_node_type(struct leaf_node *leaf)
{
	return leaf->header.type;
}

static inline int32_t frac_get_leaf_num_entries(struct leaf_node *leaf)
{
	return leaf->header.num_entries;
}

static struct kv_splice_base frac_get_last_splice(struct leaf_node *leaf)
{
	struct kv_splice_base splice = { .kv_type = INT16_MAX };
	if (0 == frac_get_leaf_num_entries(leaf))
		return splice;

	frac_get_splice(leaf, &splice, leaf->counters[FRAC_TAIL_OFFT]);
	return splice;
}

static bool frac_set_next_leaf_offt(struct leaf_node *leaf, uint64_t leaf_offt)
{
	leaf->next_leaf_offt = leaf_offt;
	return true;
}

static uint64_t frac_get_next_leaf_offt(const struct leaf_node *leaf)
{
	return leaf->next_leaf_offt;
}
/*iterators*/
struct leaf_iterator *frac_leaf_create_empty_iter(void)
{
	return calloc(1UL, sizeof(struct leaf_iterator));
}

void frac_leaf_destroy_iter(struct leaf_iterator *iter)
{
	free(iter);
}

bool frac_leaf_iter_first(struct leaf_node *leaf, struct leaf_iterator *iter)
{
	if (0 == frac_get_leaf_num_entries(leaf))
		return false;

	iter->leaf = leaf;
	iter->splice_offt = leaf->counters[FRAC_FIRST_SPLICE_OFFT];
	assert(iter->splice_offt > 0 && iter->splice_offt < LEAF_NODE_SIZE);
	frac_get_splice(iter->leaf, &iter->curr_splice, iter->splice_offt);
	assert(kv_splice_base_get_key_size(&iter->curr_splice) > 0);
	return true;
}

bool frac_leaf_seek_iter(struct leaf_node *leaf, struct leaf_iterator *iter, const char *key, int32_t key_size)
{
	bool exact_match = false;
	iter->leaf = leaf;

	iter->splice_offt = frac_leaf_seek(leaf, key, key_size, &exact_match, &iter->curr_splice);
	// log_debug("Seek for key: %s --> at iter leaf: %p splice_offt = %u we have key: %s", key, (void *)iter->leaf,
	//    iter->splice_offt, kv_splice_base_get_key_buf(&iter->curr_splice));
	return exact_match;
}

bool frac_leaf_is_iter_valid(struct leaf_iterator *iter)
{
	// log_debug("Iter_is_valid: iterator splice offt: %u kv splice tail offt: %u pivot tail offt: %u", iter->splice_offt,
	//    iter->leaf->counters[FRAC_TAIL_OFFT], iter->leaf->counters[FRAC_PIVOT_TAIL_OFFT]);
	assert(iter->splice_offt == 0 ||
	       (iter->splice_offt >= iter->leaf->counters[FRAC_TAIL_OFFT] && iter->splice_offt < LEAF_NODE_SIZE));
	return iter->splice_offt >= iter->leaf->counters[FRAC_TAIL_OFFT];
}

bool frac_leaf_iter_next(struct leaf_iterator *iter)
{
	const struct kv_splice_meta *meta = &iter->curr_splice.kv_splice->meta;

	uint16_t prev_kv_size = kv_meta_get_prev_kv_size(meta);
	// log_debug("Iter_next: Prev kv size is = %u for leaf: %p",prev_kv_size,(void *)iter->leaf);
	if (0 == prev_kv_size) {
		iter->splice_offt = 0;
		return false;
	}

	iter->splice_offt -= kv_meta_get_prev_kv_size(meta);
	if (false == frac_leaf_is_iter_valid(iter))
		return false;

	frac_get_splice(iter->leaf, &iter->curr_splice, iter->splice_offt);
	assert(kv_splice_base_get_key_size(&iter->curr_splice) > 0);
	// log_debug("Next: iter splice_offt = %u we have key: %s", iter->splice_offt,
	// 	  kv_splice_base_get_key_buf(&iter->curr_splice));

	return true;
}

struct kv_splice_base frac_leaf_iter_curr(const struct leaf_iterator *iter)
{
	return iter->curr_splice;
}

// cppcheck-suppress unusedFunction
bool frac_leaf_register(struct level_leaf_api *leaf_api)
{
	leaf_api->leaf_append = frac_append_splice_in_leaf;

	leaf_api->leaf_find = (level_leaf_find)frac_find_kv_leaf;

	leaf_api->leaf_init = frac_init_leaf;

	leaf_api->leaf_is_full = frac_is_leaf_full;

	leaf_api->leaf_set_type = frac_set_leaf_node_type;

	leaf_api->leaf_get_type = frac_get_leaf_node_type;

	leaf_api->leaf_get_entries = frac_get_leaf_num_entries;

	leaf_api->leaf_get_size = frac_leaf_get_node_size;

	leaf_api->leaf_get_last = frac_get_last_splice;

	leaf_api->leaf_set_next_offt = frac_set_next_leaf_offt;

	leaf_api->leaf_get_next_offt = (level_leaf_get_next_leaf_offt)frac_get_next_leaf_offt;
	/*iterator staff*/
	leaf_api->leaf_create_empty_iter = frac_leaf_create_empty_iter;
	leaf_api->leaf_destroy_iter = frac_leaf_destroy_iter;
	leaf_api->leaf_seek_first = frac_leaf_iter_first;
	leaf_api->leaf_seek_iter = (level_leaf_iter_seek)frac_leaf_seek_iter;
	leaf_api->leaf_is_iter_valid = frac_leaf_is_iter_valid;
	leaf_api->leaf_iter_next = frac_leaf_iter_next;
	leaf_api->leaf_iter_curr = (level_leaf_iter_curr)frac_leaf_iter_curr;

	return true;
}

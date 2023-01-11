#include <allocator/volume_manager.h>
#include <assert.h>
#include <btree/btree.h>
#include <btree/dynamic_leaf.h>
#include <btree/key_splice.h>
#include <btree/kv_pairs.h>
#include <log.h>
#include <parallax/structures.h>
#include <stdint.h>
#include <unistd.h>
#include <uthash.h>

/**
 * test_leaf_node randomly generates in place kv_pair and kv_seperated and
 * stores them in a leaf node. Then it 1) verifies their existence 2) splits
 * the leaf into two nodes and verify the existence of the kv pairs and 3)
 * reorganizes the leaf node and checks if all kv pairs are present.
 */
struct kv_splice *tlf_generate_in_place_kv(void)
{
	char key[MAX_KEY_SIZE] = { 0 };
	uint32_t key_size = (rand() % MAX_KEY_SIZE) + 1;
	for (uint32_t i = 0; i < key_size; ++i)
		key[i] = rand() % 255;
	int32_t value_size = rand() % MAX_KEY_SIZE;
	char value[MAX_KEY_SIZE] = { 0 };

	return kv_splice_create(key_size, key, value_size, value);
}

struct kv_seperation_splice2 *tlf_generate_in_log_kv(void)
{
	char key[MAX_KEY_SIZE] = { 0 };
	uint32_t key_size = (rand() % MAX_KEY_SIZE) + 1;
	for (uint32_t i = 0; i < key_size; ++i)
		key[i] = rand() % 255;
	uint64_t value_offt = rand() % UINT64_MAX;
	return kv_sep2_alloc_and_create(key_size, key, value_offt);
}

struct hash_entry {
	struct kv_splice_base hsplice;
	UT_hash_handle hh;
};

static void tlf_fill_key(struct kv_splice_base *pivot, char **key, int32_t *key_size)
{
	if (NULL == pivot) {
		*key = NULL;
		*key_size = -1;
		return;
	}

	if (pivot->cat == SMALL_INPLACE || pivot->cat == MEDIUM_INPLACE) {
		*key = kv_splice_get_key_offset_in_kv(pivot->kv_splice);
		*key_size = kv_splice_get_key_size(pivot->kv_splice);
	}

	if (pivot->cat == BIG_INLOG || pivot->cat == MEDIUM_INLOG) {
		*key = kv_sep2_get_key(pivot->kv_sep2);
		*key_size = kv_sep2_get_key_size(pivot->kv_sep2);
	}
}

static int tlf_compare(struct kv_splice_base *key1_splice, struct kv_splice_base *key2_splice)
{
	char *key1 = NULL;
	int32_t key1_size = 0;
	tlf_fill_key(key1_splice, &key1, &key1_size);
	char *key2 = NULL;
	int32_t key2_size = 0;
	tlf_fill_key(key2_splice, &key2, &key2_size);
	int ret = memcmp(key1, key2, key1_size < key2_size ? key1_size : key2_size);
	return ret ? ret : key1_size - key2_size;
}

enum tlf_group_check { TLF_CHECK_LEFT, TLF_CHECK_RIGHT, TLF_CHECK_ALL };
bool tlf_verify_keys(struct hash_entry *root, struct kv_splice_base *pivot, struct leaf_node *leaf,
		     enum tlf_group_check check)
{
	struct hash_entry *current_entry = NULL;
	struct hash_entry *tmp = NULL;

	char *key = NULL;
	int32_t key_size = 0;
	tlf_fill_key(pivot, &key, &key_size);

	HASH_ITER(hh, root, current_entry, tmp)
	{
		if (!current_entry)
			return false;
		const char *error = NULL;
		if (current_entry->hsplice.cat == SMALL_INPLACE || current_entry->hsplice.cat == MEDIUM_INPLACE) {
			key = kv_splice_get_key_offset_in_kv(current_entry->hsplice.kv_splice);
			key_size = kv_splice_get_key_size(current_entry->hsplice.kv_splice);
		}
		if (current_entry->hsplice.cat == BIG_INLOG || current_entry->hsplice.cat == MEDIUM_INLOG) {
			key = kv_sep2_get_key(current_entry->hsplice.kv_sep2);
			key_size = kv_sep2_get_key_size(current_entry->hsplice.kv_sep2);
		}
		char *index_key = NULL;
		int32_t index_key_size = 0;
		tlf_fill_key(&current_entry->hsplice, &index_key, &index_key_size);
		if (pivot && check == TLF_CHECK_LEFT && tlf_compare(&current_entry->hsplice, pivot) >= 0)
			continue;
		if (pivot && check == TLF_CHECK_RIGHT && tlf_compare(&current_entry->hsplice, pivot) < 0)
			continue;

		dl_find_kv_in_dynamic_leaf(leaf, key, key_size, &error);
		if (NULL != error) {
			log_fatal("Key lookup: %d:%.*s failed with error message: %s", key_size, key_size, key, error);
			assert(0);
			_exit(EXIT_FAILURE);
		}
	}

	return true;
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	struct hash_entry *root = NULL;
	struct leaf_node *leaf = malloc(8192UL);
	dl_init_leaf_node(leaf, 8192UL);
	uint32_t generated_keys_num = 0;

	struct kv_splice_base splice = { 0 };
	while (1) {
		uint32_t choice = generated_keys_num++ % 10;

		if (choice <= 6) {
			splice.kv_splice = tlf_generate_in_place_kv();
			splice.cat = SMALL_INPLACE;
		} else {
			splice.kv_sep2 = tlf_generate_in_log_kv();
			splice.cat = MEDIUM_INLOG;
		}
		bool exact_match = false;
		bool ret = dl_insert_in_dynamic_leaf(leaf, &splice, false, &exact_match);
		if (!ret)
			break;
		struct hash_entry *hentry = calloc(1UL, sizeof(*hentry));
		hentry->hsplice = splice;

		HASH_ADD_PTR(root, hsplice, hentry);
		++generated_keys_num;
	}
	log_info("Inserted %u kv pairs in leaf  now verifying keys...", generated_keys_num);
	tlf_verify_keys(root, NULL, leaf, TLF_CHECK_ALL);
	log_info("All keys found great!");

	struct leaf_node *left = malloc(8192UL);
	dl_init_leaf_node(left, 8192UL);
	struct leaf_node *right = malloc(8192UL);
	dl_init_leaf_node(right, 8192UL);
	struct kv_splice_base pivot_splice = dl_split_dynamic_leaf(leaf, left, right);
	log_debug("Pivot splice is %d", kv_splice_get_key_size(pivot_splice.kv_splice));
	char *pivot = NULL;
	int32_t pivot_size = 0;
	tlf_fill_key(&pivot_splice, &pivot, &pivot_size);
	assert(pivot != NULL);

	log_info("Split done pivot size is %d cat is %d", pivot_size, pivot_splice.cat);
	log_info("Split done actual pivot is %.*s", pivot_size, pivot);

	tlf_verify_keys(root, &pivot_splice, left, TLF_CHECK_LEFT);
	tlf_verify_keys(root, &pivot_splice, right, TLF_CHECK_RIGHT);

	log_info("split leaf ok! found all keys");
	struct leaf_node *reorganized_leaf = malloc(8192UL);
	dl_init_leaf_node(reorganized_leaf, 8192UL);
	dl_reorganize_dynamic_leaf(leaf, reorganized_leaf);
	tlf_verify_keys(root, NULL, reorganized_leaf, TLF_CHECK_ALL);
	log_info("TEST LEAF NODE SUCCESS!!!");
	free(leaf);
	free(left);
	free(right);
	free(reorganized_leaf);
}

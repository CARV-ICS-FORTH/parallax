#include "../lib/btree/kv_pairs.h"
#include "parallax/structures.h"
#include <assert.h>
#include <log.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
struct leaf_node;
#define MAX_KEY_SIZE 35
#define MAX_VALUE_SIZE 8
#define NUM_KEYS 256
#define ASCII_ALPHABET_SIZE 25
#define LEAF_NODE_SIZE 8192UL

extern bool frac_append_splice_in_leaf(struct leaf_node *leaf, struct kv_splice_base *general_splice,
				       bool is_tombstone);
extern void frac_init_leaf(struct leaf_node *leaf, uint32_t leaf_size);
extern struct kv_splice_base frac_find_kv_leaf(struct leaf_node *leaf, char *key, int32_t key_size, const char **error);
extern struct leaf_iterator *frac_leaf_create_empty_iter(void);
extern void frac_leaf_destroy_iter(struct leaf_iterator *iter);
extern bool frac_leaf_iter_first(struct leaf_node *leaf, struct leaf_iterator *iter);
extern bool frac_leaf_seek_iter(struct leaf_node *leaf, struct leaf_iterator *iter, char *key, int32_t key_size);
extern bool frac_leaf_is_iter_valid(struct leaf_iterator *iter);
extern bool frac_leaf_iter_next(struct leaf_iterator *iter);
extern struct kv_splice_base frac_leaf_iter_curr(struct leaf_iterator *iter);

static void generate_random_key(char *key, int max_size)
{
	static char counter1 = 65;
	static char counter2 = 65;
	unsigned int size = rand() % max_size;
	size = size >= 4 ? size : 4;

	for (unsigned int i = 1; i < size - 1; i++)
		key[i] = 65 + (rand() % ASCII_ALPHABET_SIZE);
	if (counter1 > 65 + ASCII_ALPHABET_SIZE) {
		counter1 = 65;
		counter2++;
	}

	if (counter2 > 65 + ASCII_ALPHABET_SIZE)
		counter2 = 65;

	key[0] = counter1++;
	key[1] = counter2;
	key[size - 1] = '\0';
}

// Comparison function for qsort to sort strings
static int compare_strings(const void *key_a, const void *key_b)
{
	return strcmp(key_a, key_b);
}

int main(void)
{
	srand(time(0)); // Seed the random number generator with current time

	char keys[NUM_KEYS][MAX_KEY_SIZE] = { 0 };
	const char value_buf[MAX_VALUE_SIZE] = { 0 };

	for (int i = 0; i < NUM_KEYS; i++) {
		generate_random_key(keys[i], MAX_KEY_SIZE);
		assert(strlen(keys[i]) > 0);
	}
	qsort(keys, NUM_KEYS, MAX_KEY_SIZE, compare_strings);

	log_debug("Sorted keys are:");
	for (int i = 0; i < NUM_KEYS; i++)
		log_debug("key[%d] = %s", i, keys[i]);

	struct leaf_node *leaf = NULL;
	posix_memalign((void **)&leaf, 4096, LEAF_NODE_SIZE);
	frac_init_leaf(leaf, LEAF_NODE_SIZE);

	struct leaf_node *leaf_for_iter = NULL;
	posix_memalign((void **)&leaf_for_iter, 4096, LEAF_NODE_SIZE);
	frac_init_leaf(leaf_for_iter, LEAF_NODE_SIZE);

	// Printing the sorted keys and their corresponding value array size
	struct kv_splice_base splice = { .kv_cat = SMALL_INPLACE, .kv_type = KV_FORMAT };
	int num_keys = 0;
	for (; num_keys < NUM_KEYS; num_keys++) {
		int32_t value_size = rand() % MAX_VALUE_SIZE;
		splice.kv_splice =
			kv_splice_create(strlen(keys[num_keys]) + 1, &keys[num_keys][0], value_size, value_buf);

		if (false == frac_append_splice_in_leaf(leaf, &splice, false)) {
			free(splice.kv_splice);
			break;
		}

		if (num_keys % 2 == 0) {
			log_debug("Inserting key[%d]: %s in leaf_for_iter", num_keys,
				  kv_splice_base_get_key_buf(&splice));
			frac_append_splice_in_leaf(leaf_for_iter, &splice, false);
		}

		free(splice.kv_splice);
	}

	if (0 == num_keys) {
		log_fatal("Failed to insert any key");
		_exit(EXIT_FAILURE);
	}

	log_info("Inserted a total of %d keys in the fractal leaf", num_keys);

	// Set memory region to read-only
	if (mprotect(leaf_for_iter, LEAF_NODE_SIZE, PROT_READ) != 0) {
		perror("Memory protection failed");
		return EXIT_FAILURE;
	}

	for (int i = 0; i < num_keys; i++) {
		const char *error = NULL;
		splice = frac_find_kv_leaf(leaf, keys[i], strlen(keys[i]) + 1, &error);
		if (error) {
			log_fatal("Test failed key: %s not found!", keys[i]);
			_exit(EXIT_FAILURE);
		}
	}

	log_info("All GETS successful now testing iterators...");

	struct leaf_iterator *iter = frac_leaf_create_empty_iter();
	for (int seek_id = 0; seek_id < num_keys; seek_id += 2) {
		log_debug("<seek> no: %d out of %d num keys", seek_id, num_keys);
		frac_leaf_seek_iter(leaf_for_iter, iter, keys[seek_id], strlen(keys[seek_id]) + 1);
		// if (found) {
		// 	log_fatal("Key[%d] %s found it shouldn't!", seek_id, keys[seek_id]);
		// 	_exit(EXIT_FAILURE);
		// }

		int kv_id = seek_id;
		if (kv_id >= num_keys)
			goto done;
		do {
			if (false == frac_leaf_is_iter_valid(iter)) {
				log_fatal("Invalid iterator too soon! end at %d num_keys: %d ", kv_id, num_keys);
				_exit(EXIT_FAILURE);
			}
			splice = frac_leaf_iter_curr(iter);
			if (0 != strcmp(kv_splice_base_get_key_buf(&splice), keys[kv_id])) {
				log_fatal("key[%d] = %s not found instead got: key size: %d content: %s value size: %d",
					  kv_id, keys[kv_id], kv_splice_base_get_key_size(&splice),
					  kv_splice_base_get_key_buf(&splice), kv_splice_base_get_value_size(&splice));
				_exit(EXIT_FAILURE);
			}
			log_debug("Great! found key: %s", keys[kv_id]);
			frac_leaf_iter_next(iter);

			kv_id += 2;

		} while (kv_id < num_keys);
		log_debug("</seek>");
	}
done:
	log_info("Success TEST FRACTAL!");
	return 0;
}

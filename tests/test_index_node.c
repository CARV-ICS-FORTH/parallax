#define ALPHABET_SIZE 26
#define MAX_PIVOT_KEY_SIZE 200
#define MAX_NODE_KEYS_NUM 500
#define PIVOT_BASE 1000

#include "../lib/btree/index_node.h"
#include "arg_parser.h"
#include <assert.h>
#include <log.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

enum pivot_generation_style { ASCENDING = 1, DESCENDING, RANDOM };

static void create_pivot(struct pivot_key *pivot, uint32_t pivot_num, const unsigned char *alphabet,
			 uint32_t alphabet_size)
{
	sprintf(pivot->data, "%u", pivot_num);
	uint32_t prefix_size = strlen(pivot->data);
	pivot->size = (rand() % MAX_PIVOT_KEY_SIZE);

	if (pivot->size <= prefix_size)
		pivot->size = prefix_size + 1;

	for (uint32_t i = prefix_size; i < pivot->size; ++i) {
		pivot->data[i] = alphabet[rand() % alphabet_size];
	}
}

static void verify_pivots(struct index_node *node, struct pivot_key **pivot, uint32_t num_node_keys, uint32_t base)
{
	/*
   * Verify that you can find all keys and their respective children are
   * correct
  */
	struct pivot_key *guard = calloc(1, sizeof(struct pivot_key) + MAX_PIVOT_KEY_SIZE);
	guard->size = 1;
	guard->data[0] = 0x00;

	uint64_t child_offt = index_binary_search(node, guard, KV_FORMAT);
	uint64_t expected_value = base;
	if (child_offt != expected_value) {
		log_fatal("i = %u Child offt corrupted shoud be %lu but its value is %lu", 0, expected_value,
			  child_offt);
		assert(0);
	}

	for (uint32_t i = 0; i < num_node_keys; ++i) {
		//log_debug("Look up key is %.*s", pivot[i]->size, pivot[i]->data);
		child_offt = index_binary_search(node, pivot[i], KV_FORMAT);
		expected_value = base + i + 1;
		//log_debug("i = %u expected %lu got %lu lookup key %.*s", i, expected_value, child_offt, pivot[i]->size,
		//	  pivot[i]->data);
		if (child_offt != expected_value) {
			log_fatal("i = %u Child offt corrupted shoud be %lu but its value is %lu", i, expected_value,
				  child_offt);
			assert(0);
		}
	}
	free(guard);
}

static uint32_t insert_and_verify_pivots(db_handle *handle, unsigned char *alphabet, uint32_t size)
{
	struct pivot_key **pivot = calloc(MAX_NODE_KEYS_NUM, sizeof(struct pivot_key *));

	/*Create pivots counter as prefix random size and body*/
	for (uint32_t i = 0; i < MAX_NODE_KEYS_NUM; ++i) {
		pivot[i] = calloc(1, sizeof(struct pivot_key) + MAX_PIVOT_KEY_SIZE);

		create_pivot(pivot[i], PIVOT_BASE + i, alphabet, size);
		//log_debug("Created pivot key size %u %.*s", pivot[i]->size, pivot[i]->size, pivot[i]->data);
	}

	/*insert in ascending order*/
	struct index_node *node = NULL;
	posix_memalign((void **)&node, 4096, INDEX_NODE_SIZE);

	index_init_node(ADD_GUARD, node, internalNode);
	uint32_t num_node_keys = 0;
	for (num_node_keys = 0; num_node_keys < MAX_NODE_KEYS_NUM; ++num_node_keys) {
		struct pivot_pointer left_child = { .child_offt = (uint64_t)PIVOT_BASE + num_node_keys };
		struct pivot_pointer right_child = { .child_offt = (uint64_t)PIVOT_BASE + num_node_keys + 1 };

		if (index_insert_pivot(node, &left_child, pivot[num_node_keys], &right_child)) {
			log_info(
				"Failed to insert pivot %.*s after %u pivots because node is full don't worry proceeding to the next step",
				pivot[num_node_keys]->size, pivot[num_node_keys]->data, num_node_keys);
			break;
		}
		//log_debug("Success inserting %.*s", pivot[num_node_keys]->size, pivot[num_node_keys]->data);
	}

	verify_pivots(node, pivot, num_node_keys, PIVOT_BASE);
	log_info("Success insert pivots with ascending order test!");
	log_info("Testing now with descending order...");

	index_init_node(ADD_GUARD, node, internalNode);

	for (int32_t i = (int32_t)num_node_keys - 1; i >= 0; --i) {
		struct pivot_pointer left_child = { .child_offt = (uint64_t)PIVOT_BASE + i };
		struct pivot_pointer right_child = { .child_offt = (uint64_t)PIVOT_BASE + i + 1 };

		//log_debug("Descending order %u pivot %.*s", i, pivot[i]->size, pivot[i]->data);
		assert(pivot[i]->size < 250);

		if (index_insert_pivot(node, &left_child, pivot[i], &right_child)) {
			log_fatal("Capacity is known from the previous step this should not happen");
			_exit(EXIT_FAILURE);
		}
	}

	verify_pivots(node, pivot, num_node_keys, PIVOT_BASE);
	log_info("Success insert pivots with descending order test!");

	log_info("Now testing splits ...");

	bt_insert_req ins_req = { 0 };
	ins_req.metadata.handle = handle;
	struct bt_rebalance_result split_res = index_split_node(node, &ins_req);

	log_info("Testing left child... num entries: %d", split_res.left_child->num_entries);
	verify_pivots((struct index_node *)split_res.left_child, pivot, split_res.left_child->num_entries - 1,
		      PIVOT_BASE);
	log_info("Left child is fine!");

	log_info("Testing right child...");
	verify_pivots((struct index_node *)split_res.right_child, &pivot[split_res.left_child->num_entries],
		      split_res.right_child->num_entries - 1, PIVOT_BASE + split_res.left_child->num_entries);
	log_info("Right child is fine!");

	log_info("Split node success!");

	for (uint32_t i = 0; i < MAX_NODE_KEYS_NUM; ++i)
		free(pivot[i]);

	free(pivot);
	free(node);
	return num_node_keys;
}

int main(int argc, char *argv[])
{
	int help_flag = 0;
	struct wrap_option options[] = {
		{ { "help", no_argument, &help_flag, 1 }, "Prints valid arguments for test_medium.", NULL, INTEGER },
		{ { "file", required_argument, 0, 'a' },
		  "--file=path to file of db, parameter that specifies the target where parallax is going to run.",
		  NULL,
		  STRING },
		{ { 0, 0, 0, 0 }, "End of arguments", NULL, INTEGER }
	};
	unsigned options_len = (sizeof(options) / sizeof(struct wrap_option));
	arg_parse(argc, argv, options, options_len);
	arg_print_options(help_flag, options, options_len);

	db_handle *handle = db_open(get_option(options, 1), 0, UINT64_MAX, "redo_undo_test", CREATE_DB);
	unsigned char *alphabet = calloc(ALPHABET_SIZE, sizeof(char));
	alphabet[0] = 'A';

	for (uint32_t i = 1; i < ALPHABET_SIZE; ++i)
		alphabet[i] = alphabet[i - 1] + 1;

	insert_and_verify_pivots(handle, alphabet, ALPHABET_SIZE);
	free(alphabet);
}

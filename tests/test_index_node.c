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

/**
  * This test takes as input the volume path and tests the following
  * scenarions: 1) Insert all pivots in ascending order and verify correctness.
  * 2) Insert all pivots in descending order and verify correctness. 3) Split
  * index_node and check correctness for its children.
**/

#include "arg_parser.h"
#include "btree/key_splice.h"
#include <assert.h>
#include <btree/btree.h>
#include <btree/index_node.h>
#include <btree/segment_allocator.h>
#include <log.h>
#include <parallax/parallax.h>
#include <parallax/structures.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define ALPHABET_SIZE 26
#define MAX_PIVOT_KEY_SIZE 200
#define MAX_NODE_KEYS_NUM 500
#define PIVOT_BASE 1000

enum pivot_generation_style { ASCENDING = 1, DESCENDING, RANDOM };

static struct key_splice *create_pivot(char *pivot_buf, int pivot_buf_size, const unsigned char *alphabet,
				       uint32_t pivot_num, uint32_t alphabet_size)
{
	char pivot_data[256] = { 0 };
	if (snprintf(pivot_data, sizeof(pivot_data), "%u", pivot_num) < 0) {
		log_fatal("Failed to create pivot");
		_exit(EXIT_FAILURE);
	}
	bool malloced = false;

	int32_t prefix_size = strlen(pivot_data);
	int pivot_size = (rand() % MAX_PIVOT_KEY_SIZE);

	if (pivot_size <= prefix_size)
		pivot_size = prefix_size + 1;

	for (int32_t i = prefix_size; i < pivot_size; ++i) {
		pivot_data[i] = alphabet[rand() % alphabet_size];
	}
	struct key_splice *new_key_splice =
		key_splice_create(pivot_data, pivot_size, pivot_buf, pivot_buf_size, &malloced);
	if (malloced) {
		log_fatal("Buffer is not large enough");
		_exit(EXIT_FAILURE);
	}
	// log_debug("Created key with size %d and data %.*s", key_splice_get_key_size(new_key_splice),
	// 	  key_splice_get_key_size(new_key_splice), key_splice_get_key_offset(new_key_splice));
	return new_key_splice;
}

static void verify_pivots(struct index_node *node, struct key_splice **pivot_splice, uint32_t num_node_keys,
			  uint32_t base)
{
	/*
   * Verify that you can find all keys and their respective children are
   * correct
  */
	char guard_buf[256] = { 0 };
	bool malloced = false;
	struct key_splice *guard_splice = key_splice_create_smallest(guard_buf, sizeof guard_buf, &malloced);
	if (malloced) {
		log_fatal("Buffer not large enough");
		_exit(EXIT_FAILURE);
	}

	uint64_t child_offt = index_binary_search(node, key_splice_get_key_offset(guard_splice),
						  key_splice_get_key_size(guard_splice));
	uint64_t expected_value = base;
	if (child_offt != expected_value) {
		log_fatal("i = %u Child offt corrupted should be %lu but its value is %lu", 0, expected_value,
			  child_offt);
		_exit(EXIT_FAILURE);
	}

	for (uint32_t i = 0; i < num_node_keys; ++i) {
		//log_debug("Look up key is %.*s", pivot[i]->size, pivot[i]->data);
		child_offt = index_binary_search(node, key_splice_get_key_offset(pivot_splice[i]),
						 key_splice_get_key_size(pivot_splice[i]));
		expected_value = base + i + 1;
		//log_debug("i = %u expected %lu got %lu lookup key %.*s", i, expected_value, child_offt, pivot[i]->size,
		//	  pivot[i]->data);
		if (child_offt != expected_value) {
			log_fatal("i = %u Child offt corrupted shoud be %lu but its value is %lu", i, expected_value,
				  child_offt);
			_exit(EXIT_FAILURE);
		}
	}
}

static uint32_t insert_and_verify_pivots(db_handle *handle, const unsigned char *alphabet, uint32_t size)
{
	struct key_splice **pivot = calloc(MAX_NODE_KEYS_NUM, sizeof(struct key_splice *));

	/*Create pivots counter as prefix random size and body*/
	for (uint32_t i = 0; i < MAX_NODE_KEYS_NUM; ++i) {
		pivot[i] = calloc(1UL, 512);
		pivot[i] = create_pivot((char *)pivot[i], 512, alphabet, PIVOT_BASE + i, size);

		// log_debug("Created pivot key size %u %.*s", key_splice_get_key_size(pivot[i]),
		// 	  key_splice_get_key_size(pivot[i]), key_splice_get_key_offset(pivot[i]));
	}

	/*insert in ascending order*/
	struct index_node *node = NULL;
	posix_memalign((void **)&node, 4096, index_node_get_size());

	index_init_node(ADD_GUARD, node, internalNode);
	uint32_t num_node_keys = 0;
	for (num_node_keys = 0; num_node_keys < MAX_NODE_KEYS_NUM; ++num_node_keys) {
		struct pivot_pointer left_child = { .child_offt = (uint64_t)PIVOT_BASE + num_node_keys };
		struct pivot_pointer right_child = { .child_offt = (uint64_t)PIVOT_BASE + num_node_keys + 1 };

		struct insert_pivot_req ins_pivot_req = { .node = node,
							  .left_child = &left_child,
							  .key_splice = pivot[num_node_keys],
							  .right_child = &right_child };
		log_debug("Inserting pivot key size %u %.*s", key_splice_get_key_size(pivot[num_node_keys]),
			  key_splice_get_key_size(pivot[num_node_keys]),
			  key_splice_get_key_offset(pivot[num_node_keys]));
		if (!index_insert_pivot(&ins_pivot_req)) {
			log_warn(
				"Failed to insert pivot %.*s after %u pivots because node is full don't worry proceeding to the next step",
				key_splice_get_key_size((struct key_splice *)pivot[num_node_keys]),
				key_splice_get_key_offset((struct key_splice *)pivot[num_node_keys]), num_node_keys);
			break;
		}
		log_debug("Success inserting key size %u %.*s", key_splice_get_key_size(pivot[num_node_keys]),
			  key_splice_get_key_size(pivot[num_node_keys]),
			  key_splice_get_key_offset(pivot[num_node_keys]));
	}

	verify_pivots(node, pivot, num_node_keys, PIVOT_BASE);
	log_info("Success insert pivots with ascending order test!");
	log_info("Testing now with descending order...");

	index_init_node(ADD_GUARD, node, internalNode);

	for (int32_t i = (int32_t)num_node_keys - 1; i >= 0; --i) {
		struct pivot_pointer left_child = { .child_offt = (uint64_t)PIVOT_BASE + i };
		struct pivot_pointer right_child = { .child_offt = (uint64_t)PIVOT_BASE + i + 1 };

		//log_debug("Descending order %u pivot %.*s", i, pivot[i]->size, pivot[i]->data);
		assert(key_splice_get_key_size(pivot[i]) < 250);

		struct insert_pivot_req ins_pivot_req = {
			.node = node, .left_child = &left_child, .key_splice = pivot[i], .right_child = &right_child
		};
		if (!index_insert_pivot(&ins_pivot_req)) {
			log_fatal("Capacity is known from the previous step this should not happen");
			_exit(EXIT_FAILURE);
		}
	}

	verify_pivots(node, pivot, num_node_keys, PIVOT_BASE);
	log_info("Success insert pivots with descending order test!");

	log_info("Now testing iterators");
	struct index_node_iterator *index_iterator =
		(struct index_node_iterator *)calloc(1, sizeof(struct index_node_iterator));
	index_iterator_init(node, index_iterator);
	uint32_t num_of_pivots_found_with_iter = 0; //1 for the starting position
	while (index_iterator_next(index_iterator))
		++num_of_pivots_found_with_iter;

	if (num_of_pivots_found_with_iter != num_node_keys) {
		log_fatal("Index iterator found %u pivots out of %u", num_of_pivots_found_with_iter, num_node_keys);
		assert(0);
		_exit(EXIT_FAILURE);
	}

	log_info("Success finding all pivots with and index iterator");

	log_info("Now testing splits ...");

	struct bt_rebalance_result split_res = {
		.left_child = (struct node_header *)seg_get_index_node(handle->db_desc, 0, 0, 0),
		.right_child = (struct node_header *)seg_get_index_node(handle->db_desc, 0, 0, 0)
	};
	struct index_node_split_request request = { .node = node,
						    .left_child = (struct index_node *)split_res.left_child,
						    .right_child = (struct index_node *)split_res.right_child };
	struct index_node_split_reply reply = { .pivot_buf = split_res.middle_key,
						.pivot_buf_size = MAX_KEY_SPLICE_SIZE };

	index_split_node(&request, &reply);

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

	const char *error_message = NULL;
	char *volume_name = get_option(options, 1);
	char *db_name = "redo_undo_test";
	struct par_options_desc *default_options = par_get_default_options();
	struct par_db_options db_options = {
		.volume_name = volume_name,
		.db_name = db_name,
		.create_flag = PAR_CREATE_DB,
		default_options,
	};
	db_handle *handle = db_open(&db_options, &error_message);
	unsigned char *alphabet = calloc(ALPHABET_SIZE, sizeof(char));
	char letter = 'A';
	for (uint32_t i = 0; i < ALPHABET_SIZE; ++i)
		alphabet[i] = letter++;

	insert_and_verify_pivots(handle, alphabet, ALPHABET_SIZE);
	free(alphabet);
}

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

#include "arg_parser.h"
#include "btree/gc.h"
#include "parallax/parallax.h"
#include "parallax/structures.h"
#include <allocator/persistent_operations.h>
#include <allocator/region_log.h>
#include <allocator/volume_manager.h>
#include <btree/btree.h>
#include <common/common.h>
#include <fcntl.h>
#include <log.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#define REGL_TRANSACTION_SIZE (2048)
#define REGL_TRANSACTION_NUM (512)
#define GARBAGE_BYTES 128

struct rul_worker_arg {
	struct db_descriptor *db_desc;
};

static void *rul_worker(void *args)
{
	struct rul_worker_arg *my_args = (struct rul_worker_arg *)args;
	struct db_descriptor *db_desc = my_args->db_desc;

	uint64_t dev_offt = 0;
	uint64_t fake_dev_offt = 1;

	for (uint32_t i = 0; i < REGL_TRANSACTION_NUM; ++i) {
		uint64_t txn_id = regl_start_txn(db_desc);
		//log_info("Starting trans %lu", my_txn_id);
		for (uint32_t j = 0; j < REGL_TRANSACTION_SIZE; ++j) {
			struct regl_log_entry log_entry = { 0 };
			log_entry.size = SEGMENT_SIZE;
			log_entry.txn_id = txn_id;
			if (0 == j % 3) {
				dev_offt = mem_allocate(db_desc->db_volume, SEGMENT_SIZE);
				if (0 == dev_offt) {
					log_fatal(
						"Ok device is out space no worries increase the size to pass the test");
					_exit(EXIT_FAILURE);
				}
				log_entry.dev_offt = dev_offt;
				log_entry.op_type = REGL_LARGE_LOG_ALLOCATE;
			} else if (1 == j % 3) {
				mem_free_segment(db_desc->db_volume, dev_offt);
				log_entry.dev_offt = dev_offt;
				log_entry.op_type = REGL_FREE;
			} else {
				log_entry.dev_offt = fake_dev_offt++;
				log_entry.op_type = BLOB_GARBAGE_BYTES;
				log_entry.blob_garbage_bytes = GARBAGE_BYTES;
			}
			regl_add_entry_in_txn_buf(db_desc, &log_entry);
		}

		pr_lock_db_superblock(db_desc);
		struct regl_log_info rul_log = regl_flush_txn(db_desc, txn_id);

		db_desc->db_superblock->allocation_log.head_dev_offt = rul_log.head_dev_offt;
		db_desc->db_superblock->allocation_log.tail_dev_offt = rul_log.tail_dev_offt;
		db_desc->db_superblock->allocation_log.size = rul_log.size;
		db_desc->db_superblock->allocation_log.txn_id = rul_log.txn_id;
		pr_flush_db_superblock(db_desc);
		pr_unlock_db_superblock(db_desc);
	}
	return NULL;
}

uint32_t count_entries(void)
{
	uint32_t count = 0;
	for (uint32_t i = 0; i < REGL_TRANSACTION_NUM; ++i)
		for (uint32_t j = 0; j < REGL_TRANSACTION_SIZE; ++j)
			if (2 == j % 3)
				++count;

	return count;
}

void *validate_blobs_garbage_bytes(void *args)
{
	uint32_t num_threads = *(int *)args;
	uint32_t garbage_entries;
	uint32_t garbage_bytes;

	while (!get_garbage_entries())
		;
	while (!get_garbage_bytes())
		;
	garbage_entries = get_garbage_entries();
	garbage_bytes = get_garbage_bytes();

	if (count_entries() != garbage_entries) {
		log_fatal("fatal inserted garbage entries do not match with recovered entries expected %u got %u",
			  count_entries(), garbage_entries);
		BUG_ON();
	}

	uint32_t expected_garbage_bytes = count_entries() * GARBAGE_BYTES * num_threads;
	if (garbage_bytes != expected_garbage_bytes) {
		log_fatal("fatal inserted garbage bytes do not match with recovered bytes expected %u got %u",
			  expected_garbage_bytes, garbage_bytes);
	}

	pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
	uint32_t num_threads = 0;
	int help_flag = 0;
	struct wrap_option options[] = {
		{ { "help", no_argument, &help_flag, 1 }, "Prints valid arguments for test_medium.", NULL, INTEGER },
		{ { "file", required_argument, 0, 'a' },
		  "--file=path to file of db, parameter that specifies the target where parallax is going to run.",
		  NULL,
		  STRING },
		{ { "num_threads", required_argument, 0, 'a' },
		  "--num_threads=<int> number of threads to spawn to run the test.",
		  NULL,
		  INTEGER },
		{ { 0, 0, 0, 0 }, "End of arguments", NULL, INTEGER }
	};
	unsigned options_len = (sizeof(options) / sizeof(struct wrap_option));
	arg_parse(argc, argv, options, options_len);
	arg_print_options(help_flag, options, options_len);
	log_info("Configuration is :");

	log_info("RUL_LOG_CHUNK_NUM = %lu", REGL_LOG_CHUNK_NUM);
	log_info("RUL_SEGMENT_FOOTER_SIZE_IN_BYTES = %lu", REGL_SEGMENT_FOOTER_SIZE_IN_BYTES);
	log_info("RUL_LOG_CHUNK_SIZE_IN_BYTES = %lu", REGL_LOG_CHUNK_SIZE_IN_BYTES);
	log_info("RUL_LOG_CHUNK_MAX_ENTRIES = %lu", REGL_LOG_CHUNK_MAX_ENTRIES);
	log_info("RUL_SEGMENT_MAX_ENTRIES = %lu", REGL_SEGMENT_MAX_ENTRIES);

	disable_gc();
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
	par_handle handle = par_open(&db_options, &error_message);
	if (error_message) {
		log_fatal("%s", error_message);
		return EXIT_FAILURE;
	}

	struct rul_worker_arg args;
	args.db_desc = ((struct db_handle *)handle)->db_desc;
	num_threads = *(int *)get_option(options, 2);
	pthread_t workers[num_threads];
	for (uint32_t i = 0; i < num_threads; ++i) {
		if (pthread_create(&workers[i], NULL, rul_worker, &args) != 0) {
			log_fatal("Failed to create worker");
			BUG_ON();
		}
	}

	for (uint32_t i = 0; i < num_threads; ++i)
		pthread_join(workers[i], NULL);

	log_info("Test done closing DB");
	error_message = par_close(handle);
	if (error_message != NULL) {
		log_fatal("error message from par_close: %s", error_message);
		exit(EXIT_FAILURE);
	}

	pthread_t validator_thread;
	if (pthread_create(&validator_thread, NULL, validate_blobs_garbage_bytes, &num_threads) != 0) {
		log_fatal("Failed to create worker");
		BUG_ON();
	}

	enable_validation_garbage_bytes();
	handle = db_open(&db_options, &error_message);
	if (error_message) {
		log_fatal("%s", error_message);
		return EXIT_FAILURE;
	}
	pthread_join(validator_thread, NULL);
	error_message = par_close(handle);
	if (error_message != NULL) {
		log_fatal("error message from par_close: %s", error_message);
		exit(EXIT_FAILURE);
	}
	disable_validation_garbage_bytes();

	return 0;
}

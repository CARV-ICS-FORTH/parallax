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

#include "../lib/allocator/redo_undo_log.h"
#include "../lib/allocator/volume_manager.h"
#include "../lib/btree/btree.h"
#include "arg_parser.h"
#include <fcntl.h>
#include <log.h>
#include <pthread.h>
#include <stdlib.h>

#define RUL_TRANSACTION_SIZE (3457)
#define RUL_TRANSACTION_NUM (1239)

struct rul_worker_arg {
	struct db_descriptor *db_desc;
};

static void *rul_worker(void *args)
{
	struct rul_worker_arg *my_args = (struct rul_worker_arg *)args;
	struct db_descriptor *db_desc = my_args->db_desc;

	uint64_t dev_offt = 0;
	for (uint32_t i = 0; i < RUL_TRANSACTION_NUM; ++i) {
		uint64_t my_txn_id = rul_start_txn(db_desc);
		//log_info("Starting trans %lu", my_txn_id);
		for (uint32_t j = 0; j < RUL_TRANSACTION_SIZE; ++j) {
			struct rul_log_entry log_entry = { 0 };
			log_entry.size = SEGMENT_SIZE;
			log_entry.txn_id = my_txn_id;
			if (0 == j % 2) {
				dev_offt = mem_allocate(db_desc->db_volume, SEGMENT_SIZE);
				log_entry.dev_offt = dev_offt;
				log_entry.op_type = RUL_LARGE_LOG_ALLOCATE;
			} else {
				mem_free_segment(db_desc->db_volume, dev_offt);
				log_entry.dev_offt = dev_offt;
				log_entry.op_type = RUL_FREE;
			}
			rul_add_entry_in_txn_buf(db_desc, &log_entry);
		}

		pr_lock_db_superblock(db_desc);
		struct rul_log_info rul_log = rul_flush_txn(db_desc, my_txn_id);

		db_desc->db_superblock->allocation_log.head_dev_offt = rul_log.head_dev_offt;
		db_desc->db_superblock->allocation_log.tail_dev_offt = rul_log.tail_dev_offt;
		db_desc->db_superblock->allocation_log.size = rul_log.size;
		db_desc->db_superblock->allocation_log.txn_id = rul_log.txn_id;
		pr_flush_db_superblock(db_desc);
		pr_unlock_db_superblock(db_desc);
	}
	return NULL;
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

	log_info("RUL_LOG_CHUNK_NUM = %u", RUL_LOG_CHUNK_NUM);
	log_info("RUL_SEGMENT_FOOTER_SIZE_IN_BYTES = %u", RUL_SEGMENT_FOOTER_SIZE_IN_BYTES);
	log_info("RUL_LOG_CHUNK_SIZE_IN_BYTES = %u", RUL_LOG_CHUNK_SIZE_IN_BYTES);
	log_info("RUL_LOG_CHUNK_MAX_ENTRIES = %lu", RUL_LOG_CHUNK_MAX_ENTRIES);
	log_info("RUL_SEGMENT_MAX_ENTRIES = %lu", RUL_SEGMENT_MAX_ENTRIES);

	db_handle *handle = db_open(get_option(options, 1), 0, UINT64_MAX, "redo_undo_test", CREATE_DB);

	struct rul_worker_arg args;
	args.db_desc = handle->db_desc;
	num_threads = *(uint32_t *)get_option(options, 2);
	pthread_t workers[num_threads];
	for (uint32_t i = 0; i < num_threads; ++i) {
		if (pthread_create(&workers[i], NULL, rul_worker, &args) != 0) {
			log_fatal("Failed to create worker");
			_Exit(EXIT_FAILURE);
		}
	}

	for (uint32_t i = 0; i < num_threads; ++i)
		pthread_join(workers[i], NULL);

	log_info("Test done closing DB");
	db_close(handle);

	handle = db_open(get_option(options, 1), 0, UINT64_MAX, "redo_undo_test", CREATE_DB);
	db_close(handle);

	return 0;
}

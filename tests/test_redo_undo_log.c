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
#include <fcntl.h>
#include <log.h>
#include <pthread.h>
#include <stdlib.h>

#define RUL_MAX_TRANS_SIZE 32
#define RUL_TRANS_PER_WORKER 1024
#define RUL_NUM_THREADS 1

struct rul_worker_arg {
	struct db_descriptor *db_desc;
};

static uint64_t bytes_allocated = 0;

static void *rul_worker(void *args)
{
	struct rul_worker_arg *my_args = (struct rul_worker_arg *)args;
	struct db_descriptor *db_desc = my_args->db_desc;

	for (uint32_t i = 0; i < RUL_TRANS_PER_WORKER; ++i) {
		uint64_t my_txn_id = rul_start_txn(db_desc);
		log_info("Starting trans %llu", my_txn_id);
		uint32_t trans_length = rand() % RUL_MAX_TRANS_SIZE;
		struct rul_log_entry log_entry;

		for (uint32_t j = 0; j < trans_length; ++j) {
			uint64_t dev_offt = mem_allocate(db_desc->db_volume, SEGMENT_SIZE);
			log_entry.txn_id = my_txn_id;
			log_entry.dev_offt = dev_offt;
			log_entry.op_type = RUL_ALLOCATE;
			log_entry.size = SEGMENT_SIZE;

			rul_add_entry_in_txn_buf(db_desc, &log_entry);
			__sync_fetch_and_add(&bytes_allocated, SEGMENT_SIZE);
		}
		log_info("Commiting transaction %llu", my_txn_id);
		rul_flush_txn(db_desc, my_txn_id);
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		log_fatal("Wrong number of arguments, Usage: ./test_redo_undo_log <file name>");
		exit(EXIT_FAILURE);
	}

	log_info("Opening volume %s", argv[1]);
	struct volume_descriptor *volume_desc = mem_get_volume_desc(argv[1]);

	struct db_descriptor *db_desc;
	int ret = posix_memalign((void **)&db_desc, ALIGNMENT_SIZE, sizeof(struct db_descriptor));
	if (ret) {
		log_fatal("Failed to allocate db_descriptor");
		exit(EXIT_FAILURE);
	}

	db_desc->db_volume = volume_desc;
	pr_read_db_superblock(db_desc);
	rul_log_init(db_desc);
	log_info("Initialized redo undo log curr segment entry %llu", db_desc->allocation_log->curr_segment_entry);

	log_info("Initialized redo undo log successfully!, starting %d workers", RUL_NUM_THREADS);

	struct rul_worker_arg args;
	args.db_desc = db_desc;
	pthread_t workers[RUL_NUM_THREADS];
	for (uint32_t i = 0; i < RUL_NUM_THREADS; ++i) {
		if (pthread_create(&workers[i], NULL, rul_worker, &args) != 0) {
			log_fatal("Faile to create worker");
			exit(EXIT_FAILURE);
		}
	}

	for (uint32_t i = 0; i < RUL_NUM_THREADS; ++i)
		pthread_join(workers[i], NULL);
	log_info("Writing phase done now verifying the outcome...");

	return 1;
}

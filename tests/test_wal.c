#include "../lib/btree/btree.h"
#include "allocator/redo_undo_log.h"
#include "btree/kv_pairs.h"
#include "parallax/parallax.h"
#include "parallax/structures.h"
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#define KEY "userakias"
const char small_value[33];
const char medium_value[128];
const char large_value[1024];
const char *const value[3] = { small_value, medium_value, large_value };
const size_t sizes[3] = { 33, 128, 1024 };
#define CHECK(X)                             \
	do {                                 \
		if ((X) < 0) {               \
			_exit(EXIT_FAILURE); \
		}                            \
	} while (0)

struct bench_info {
	db_handle **dbs;
	uint64_t *txn_ids;
	uint64_t num_dbs;
	uint64_t num_kv_pairs;
	uint32_t num_threads;
};

struct thr_args {
	struct bench_info *bench_info;
};

static unsigned long long get_tsc(void)
{
	unsigned int low;
	unsigned int high;
	__asm__ volatile("rdtsc" : "=a"(low), "=d"(high));
	return ((unsigned long long)high << 32) | low;
}

static void *do_wal_IO(void *arg)
{
	struct thr_args *thr_args = (struct thr_args *)arg;
	char splice_buf[4096];
	size_t key_size = strlen(KEY) + 1;

	uint64_t num_kv_pairs = thr_args->bench_info->num_kv_pairs / thr_args->bench_info->num_threads;
	CHECK(fprintf(stderr, "Going to perform %lu append operations in Parallax WAL\n",
		      thr_args->bench_info->num_kv_pairs / thr_args->bench_info->num_threads));

	for (uint64_t kv_id = 0; kv_id < num_kv_pairs; ++kv_id) {
		uint64_t idx = get_tsc() % 3;
		uint64_t db_id = get_tsc() % thr_args->bench_info->num_dbs;

		struct kv_splice *kv_splice = (struct kv_splice *)splice_buf;
		kv_splice_set_key(kv_splice, KEY, key_size);
		kv_splice_set_value(kv_splice, (char *)value[idx], sizes[idx]);
		struct kv_splice_base kv_splice_base = { .kv_splice = kv_splice, .kv_type = KV_FORMAT };
		struct bt_insert_req ins_req = { .metadata.handle = thr_args->bench_info->dbs[db_id],
						 .metadata.put_op_metadata.key_value_category = idx > 1 ? BIG_INLOG :
													  SMALL_INPLACE,
						 .metadata.cat = idx > 1 ? BIG_INLOG : SMALL_INPLACE,
						 .metadata.key_format = KV_FORMAT,
						 .metadata.level_id = 0,
						 .metadata.append_to_log = 1,
						 .metadata.gc_request = 0 };
		ins_req.splice_base = &kv_splice_base;
		struct bt_mutate_req mutate = { .append_to_log = 1 };
		struct log_operation log_op = { 0 };
		// log_op.metadata = &mutate;
		// log_op.metadata->handle = thr_args->bench_info->dbs[db_id];
		log_op.optype_tolog = insertOp;
		log_op.txn_id = thr_args->bench_info->txn_ids[db_id];
		log_op.ins_req = &ins_req;
		append_key_value_to_log(&log_op);
	}
	pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
	char *parallax_volume = NULL;
	uint64_t num_kv_pairs = 0;
	uint64_t num_threads = 0;
	uint64_t num_dbs = 0;

	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "-parallax_volume") == 0) {
			if (i + 1 < argc) {
				parallax_volume = argv[i + 1];
			}
		} else if (strcmp(argv[i], "-num_kv_pairs") == 0) {
			if (i + 1 < argc) {
				num_kv_pairs = strtoull(argv[i + 1], NULL, 10);
			}
		} else if (strcmp(argv[i], "-num_threads") == 0) {
			if (i + 1 < argc) {
				num_threads = strtoull(argv[i + 1], NULL, 10);
			}
		} else if (strcmp(argv[i], "-num_dbs") == 0) {
			if (i + 1 < argc) {
				num_dbs = strtoull(argv[i + 1], NULL, 10);
			}
		}
	}

	if (num_kv_pairs == 0 || num_threads == 0 || num_dbs == 0) {
		printf("Usage: %s -parallax_volume <parallax_volume_value> -num_kv_pairs <num_kv_pairs_value> -num_threads <num_threads_value> -num_dbs <number of dbs> \n",
		       argv[0]);
		_exit(EXIT_FAILURE);
	}
	if (parallax_volume == NULL) {
		printf("Usage: %s -parallax_volume <parallax_volume_value> -num_kv_pairs <num_kv_pairs_value> -num_threads <num_threads_value> -num_dbs <number of dbs> \n",
		       argv[0]);
		_exit(EXIT_FAILURE);
	}
	CHECK(fprintf(stderr, "-->test_wal: parallax_volume: %s, num_kv_pairs: %lu, and num_threads: %lu\n",
		      parallax_volume, num_kv_pairs, num_threads));

	const char *error = par_format(parallax_volume, 128);
	if (error) {
		CHECK(fprintf(stderr, "failed to format volume: %s Reason: %s\n", parallax_volume, error));
		_exit(EXIT_FAILURE);
	}

	pthread_t threads[num_threads];
	struct bench_info bench_info = { 0 };
	bench_info.dbs = calloc(num_dbs, sizeof(db_handle *));
	bench_info.txn_ids = calloc(num_dbs, sizeof(uint64_t));
	const char *const db_name_prefix = "wal_test";
	bench_info.num_dbs = num_dbs;
	for (uint64_t i = 0; i < bench_info.num_dbs; i++) {
		par_db_options db_options = { .create_flag = PAR_CREATE_DB, .options = par_get_default_options() };
		error = NULL;
		char db_name[128] = { 0 };
		strcpy(db_name, db_name_prefix);
		memcpy(&db_name[strlen(db_name)], &i, sizeof(uint64_t));
		db_options.db_name = db_name;
		db_options.volume_name = (char *)parallax_volume;
		bench_info.dbs[i] = db_open(&db_options, &error);
		if (error) {
			CHECK(fprintf(stderr, "Failed to open db. Reason: %s\n", error));
			_exit(EXIT_FAILURE);
		}
		bench_info.txn_ids[i] = rul_start_txn(bench_info.dbs[i]->db_desc);
	}

	bench_info.num_kv_pairs = num_kv_pairs;
	bench_info.num_threads = num_threads;

	if (error) {
		CHECK(fprintf(stderr, "Failed to open volume: %s reason: %s", parallax_volume, error));
		_exit(EXIT_FAILURE);
	}

	struct timeval start_time;
	struct timeval end_time;
	gettimeofday(&start_time, NULL);

	struct thr_args *thr_args = calloc(num_threads, sizeof(struct thr_args));

	for (uint64_t thr_id = 0; thr_id < num_threads; ++thr_id) {
		thr_args[thr_id].bench_info = &bench_info;
		if (pthread_create(&threads[thr_id], NULL, do_wal_IO, &thr_args[thr_id]) != 0) {
			perror("pthread_create");
			_exit(EXIT_FAILURE);
		}
	}

	for (uint64_t i = 0; i < num_threads; ++i)
		pthread_join(threads[i], NULL);

	// Generating a timestamp compatible with Python datetime
	time_t timestamp = time(NULL);
	struct tm *local_time = localtime(&timestamp);
	char datetime[20];
	strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", local_time);

	CHECK(fprintf(stderr, "Timestamp: %s\n", datetime));

	gettimeofday(&end_time, NULL);
	double execution_time = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1e6;

	double throughput = bench_info.num_kv_pairs / execution_time;

	CHECK(fprintf(stderr, "Total execution time: %f seconds\n", execution_time));
	CHECK(fprintf(stderr, "Throughput: %lf append kv_pairs/s\n", throughput));
	return EXIT_SUCCESS;
}

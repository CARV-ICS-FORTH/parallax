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
#include "../btree/conf.h"
#include "../btree/key_splice.h"
#include "arg_parser.h"
#include "btree/key_splice.h"
#include <assert.h>
#include <btree/gc.h>
#include <db.h>
#include <log.h>
#include <parallax/parallax.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#define MAX_KV_PAIR_SIZE 4096
#define MY_MAX_KEY_SIZE 255

/**
 * This test uses a BerkeleyDB key value store as the source of truth. We use
 * BerkeleyDB because a) it is robust and b) it is available in the majority of
 * package managers of popular Linux distributions. During the population
 * phase, it produces keys and values of all sizes and of all contents using
 * the srand function. Then, it stores them in Parallax and BerkeleyDB. In the
 * verification stage, it opens a cursor in BerkeleyDB and retieves keys and
 * values from Parallax. It checks the correctness of keys and values with the
 * ones stored in BerkeleyDB. In the final phase, it iterates all the kv pairs
 * and checks if their total number agree with the kv pairs stored in
 * BekeleyDB.
 */

struct workload_config_t {
	par_handle handle;
	DB *truth;
	uint64_t total_keys;
	uint32_t progress_report;
};

static void generate_random_key(unsigned char *key_buffer, uint32_t key_size)
{
	for (uint32_t i = 0; i < key_size; i++) {
		key_buffer[i] = (rand() % 255) + 1;
	}
}

static void generate_random_value(char *value_buffer, uint32_t value_size, uint32_t id)
{
	*(uint32_t *)value_buffer = id;
	for (uint32_t i = sizeof(uint64_t); i < value_size; i++)
		value_buffer[i] = rand() % 256;
}

static void populate_from_BDB(struct workload_config_t *workload_config)
{
	DBC *cursorp = NULL;
	DBT BDB_key = { 0 };
	DBT BDB_value = { 0 };
	/* Database open omitted for clarity */
	/* Get a cursor */
	workload_config->truth->cursor(workload_config->truth, NULL, &cursorp, 0);

	/* Iterate over the database, retrieving each record in turn. */
	int ret = cursorp->get(cursorp, &BDB_key, &BDB_value, DB_NEXT);
	int num_keys = 0;
	for (; ret == 0; ret = cursorp->get(cursorp, &BDB_key, &BDB_value, DB_NEXT), ++num_keys) {
		struct par_key_value kv_pair = { 0 };
		kv_pair.k.size = BDB_key.size;
		kv_pair.k.data = BDB_key.data;
		kv_pair.v.val_size = BDB_value.size;
		kv_pair.v.val_buffer = BDB_value.data;
		const char *error_message = NULL;
		par_put(workload_config->handle, &kv_pair, &error_message);

		if (!(num_keys % workload_config->progress_report))
			log_info("Progress in population %d keys", num_keys);
	}
	log_info("Population ended Successfully! :-)");
	workload_config->total_keys = num_keys;
}

static void populate_randomly(struct workload_config_t *workload_config)
{
	log_info("Starting population for %lu keys...", workload_config->total_keys);
	const char *error_message = NULL;
	unsigned char key_buffer[MY_MAX_KEY_SIZE] = { 0 };
	unsigned char value_buffer[MAX_KV_PAIR_SIZE] = { 0 };
	uint64_t unique_keys = 0;
	for (uint64_t i = 0; i < workload_config->total_keys; i++) {
		struct par_key_value kv_pair = { 0 };

		kv_pair.k.size = rand() % (MY_MAX_KEY_SIZE + 1);

		// if (kv_pair.k.size <= 12) {
		// 	kv_pair.k.size = 14;
		// }

		if (!kv_pair.k.size)
			kv_pair.k.size++;
		kv_pair.v.val_size = rand() % (MAX_KV_PAIR_SIZE - (kv_pair.k.size + sizeof(uint32_t)));
		if (kv_pair.v.val_size < 4)
			kv_pair.v.val_size = 4;

		//hack
		kv_pair.k.size = 23;
		kv_pair.v.val_size = 8;

		generate_random_key(key_buffer, kv_pair.k.size);
		kv_pair.k.data = (char *)key_buffer;
		generate_random_value((char *)value_buffer, kv_pair.v.val_size, i);
		kv_pair.v.val_buffer = (char *)value_buffer;

		DBT truth_key = { 0 };
		DBT truth_data = { 0 };
		truth_key.data = (void *)kv_pair.k.data;
		truth_key.size = kv_pair.k.size;
		truth_data.data = kv_pair.v.val_buffer;
		truth_data.size = kv_pair.v.val_size;
		int ret = workload_config->truth->put(workload_config->truth, NULL, &truth_key, &truth_data,
						      DB_NOOVERWRITE);
		if (ret == DB_KEYEXIST) {
			// workload_config->truth->err(workload_config->truth, ret,
			// 			    "Put failed because key size %u payload: %.*s already exists",
			// 			    truth_key.size, truth_key.size, truth_key.data);
			continue;
		}
		++unique_keys;
		// log_debug("Inserting in store key size %u key: %s value size %u unique keys %lu", kv_pair.k.size,
		// 	  kv_pair.k.data, kv_pair.v.val_size, unique_keys);
		par_put(workload_config->handle, &kv_pair, &error_message);
		if (!(i % workload_config->progress_report))
			log_info("Progress in population %lu keys", i);
	}
	log_info("Population ended Successfully! :-)");
	workload_config->total_keys = unique_keys;
}

static void locate_key(par_handle handle, DBT lookup_key)
{
	const char *error_message = NULL;
	par_scanner scanner = par_init_scanner(handle, NULL, PAR_FETCH_FIRST, &error_message);
	while (par_is_valid(scanner)) {
		struct par_key fetched_key = par_get_key(scanner);

		if (fetched_key.size == lookup_key.size &&
		    memcmp(fetched_key.data, lookup_key.data, fetched_key.size) == 0) {
			log_info("Found key %u %.*s", lookup_key.size, lookup_key.size, (char *)lookup_key.data);
			return;
		}
		par_get_next(scanner);
	}
	log_info("Not Found key %u %.*s", lookup_key.size, lookup_key.size, (char *)lookup_key.data);
}

static void *get_workload(void *config)
{
	struct workload_config_t *workload_config = config;
	log_info("Testing GETS now");

	const char *error_message = NULL;
	DBC *cursorp = NULL;
	DBT key = { 0 };
	DBT data = { 0 };
	/* Database open omitted for clarity */
	/* Get a cursor */
	workload_config->truth->cursor(workload_config->truth, NULL, &cursorp, 0);

	/* Iterate over the database, retrieving each record in turn. */
	uint64_t unique_keys = 0;
	int ret = cursorp->get(cursorp, &key, &data, DB_NEXT);
	for (; ret == 0; ret = cursorp->get(cursorp, &key, &data, DB_NEXT)) {
		struct par_key par_key = { .size = key.size, .data = key.data };
		struct par_value value = { 0 };
		bool malloced = 1;
		char get_buf[4096];
		if (unique_keys < workload_config->total_keys / 2)
			par_get(workload_config->handle, &par_key, &value, &error_message);
		else {
			malloced = 0;
			struct key_splice *key_serialized =
				(struct key_splice *)calloc(1UL, key.size + key_splice_get_metadata_size());
			key_splice_set_key_size(key_serialized, key.size);
			key_splice_set_key_offset(key_serialized, (char *)key.data);
			value.val_buffer_size = 4096;
			value.val_buffer = get_buf;
			par_get_serialized(workload_config->handle, (char *)key_serialized, &value, &error_message);
		}

		if (error_message) {
			uint64_t insert_order = *(uint64_t *)data.data;
			log_debug(
				"Key is size: %u data: %.*s not found! keys found so far %lu error_message is %s insert order was %lu",
				key.size, key.size, (char *)key.data, unique_keys, error_message, insert_order);
			locate_key(workload_config->handle, key);
			_Exit(EXIT_FAILURE);
		}
		if (value.val_size != data.size) {
			log_fatal("Value sizes mismatch waited %u got %u", data.size, value.val_size);
			_Exit(EXIT_FAILURE);
		}
		if (memcmp(value.val_buffer, data.data, data.size) != 0) {
			log_fatal("Value data do not match");
			_Exit(EXIT_FAILURE);
		}

		if (malloced)
			free(value.val_buffer);
		if (0 == ++unique_keys % 10000)
			log_info("Progress: Retrieved %lu keys", unique_keys);
	}
	log_debug("KV pairs found are %lu", unique_keys);
	if (ret != DB_NOTFOUND) {
		workload_config->truth->err(workload_config->truth, ret, "DB not found");
		_Exit(EXIT_FAILURE);
	}

	cursorp->close(cursorp);
	log_info("Testing GETS DONE!");
	pthread_exit(NULL);
}

static void *scan_workload(void *config)
{
	struct workload_config_t *workload_config = config;
	log_info("Now, testing SCANS");
	const char *error_message = NULL;
	par_scanner scanner = par_init_scanner(workload_config->handle, NULL, PAR_FETCH_FIRST, &error_message);
	uint64_t unique_keys = 0;
	for (; par_is_valid(scanner); ++unique_keys)
		par_get_next(scanner);

	par_close_scanner(scanner);
	if (workload_config->total_keys != unique_keys) {
		log_fatal("Scanner lost keys expected %lu found %lu", workload_config->total_keys, unique_keys);
		_Exit(EXIT_FAILURE);
	}
	log_info("Testing SCANS Successful");
	pthread_exit(NULL);
}

static void delete_workload(struct workload_config_t *workload_config)
{
	log_info("Now, testing Deletes");

	const char *error_message = NULL;
	DBC *cursorp = NULL;
	DBT key = { 0 };
	DBT data = { 0 };
	/* Database open omitted for clarity */
	/* Get a cursor */
	workload_config->truth->cursor(workload_config->truth, NULL, &cursorp, 0);

	for (int ret = cursorp->get(cursorp, &key, &data, DB_NEXT); ret == 0;
	     ret = cursorp->get(cursorp, &key, &data, DB_NEXT)) {
		struct par_key par_key = { .size = key.size, .data = key.data };
		par_delete(workload_config->handle, &par_key, &error_message);
		if (error_message) {
			log_fatal("Key is size: %u data: %.*s deletion failed!", key.size, key.size, (char *)key.data);
			_Exit(EXIT_FAILURE);
		}
	}
	cursorp->close(cursorp);
	/*Verify that all deleted keys cannot be found through par_get() operation*/
	uint64_t keys_checked = 0;
	workload_config->truth->cursor(workload_config->truth, NULL, &cursorp, 0);
	for (int ret = cursorp->get(cursorp, &key, &data, DB_NEXT); ret == 0;
	     ret = cursorp->get(cursorp, &key, &data, DB_NEXT)) {
		struct par_key par_key = { .size = key.size, .data = key.data };
		struct par_value value = { 0 };

		if (0 == ++keys_checked % 10000)
			log_info("Progress: Checked %lu keys", keys_checked);

		par_get(workload_config->handle, &par_key, &value, &error_message);
		if (error_message) {
			error_message = NULL;
			continue;
		}
		log_fatal(
			"Key is size: %u data: %.*s value size %u found! (It shouldn't since we have deleted it!) keys checked so far %lu",
			key.size, key.size, (char *)key.data, data.size, keys_checked);
		_Exit(EXIT_FAILURE);
	}
	workload_config->total_keys = 0;
	pthread_t scan_thread;
	pthread_create(&scan_thread, NULL, scan_workload, workload_config);
	pthread_join(scan_thread, NULL);
	log_info("Test Deletes Successful");
}

int main(int argc, char **argv)
{
	int help_flag = 0;

	struct wrap_option options[] = {
		{ { "help", no_argument, &help_flag, 1 }, "Prints valid arguments for tiresias.", NULL, INTEGER },
		{ { "file", required_argument, 0, 'a' },
		  "--file=path to file of db, parameter that specifies the target where parallax is going to run.",
		  NULL,
		  STRING },
		{ { "num_of_kvs", required_argument, 0, 'b' },
		  "--num_of_kvs=number, parameter that specifies the number of operation the test will execute.",
		  NULL,
		  INTEGER },
		{ { "BDB_file", optional_argument, 0, 'a' },
		  "--BDB_file=path to a prepopulated BerkeleyDB (BDB), parameter that specifies the BDB that the test uses as the source of truth.",
		  NULL,
		  STRING },
		{ { 0, 0, 0, 0 }, "End of arguments", NULL, INTEGER }
	};

	unsigned optional_args_len = 0;
	unsigned options_len = sizeof(options) / sizeof(struct wrap_option);
	log_debug("Options len %u", options_len);
	arg_parse(argc, argv, options, options_len - optional_args_len);
	arg_print_options(help_flag, options, options_len);
	uint64_t total_keys = *(int *)get_option(options, 2);
	log_debug("Total keys %lu", total_keys);

	srand(1);
	par_db_options db_options = { 0 };
	db_options.volume_name = get_option(options, 1);
	log_debug("Volume name %s", db_options.volume_name);

	char *truth_db = get_option(options, 3);
	log_info("BerkeleyDB path is %s", truth_db);
	/*First open source of truth BerkeleyDB database*/
	DB *truth = { 0 };
	int ret = db_create(&truth, NULL, 0);
	if (ret) {
		truth->err(truth, ret, "Database open failed: %s", "truth.db");
		_Exit(EXIT_FAILURE);
	}

	bool truth_db_exists = false;
	ret = truth->open(truth, NULL, truth_db, NULL, DB_BTREE, /*DB_CREATE | DB_TRUNCATE*/ 0, 0);
	if (0 == ret) {
		log_info("BDB %s already exists, not  populating it again", truth_db);
		truth_db_exists = true;
	}

	if (!truth_db_exists) {
		ret = truth->open(truth, NULL, truth_db, NULL, DB_BTREE, DB_CREATE, 0);
		if (ret) {
			truth->err(truth, ret, "Database open failed: %s", "truth.db");
			return (ret);
		}
		log_info("Created BDB %s already exists, going to populate as well", truth_db);
	}

	const char *error_message = par_format(db_options.volume_name, 16);
	if (error_message) {
		log_fatal("Error message from par_format: %s", error_message);
		_Exit(EXIT_FAILURE);
	}

	db_options.db_name = "TIRESIAS";
	db_options.create_flag = PAR_CREATE_DB;
	db_options.options = par_get_default_options();
	par_handle parallax_db = par_open(&db_options, &error_message);

	struct workload_config_t workload_config = {
		.handle = parallax_db, .truth = truth, .total_keys = total_keys, .progress_report = 100000
	};

	if (truth_db_exists)
		populate_from_BDB(&workload_config);
	else {
		struct timeval time;
		gettimeofday(&time, NULL);
		srand((time.tv_sec * 1000) + (time.tv_usec / 1000));
		populate_randomly(&workload_config);
	}

	pthread_t get_thread;
	pthread_t scan_thread;

	pthread_create(&get_thread, NULL, get_workload, &workload_config);
	pthread_create(&scan_thread, NULL, scan_workload, &workload_config);
	pthread_join(get_thread, NULL);
	pthread_join(scan_thread, NULL);

	delete_workload(&workload_config);

	error_message = par_close(parallax_db);
	if (error_message) {
		log_fatal("Error message from par_close: %s", error_message);
		_Exit(EXIT_FAILURE);
	}
	truth->close(truth, 0);
	return 0;
}

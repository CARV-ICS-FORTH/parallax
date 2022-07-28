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
#include "arg_parser.h"
#include <assert.h>
#include <db.h>
#include <log.h>
#include <parallax.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define MAX_KV_PAIR_SIZE 4096
#define MY_MAX_KEY_SIZE 255
static char workload[512];

enum workload_types { Load = 0, Get, Scan, All, All_scan_greater };
const char *workload_tags[] = { "Load", "Get", "Scan", "All", "All_scan_greater" };

enum kvf_options { VOLUME_NAME = 0, TOTAL_KEYS, SCAN_SIZE, WORKLOAD };

struct workload_config_t {
	par_handle handle;
	DB *truth;
	uint64_t total_keys;
	uint32_t progress_report;
};

static void generate_random_key(unsigned char *key_buffer, uint32_t key_size)
{
	for (uint32_t i = 0; i < key_size; i++)
		key_buffer[i] = rand() % 256;
}

static void generate_random_value(char *value_buffer, uint32_t value_size, uint32_t id)
{
	*(uint32_t *)value_buffer = id;
	for (uint32_t i = sizeof(uint64_t); i < value_size; i++)
		value_buffer[i] = rand() % 256;
}

static void put_workload(struct workload_config_t *workload_config)
{
	log_info("Starting population for %lu keys...", workload_config->total_keys);

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
		//log_debug("Inserting in store key size %u value size %u unique keys %lu", kv_pair.k.size,
		//	  kv_pair.v.val_size, unique_keys);
		par_put(workload_config->handle, &kv_pair);
		if (!(i % workload_config->progress_report))
			log_info("Progress in population %lu keys", i);
	}
	log_info("Population ended Successfully! :-)");
	workload_config->total_keys = unique_keys;
}

static void locate_key(par_handle handle, DBT lookup_key)
{
	par_scanner scanner = par_init_scanner(handle, NULL, PAR_FETCH_FIRST);
	while (par_is_valid(scanner)) {
		struct par_key fetched_key = par_get_key(scanner);

		if (fetched_key.size == lookup_key.size && memcmp(fetched_key.data, lookup_key.data, 12) == 0)
			log_info("Fetched key %u %.*s", fetched_key.size, fetched_key.size, fetched_key.data);
		if (fetched_key.size != lookup_key.size ||
		    memcmp(fetched_key.data, lookup_key.data, lookup_key.size) != 0) {
			par_get_next(scanner);
			continue;
		}
		log_info("Found key %u %.*s", lookup_key.size, lookup_key.size, (char *)lookup_key.data);
		return;
	}
	log_info("Not Found key %u %.*s", lookup_key.size, lookup_key.size, (char *)lookup_key.data);
}

static void get_workload(struct workload_config_t *workload_config)
{
	log_info("Testing GETS now");
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

		int get_status = par_get(workload_config->handle, &par_key, &value);
		if (get_status != PAR_SUCCESS) {
			uint64_t insert_order = *(uint64_t *)data.data;
			log_debug(
				"Key is size: %u data: %.*s not found! keys found so far %lu code is %d insert order was %lu",
				key.size, key.size, (char *)key.data, unique_keys, get_status, insert_order);
			locate_key(workload_config->handle, key);
			_exit(EXIT_FAILURE);
		}
		if (value.val_size != data.size) {
			log_fatal("Value sizes mismatch waited %u got %u", data.size, value.val_size);
			_exit(EXIT_FAILURE);
		}
		if (memcmp(value.val_buffer, data.data, data.size) != 0) {
			log_fatal("Value data do not match");
			_exit(EXIT_FAILURE);
		}
		free(value.val_buffer);
		++unique_keys;
	}
	log_debug("KV pairs found are %lu", unique_keys);
	if (ret != DB_NOTFOUND) {
		workload_config->truth->err(workload_config->truth, ret, "DB not found");
		_exit(EXIT_FAILURE);
	}

	cursorp->close(cursorp);
	log_info("Testing GETS DONE!");
}

static void scan_workload(struct workload_config_t *workload_config)
{
	log_info("Now, testing SCANS");
	par_scanner scanner = par_init_scanner(workload_config->handle, NULL, PAR_FETCH_FIRST);
	uint64_t unique_keys = 0;
	for (; par_is_valid(scanner); ++unique_keys)
		par_get_next(scanner);

	par_close_scanner(scanner);
	if (workload_config->total_keys != unique_keys) {
		log_fatal("Scanner lost keys expected %lu found %lu", workload_config->total_keys, unique_keys);
		_exit(EXIT_FAILURE);
	}
	log_info("Testing SCANS Successful");
}

int main(int argc, char **argv)
{
	strcpy(workload, "All"); /*Default value*/
	int help_flag = 0;

	struct wrap_option options[] = {
		{ { "help", no_argument, &help_flag, 1 }, "Prints valid arguments for test_medium.", NULL, INTEGER },
		{ { "file", required_argument, 0, 'a' },
		  "--file=path to file of db, parameter that specifies the target where parallax is going to run.",
		  NULL,
		  STRING },
		{ { "num_of_kvs", required_argument, 0, 'b' },
		  "--num_of_kvs=number, parameter that specifies the number of operation the test will execute.",
		  NULL,
		  INTEGER },
		{ { "scan_size", required_argument, 0, 'b' },
		  "--scan_size=number, parameter that specifies entries to fetch per scan",
		  NULL,
		  INTEGER },
		{ { "workload", required_argument, 0, 'b' },
		  "--workload=string, parameter that specifies the workload to run possible options <Load, Get, Scan, All>",
		  NULL,
		  STRING },
		{ { "kv_mix", required_argument, 0, 'b' },
		  "--kv_mix=string, parameter that specifies the mix of the kvs to run possible options <s, m, l, sd, md, ld>",
		  NULL,
		  STRING },
		{ { 0, 0, 0, 0 }, "End of arguments", NULL, INTEGER }
	};
	unsigned options_len = (sizeof(options) / sizeof(struct wrap_option));

	arg_parse(argc, argv, options, options_len);
	arg_print_options(help_flag, options, options_len);
	uint64_t total_keys = *(int *)get_option(options, 2);

	strcpy(workload, get_option(options, 4));
	if (!(!strcmp(workload, workload_tags[Load]) || !strcmp(workload, workload_tags[Get]) ||
	      !strcmp(workload, workload_tags[Scan]) || !strcmp(workload, workload_tags[All]) ||
	      !strcmp(workload, workload_tags[All_scan_greater]))) {
		log_fatal("Unknown workload type %s possible values are Load, Get, Scan, All (Default)", workload);
		_exit(EXIT_FAILURE);
	}

	log_info("Running workload %s", workload);
	srand(1);
	par_db_options db_options = { 0 };
	db_options.volume_name = get_option(options, 1);
	char truth_db[4096] = { 0 };
	memcpy(truth_db, db_options.volume_name, strlen(db_options.volume_name));
	uint32_t idx = strlen(truth_db);
	for (; truth_db[idx] != '/'; idx--)
		;

	truth_db[idx++] = '/';
	strcpy(&truth_db[idx], "TIRESIAS");
	log_info("BerkeleyDB path is %s", truth_db);
	/*First open source of truth BerkeleyDB database*/
	DB *truth = { 0 };
	int ret = db_create(&truth, NULL, 0);
	if (ret) {
		truth->err(truth, ret, "Database open failed: %s", "truth.db");
		_exit(EXIT_FAILURE);
	}

	ret = truth->open(truth, NULL, truth_db, NULL, DB_BTREE, DB_CREATE | DB_TRUNCATE, 0);
	if (ret) {
		truth->err(truth, ret, "Database open failed: %s", "truth.db");
		return (ret);
	}

	if (strcmp(workload, workload_tags[Load]) == 0 || strcmp(workload, workload_tags[All]) == 0)
		par_format(db_options.volume_name, 16);

	db_options.db_name = "TIRESIAS";
	db_options.volume_start = 0;
	db_options.volume_size = 0;
	db_options.create_flag = PAR_CREATE_DB;
	par_handle hd = par_open(&db_options);

	struct workload_config_t workload_config = {
		.handle = hd, .truth = truth, .total_keys = total_keys, .progress_report = 100000
	};

	if (!strcmp(workload, workload_tags[Load]) || !strcmp(workload, workload_tags[All]) ||
	    !strcmp(workload, workload_tags[All_scan_greater]))
		put_workload(&workload_config);

	if (!strcmp(workload, workload_tags[Get]) || !strcmp(workload, workload_tags[All]) ||
	    !strcmp(workload, workload_tags[All_scan_greater]))
		get_workload(&workload_config);

	if (!strcmp(workload, workload_tags[Scan]) || !strcmp(workload, workload_tags[All])) {
		log_info("Testing scan with PAR_GREATER_OR_EQUAL mode");
		scan_workload(&workload_config);
	}

	par_close(hd);
	truth->close(truth, 0);

	return 0;
}

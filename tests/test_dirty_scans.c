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
#include <assert.h>
#include <log.h>
#include <parallax/parallax.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define KEY_PREFIX "userakias_computerakias"
#define SMALL_VALUE_SIZE 4
#define MEDIUM_VALUE_SIZE 512
#define LARGE_VALUE_SIZE 2048
#define KV_BUFFER_SIZE 4096

struct key {
	uint32_t key_size;
	char key_buf[];
};

static uint64_t total_keys = 1000000;
static uint64_t base;
static uint32_t scan_size = 16;
static char workload[512];

enum workload_types { Load = 0, Get, Scan, All, All_scan_greater };
const char *workload_tags[] = { "Load", "Get", "Scan", "All", "All_scan_greater" };
const char *kv_mix[] = { "s", "m", "l", "sd", "md", "ld" };

enum kvf_options { VOLUME_NAME = 0, TOTAL_KEYS, SCAN_SIZE, WORKLOAD };

unsigned choose_mix(const char *mix, unsigned key_count)
{
	unsigned kv_mix_mapping;
	if (!strcmp(mix, "sd"))
		kv_mix_mapping = 0;
	else if (!strcmp(mix, "md"))
		kv_mix_mapping = 1;
	else if (!strcmp(mix, "ld"))
		kv_mix_mapping = 2;
	else if (!strcmp(mix, "s"))
		kv_mix_mapping = 3;
	else if (!strcmp(mix, "m"))
		kv_mix_mapping = 4;
	else if (!strcmp(mix, "l"))
		kv_mix_mapping = 5;
	else {
		log_fatal("Error unknown workload specified");
		exit(EXIT_FAILURE);
	}

	switch (kv_mix_mapping) {
	case 0:
		if (key_count < 6)
			return 0;
		else if (key_count < 8)
			return 1;
		else
			return 2;

		break;
	case 1:
		if (key_count < 6)
			return 1;
		else if (key_count < 8)
			return 0;
		else
			return 2;

		break;
	case 2:
		if (key_count < 6)
			return 2;
		else if (key_count < 8)
			return 0;
		else
			return 1;

		break;
	case 3:
		return 0;
	case 4:
		return 1;
	case 5:
		return 2;
	default:
		assert(0);
		log_fatal("Unknown workload given");
		_exit(EXIT_FAILURE);
	}
}
struct workload_config_t {
	par_handle handle;
	uint64_t base;
	uint64_t total_keys;
	uint64_t step;
	uint64_t scan_size;
	enum par_seek_mode seek_mode;
	uint32_t progress_report;
};

static void put_workload(struct workload_config_t *workload_config, const char *kv_size_mix)
{
	log_info("Starting population for %lu keys...", total_keys);
	struct par_key_value my_kv = { .k.size = 0, .k.data = NULL, .v.val_buffer = NULL };
	struct key *k = calloc(1, KV_BUFFER_SIZE);
	uint64_t key_count = 0;

	for (uint64_t i = workload_config->base; key_count < total_keys; i += workload_config->step) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf);
		char *value_payload = (char *)((uint64_t)k + sizeof(struct key) + k->key_size);
		uint32_t res = choose_mix(kv_size_mix, key_count % 10);

		my_kv.k.size = k->key_size;
		my_kv.k.data = k->key_buf;
		if (res == 0) {
			my_kv.v.val_size = SMALL_VALUE_SIZE;
			my_kv.v.val_buffer_size = KV_BUFFER_SIZE / 2;
			my_kv.v.val_buffer = value_payload;
		} else if (res == 1) {
			my_kv.v.val_size = MEDIUM_VALUE_SIZE;
			my_kv.v.val_buffer_size = KV_BUFFER_SIZE / 2;
			my_kv.v.val_buffer = value_payload;
		} else {
			my_kv.v.val_size = LARGE_VALUE_SIZE;
			my_kv.v.val_buffer_size = KV_BUFFER_SIZE / 2;
			my_kv.v.val_buffer = value_payload;
		}
		//log_debug("key %.*s %u", my_kv.k.size, my_kv.k.data, my_kv.v.val_size);
		par_put(workload_config->handle, &my_kv);
		if (!(++key_count % workload_config->progress_report))
			log_info("Progress in population %lu keys", key_count);
	}
	log_info("Population ended Successfully! :-)");
	free(k);
}

static void get_workload(struct workload_config_t *workload_config)
{
	struct par_key_value my_kv = { .k.size = 0, .k.data = NULL, .v.val_buffer = NULL };
	struct key *k = calloc(1, KV_BUFFER_SIZE);

	log_info("Testing GETS now");
	uint64_t key_count = 0;
	for (uint64_t i = workload_config->base; key_count < workload_config->total_keys; i += workload_config->step) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf);

		my_kv.k.size = k->key_size;
		my_kv.k.data = k->key_buf;
		struct par_value my_value = { .val_buffer = NULL };
		if (par_get(workload_config->handle, &my_kv.k, &my_value) != PAR_SUCCESS) {
			log_fatal("Key %u:%s not found", my_kv.k.size, my_kv.k.data);
			_exit(EXIT_FAILURE);
		}
		if (my_value.val_size != SMALL_VALUE_SIZE && my_value.val_size != MEDIUM_VALUE_SIZE &&
		    my_value.val_size != LARGE_VALUE_SIZE) {
			log_fatal(
				"Corrupted size for key: %s got %u does not match any of the SMALL, MEDIUM, and LARGE categories",
				my_kv.k.data, my_value.val_size);
			_exit(EXIT_FAILURE);
		}
		my_value.val_size = UINT32_MAX;
		k->key_buf[0] = 0;
		free(my_value.val_buffer);
		my_value.val_buffer = NULL;
		if (!(++key_count % workload_config->progress_report))
			log_info("<Get no %lu> done", i);
	}

	log_info("Testing GETS DONE!");

	log_info("Testing if gets value are sane");
	char *key = "SanityCheck";
	char *value = "Hello this is a sane test";
	my_kv.k.size = strlen(key) + 1;
	my_kv.k.data = key;
	my_kv.v.val_size = strlen(value) + 1;
	my_kv.v.val_buffer = value;
	par_put(workload_config->handle, &my_kv);
	struct par_value my_value = { .val_buffer = NULL };
	if (par_get(workload_config->handle, &my_kv.k, &my_value) != PAR_SUCCESS) {
		log_fatal("Key %u:%s not found", my_kv.k.size, my_kv.k.data);
		_exit(EXIT_FAILURE);
	}
	if (strcmp(my_value.val_buffer, my_kv.v.val_buffer)) {
		log_fatal("Value is wrong do not match expected: %s got: %s", my_kv.v.val_buffer, my_value.val_buffer);
		_exit(EXIT_FAILURE);
	}
	free(my_value.val_buffer);

	log_info("Testing if gets value are sane DONE");
	free(k);
}

static void scan_workload(struct workload_config_t *workload_config)
{
	log_info("Now, testing scans");
	uint32_t expected_offset = 0;

	if (PAR_GREATER == workload_config->seek_mode)
		++expected_offset;

	struct par_key_value my_kv = { .k.size = 0, .k.data = NULL, .v.val_buffer = NULL };
	struct key *k = calloc(1, KV_BUFFER_SIZE);
	uint64_t key_count = 0;
	for (uint64_t i = workload_config->base; key_count < total_keys - scan_size; i += workload_config->step) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf);

		my_kv.k.size = k->key_size;
		my_kv.k.data = k->key_buf;
		par_scanner my_scanner =
			par_init_scanner(workload_config->handle, &my_kv.k, workload_config->seek_mode);

		if (!par_is_valid(my_scanner)) {
			log_fatal("Nothing found! it shouldn't!");
			_exit(EXIT_FAILURE);
		}

		struct par_key my_keyptr = par_get_key(my_scanner);

		/*construct the key we expect*/
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i + expected_offset);
		k->key_size = strlen(k->key_buf);
		//log_debug("Expecting key %.*s got key %.*s", k->key_size, k->key_buf, my_keyptr.size, my_keyptr.data);

		if (memcmp(k->key_buf, my_keyptr.data, my_keyptr.size) != 0) {
			log_fatal("Test failed key %s not found scanner instead returned %d:%s", k->key_buf,
				  my_keyptr.size, my_keyptr.data);
			_exit(EXIT_FAILURE);
		}
		memset((void *)my_keyptr.data, 0x00, my_keyptr.size);

		uint64_t scan_entries = 0;
		for (uint64_t j = i + 2 + expected_offset; scan_entries <= workload_config->scan_size;
		     j += workload_config->step) {
			/*construct the key we expect*/
			memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
			sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)j);
			k->key_size = strlen(k->key_buf);
			//log_info("Expecting key %s",k->key_buf);
			par_get_next(my_scanner);
			if (!par_is_valid(my_scanner)) {
				log_warn("DB end at key %s is this correct? yes", k->key_buf);
				break;
			}
			my_keyptr = par_get_key(my_scanner);

			if (memcmp(k->key_buf, my_keyptr.data, my_keyptr.size) != 0) {
				log_fatal("Test failed for i: %lu key %.*s not found scanner instead returned %.*s",
					  scan_entries, k->key_size, k->key_buf, my_keyptr.size, my_keyptr.data);
				_exit(EXIT_FAILURE);
			}
			memset((void *)my_keyptr.data, 0x00, my_keyptr.size);
			++scan_entries;
		}

		if (!(++key_count % workload_config->progress_report))
			log_info("</Scan no %lu> done", i);

		par_close_scanner(my_scanner);
	}
	log_info("Scan test Successfull");
	free(k);
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

	total_keys = *(int *)get_option(options, 2);
	scan_size = *(int *)get_option(options, 3);

	strcpy(workload, get_option(options, 4));
	if (!(!strcmp(workload, workload_tags[Load]) || !strcmp(workload, workload_tags[Get]) ||
	      !strcmp(workload, workload_tags[Scan]) || !strcmp(workload, workload_tags[All]) ||
	      !strcmp(workload, workload_tags[All_scan_greater]))) {
		log_fatal("Unknown workload type %s possible values are Load, Get, Scan, All (Default)", workload);
		_exit(EXIT_FAILURE);
	}

	unsigned kv_mix_index = 0;
	for (kv_mix_index = 0; kv_mix_index < 6; kv_mix_index++) {
		if (!strcmp(kv_mix[kv_mix_index], get_option(options, 5)))
			break;
	}

	if (kv_mix_index == 6) {
		log_fatal("Invalid kv_mix provided! kv_mix = %s", (char *)get_option(options, 5));
		return 1;
	}

	base = 100000000L;

	log_info("Running workload %s", workload);
	par_db_options db_options = { .volume_name = get_option(options, 1),
				      .db_name = "scan_test",
				      .create_flag = PAR_CREATE_DB };
	char *error_message = NULL;

	if (strcmp(workload, workload_tags[Load]) == 0 || strcmp(workload, workload_tags[All]) == 0) {
		error_message = par_format(db_options.volume_name, 16);
		if (error_message) {
			log_fatal("%s", error_message);
			free(error_message);
			return EXIT_FAILURE;
		}
	}
	par_handle hd = par_open(&db_options, &error_message);

	if (error_message) {
		log_fatal("%s", error_message);
		free(error_message);
		return EXIT_FAILURE;
	}

	struct workload_config_t workload_config = { .handle = hd,
						     .base = base + 1,
						     .total_keys = total_keys,
						     .step = 2,
						     .scan_size = scan_size,
						     .seek_mode = PAR_GREATER_OR_EQUAL,
						     .progress_report = 100000 };

	if (!strcmp(workload, workload_tags[Load]) || !strcmp(workload, workload_tags[All]) ||
	    !strcmp(workload, workload_tags[All_scan_greater]))
		put_workload(&workload_config, kv_mix[kv_mix_index]);

	if (!strcmp(workload, workload_tags[Get]) || !strcmp(workload, workload_tags[All]) ||
	    !strcmp(workload, workload_tags[All_scan_greater]))
		get_workload(&workload_config);

	if (!strcmp(workload, workload_tags[Scan]) || !strcmp(workload, workload_tags[All])) {
		log_info("Testing scan with PAR_GREATER_OR_EQUAL mode");
		scan_workload(&workload_config);
	}

	if (!strcmp(workload, workload_tags[All_scan_greater])) {
		workload_config.base = base;
		workload_config.seek_mode = PAR_GREATER;
		log_info("Testing scan with PAR_GREATER mode");
		scan_workload(&workload_config);
	}

	error_message = par_close(hd);
	if (error_message) {
		log_fatal("%s", error_message);
		free(error_message);
		return EXIT_FAILURE;
	}
	return 0;
}

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
#include "../include/parallax.h"
#include "arg_parser.h"
#include <assert.h>
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_PREFIX "userakias_computerakias"
#define SMALL_VALUE_SIZE 4
#define MEDIUM_VALUE_SIZE 512
#define LARGE_VALUE_SIZE 2048
#define KV_BUFFER_SIZE 4096

struct key {
	uint32_t key_size;
	char key_buf[];
};

struct value {
	uint32_t value_size;
	char value_buf[];
};

static uint64_t total_keys = 1000000;
static uint64_t base;
static uint32_t scan_size = 16;
static char workload[512];

enum workload_types { Load = 0, Get, Scan, All };
const char *workload_tags[] = { "Load", "Get", "Scan", "All" };
const char *kv_mix[] = { "s", "m", "l", "sd", "md", "ld" };

#define NUM_OPTIONS 4
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
		else if (key_count >= 6 && key_count < 8)
			return 1;
		else
			return 2;

		break;
	case 1:
		if (key_count < 6)
			return 1;
		else if (key_count >= 6 && key_count < 8)
			return 0;
		else
			return 2;

		break;
	case 2:
		if (key_count < 6)
			return 2;
		else if (key_count >= 6 && key_count < 8)
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
		exit(EXIT_FAILURE);
	}
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
	      !strcmp(workload, workload_tags[Scan]) || !strcmp(workload, workload_tags[All]))) {
		log_fatal("Unknown workload type possible values are Load, Get, Scan, All (Default)");
		exit(EXIT_FAILURE);
	}

	unsigned kv_mix_index;
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
	par_db_options db_options;
	db_options.volume_name = get_option(options, 1);
	db_options.db_name = "scan_test";
	db_options.volume_start = 0;
	db_options.volume_size = 0;
	db_options.create_flag = PAR_CREATE_DB;
	par_handle hd = par_open(&db_options);

	struct par_key_value my_kv = { .k.size = 0, .k.data = NULL, .v.val_buffer = NULL };
	struct key *k = calloc(1, KV_BUFFER_SIZE);
	if (strcmp(workload, workload_tags[Load]) && strcmp(workload, workload_tags[All]))
		goto Get;
	log_info("Starting population for %lu keys...", total_keys);
	uint64_t key_count = 0;
	for (uint64_t i = base; i < base + total_keys; ++i) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf);
		struct value *v = (struct value *)((uint64_t)k + sizeof(struct key) + k->key_size);
		uint32_t res = choose_mix(kv_mix[kv_mix_index], key_count % 10);

		my_kv.k.size = k->key_size;
		my_kv.k.data = k->key_buf;
		if (res == 0) {
			my_kv.v.val_size = SMALL_VALUE_SIZE;
			my_kv.v.val_buffer_size = KV_BUFFER_SIZE / 2;
			my_kv.v.val_buffer = v->value_buf;
		} else if (res == 1) {
			my_kv.v.val_size = MEDIUM_VALUE_SIZE;
			my_kv.v.val_buffer_size = KV_BUFFER_SIZE / 2;
			my_kv.v.val_buffer = v->value_buf;
		} else {
			my_kv.v.val_size = LARGE_VALUE_SIZE;
			my_kv.v.val_buffer_size = KV_BUFFER_SIZE / 2;
			my_kv.v.val_buffer = v->value_buf;
		}
		par_put(hd, &my_kv);
		if (++key_count % 10000 == 0)
			log_info("Progress in population %lu keys", key_count);
	}
	log_info("Population ended Successfully! :-)");

Get:
	if (strcmp(workload, workload_tags[Get]) && strcmp(workload, workload_tags[All]))
		goto Scan;

	log_info("Testing GETS now");
	for (uint64_t i = base; i < base + total_keys; ++i) {
		if (i % 100000 == 0)
			log_info("<Get no %lu>", i);
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf);

		my_kv.k.size = k->key_size;
		my_kv.k.data = k->key_buf;
		struct par_value my_value = { .val_buffer = NULL };
		if (par_get(hd, &my_kv.k, &my_value) != PAR_SUCCESS) {
			log_fatal("Key %u:%s not found", my_kv.k.size, my_kv.k.data);
			exit(EXIT_FAILURE);
		}
		if (my_value.val_size != SMALL_VALUE_SIZE && my_value.val_size != MEDIUM_VALUE_SIZE &&
		    my_value.val_size != LARGE_VALUE_SIZE) {
			log_fatal(
				"Corrupted size for key: %s got %u does not match any of the SMALL, MEDIUM, and LARGE categories",
				my_kv.k.data, my_value.val_size);
			exit(EXIT_FAILURE);
		}
		my_value.val_size = UINT32_MAX;
		k->key_buf[0] = 0;
		free(my_value.val_buffer);
		my_value.val_buffer = NULL;
	}

	log_info("Testing GETS DONE!");

	log_info("Testing if gets value are sane");
	char *key = "SanityCheck";
	char *value = "Hello this is a sane test";
	my_kv.k.size = strlen(key) + 1;
	my_kv.k.data = key;
	my_kv.v.val_size = strlen(value) + 1;
	my_kv.v.val_buffer = value;
	par_put(hd, &my_kv);
	struct par_value my_value = { .val_buffer = NULL };
	if (par_get(hd, &my_kv.k, &my_value) != PAR_SUCCESS) {
		log_fatal("Key %u:%s not found", my_kv.k.size, my_kv.k.data);
		exit(EXIT_FAILURE);
	}
	if (strcmp(my_value.val_buffer, my_kv.v.val_buffer)) {
		log_fatal("Value is wrong do not match expected: %s got: %s", my_kv.v.val_buffer, my_value.val_buffer);
		exit(EXIT_FAILURE);
	}
	free(my_value.val_buffer);

	log_info("Testing if gets value are sane DONE");

Scan:
	if (strcmp(workload, workload_tags[Scan]) && strcmp(workload, workload_tags[All]))
		goto exit;

	log_info("Now, testing scans");

	for (uint64_t i = base; i < (base + (total_keys - scan_size)); ++i) {
		if (i % 100000 == 0)
			log_info("<Scan no %lu>", i);
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf);

		my_kv.k.size = k->key_size;
		my_kv.k.data = k->key_buf;
		par_scanner my_scanner = par_init_scanner(hd, &my_kv.k, PAR_GREATER_OR_EQUAL);
		if (!par_is_valid(my_scanner)) {
			log_fatal("Nothing found! it shouldn't!");
			exit(EXIT_FAILURE);
		}
		struct par_key my_keyptr = par_get_key(my_scanner);
		//log_info("key is %d:%s  malloced %d scanner size %d",k->key_size,k->key_buf,sc->malloced,sizeof(scannerHandle));
		//log_info("key of scanner %d:%s",*(uint32_t *)sc->keyValue,sc->keyValue + sizeof(uint32_t));
		if (memcmp(k->key_buf, my_keyptr.data, my_keyptr.size) != 0) {
			log_fatal("Test failed key %s not found scanner instead returned %d:%s", k->key_buf,
				  my_keyptr.size, my_keyptr.data);
			exit(EXIT_FAILURE);
		}
		//element = stack_pop(&(sc->LEVEL_SCANNERS[0].stack));
		//assert(element.node->type == leafNode);
		//stack_push(&(sc->LEVEL_SCANNERS[0].stack), element);

		for (uint64_t j = 1; j <= scan_size; ++j) {
			/*construct the key we expect*/
			memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
			sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i + j);
			k->key_size = strlen(k->key_buf);
			//log_info("Expecting key %s",k->key_buf);
			par_get_next(my_scanner);
			if (!par_is_valid(my_scanner)) {
				log_warn("DB end at key %s is this correct? yes", k->key_buf);
				break;
			}
			my_keyptr = par_get_key(my_scanner);
			if (memcmp(k->key_buf, my_keyptr.data, my_keyptr.size) != 0) {
				log_fatal("Test failed key %s not found scanner instead returned %d:%s", k->key_buf,
					  my_keyptr.size, my_keyptr.data);
				exit(EXIT_FAILURE);
			}
		}

		if (i % 100000 == 0)
			log_info("</Scan no %lu>", i);
		par_close_scanner(my_scanner);
	}
	log_info("Scan test Successfull");
exit:
	par_close(hd);
	free(k);

	return 0;
}

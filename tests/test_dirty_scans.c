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
#include "../include/parallax.h"
//#include "../btree/btree.h"
//#include "../scanner/scanner.h"
#include <assert.h>
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_PREFIX "userakias_computerakias"
#define SMALL_VALUE_SIZE 4
#define MEDIUM_VALUE_SIZE 512
#define LARGE_VALUE_SIZE 1256
#define KV_BUFFER_SIZE 4096

struct key {
	uint32_t key_size;
	char key_buf[0];
};

struct value {
	uint32_t value_size;
	char value_buf[0];
};

static char *volume_name;
static uint64_t total_keys = 1000000;
static uint64_t base;
static uint32_t scan_size = 16;

#define NUM_OPTIONS 3
enum kvf_options { VOLUME_NAME = 0, TOTAL_KEYS, SCAN_SIZE };
static char *options[] = { "--volume_name", "--total_keys", "--scan_size" };
static char *help = "Usage ./test_dirty_scans <options> Where options include:\n --volume_name <volume name>,\n \
	--total_keys <total number of keys> \n --scan_size <entries to fetch per scan>\n";

static void parse_options(int argc, char **argv)
{
	int i, j;
	for (i = 1; i < argc; i += 2) {
		for (j = 0; j < NUM_OPTIONS; ++j) {
			if (strcmp(argv[i], options[j]) == 0) {
				switch (j) {
				case VOLUME_NAME:
					if (i + 1 >= argc) {
						log_fatal("Wrong arguments number %s", help);
						exit(EXIT_FAILURE);
					}
					volume_name = calloc(1, strlen(argv[i + 1]) + 1);
					strcpy(volume_name, argv[i + 1]);
					break;
				case TOTAL_KEYS: {
					if (i + 1 >= argc) {
						log_fatal("Wrong arguments number %s", help);
						exit(EXIT_FAILURE);
					}
					char *ptr;
					total_keys = strtoul(argv[i + 1], &ptr, 10);
					break;
				}
				case SCAN_SIZE: {
					if (i + 1 >= argc) {
						log_fatal("Wrong arguments number %s", help);
						exit(EXIT_FAILURE);
					}
					char *ptr;
					scan_size = strtoul(argv[i + 1], &ptr, 10);
					break;
				}
				}
				break;
			}
		}
	}

	if (!volume_name) {
		log_fatal("Device name not specified help:\n %s", help);
		exit(EXIT_FAILURE);
	}

	log_info("Volume name: %s, number of keys: %llu, and scan size = %llu", volume_name, total_keys, scan_size);
}

int main(int argc, char **argv)
{
	parse_options(argc, argv);
	base = 100000000L;

	par_db_options db_options;
	db_options.volume_name = volume_name;
	db_options.db_name = "scan_test";
	db_options.volume_start = 0;
	db_options.volume_size = 0;
	db_options.create_flag = PAR_CREATE_DB;
	par_handle hd = par_open(&db_options);

	struct par_key_value my_kv = { .k.size = 0, .k.data = NULL, .v.val_buffer = NULL };
	struct key *k = calloc(1, KV_BUFFER_SIZE);
	log_info("Starting population for %lu keys...", total_keys);
	uint64_t key_count = 0;
	for (uint64_t i = base; i < base + total_keys; ++i) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf);
		struct value *v = (struct value *)((uint64_t)k + sizeof(struct key) + k->key_size);
		uint32_t res = key_count % 10;

		my_kv.k.size = k->key_size;
		my_kv.k.data = k->key_buf;
		if (res < 6) {
			my_kv.v.val_size = SMALL_VALUE_SIZE;
			my_kv.v.val_buffer_size = KV_BUFFER_SIZE / 2;
			my_kv.v.val_buffer = v->value_buf;
		} else if (res >= 8) {
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
			log_info("Progress in population %llu keys", key_count);
	}
	log_info("Population ended Successfully! :-)");

	log_info("Testing GETS now");
	for (uint64_t i = base; i < base + total_keys; ++i) {
		if (i % 100000 == 0)
			log_info("<Get no %llu>", i);
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
				"Corrupted size got %lu does not match any of the SMALL, MEDIUM, and LARGE categories");
			exit(EXIT_FAILURE);
		}
		my_value.val_size = UINT32_MAX;
		k->key_buf[0] = 0;
		free(my_value.val_buffer);
		my_value.val_buffer = NULL;
	}

	log_info("Testing GETS DONE! Now, testing scans");
#if 0

	for (uint64_t i = base; i < (base + (total_keys - scan_size)); ++i) {
		if (i % 100000 == 0)
			log_info("<Scan no %llu>", i);
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf);

		my_kv.k.size = k->key_size;
		my_kv.k.data = k->key_buf;
		my_scanner = par_init_scanner(hd, &my_kv.k, PAR_GREATER_OR_EQUAL);
		if (!par_is_valid(my_scanner)) {
			log_fatal("Nothing found! it shouldn't!");
			exit(EXIT_FAILURE);
		}
		my_keyptr = par_get_key(my_scanner);
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
			log_info("</Scan no %llu>", i);
		par_close_scanner(my_scanner);
	}
	log_info("Scan test Successfull");
	free(k);
#endif
	return 1;
}

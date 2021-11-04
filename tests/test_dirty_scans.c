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
#include "../btree/btree.h"
#include "../scanner/scanner.h"
#include <assert.h>
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_PREFIX "userakias_computerakias"
#define SMALL_VALUE_SIZE 36
#define MEDIUM_VALUE_SIZE 512
#define LARGE_VALUE_SIZE 1120
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
	base = total_keys;

	//stackElementT element;
	db_handle *hd = db_open(volume_name, 0, 0, "scan_test", CREATE_DB);

	struct key *k = calloc(1, KV_BUFFER_SIZE);
	log_info("Starting population for %lu keys...", total_keys);
	uint64_t key_count = 0;
	for (uint64_t i = base; i < base + total_keys; ++i) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		struct value *v = (struct value *)((uint64_t)k + sizeof(struct key) + k->key_size);
		uint32_t res = key_count % 10;

		if (res < 6)
			v->value_size = SMALL_VALUE_SIZE;
		else if (res >= 8)
			v->value_size = LARGE_VALUE_SIZE;
		else
			v->value_size = MEDIUM_VALUE_SIZE;

		memset(v->value_buf, 0xDD, v->value_size);

		insert_key_value(hd, k->key_buf, v->value_buf, k->key_size, v->value_size);
		if (++key_count % 10000 == 0)
			log_info("Progress in population %llu keys", key_count);
	}
	log_info("Population ended testing scan");

	log_info("Cornercase scenario...");
	memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
	sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)base + 99);
	k->key_size = strlen(k->key_buf) + 1;

	scannerHandle *sc = (scannerHandle *)calloc(1, sizeof(scannerHandle));
	init_dirty_scanner(sc, hd, (struct key *)k, GREATER);
	assert(sc->keyValue != NULL);
	memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
	sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)base + 100);
	k->key_size = strlen(k->key_buf) + 1;

	if (memcmp(k->key_buf, sc->keyValue + sizeof(uint32_t), k->key_size) != 0) {
		log_fatal("Test failed key %s not found scanner instead returned %d:%s", k->key_buf,
			  *(uint32_t *)sc->keyValue, sc->keyValue + sizeof(uint32_t));
		exit(EXIT_FAILURE);
	}
	log_info("Milestone 1");

	getNext(sc);
	memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
	sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)base + 101);
	k->key_size = strlen(k->key_buf) + 1;
	if (memcmp(k->key_buf, sc->keyValue + sizeof(uint32_t), k->key_size) != 0) {
		log_fatal("Test failed key %s not found scanner instead returned %d:%s", k->key_buf,
			  *(uint32_t *)sc->keyValue, sc->keyValue + sizeof(uint32_t));
		exit(EXIT_FAILURE);
	}
	closeScanner(sc);
	sc = NULL;

	sc = (scannerHandle *)calloc(1, sizeof(scannerHandle));
	log_info("milestone 2");
	log_info("Cornercase scenario...DONE");

	for (uint64_t i = base; i < (base + (total_keys - scan_size)); ++i) {
		if (i % 100000 == 0)
			log_info("<Scan no %llu>", i);
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;

		init_dirty_scanner(sc, hd, (struct key *)k, GREATER_OR_EQUAL);
		assert(sc->keyValue != NULL);
		//log_info("key is %d:%s  malloced %d scanner size %d",k->key_size,k->key_buf,sc->malloced,sizeof(scannerHandle));
		//log_info("key of scanner %d:%s",*(uint32_t *)sc->keyValue,sc->keyValue + sizeof(uint32_t));
		if (memcmp(k->key_buf, sc->keyValue + sizeof(uint32_t), k->key_size) != 0) {
			log_fatal("Test failed key %s not found scanner instead returned %d:%s", k->key_buf,
				  *(uint32_t *)sc->keyValue, sc->keyValue + sizeof(uint32_t));
			exit(EXIT_FAILURE);
		}
		//element = stack_pop(&(sc->LEVEL_SCANNERS[0].stack));
		//assert(element.node->type == leafNode);
		//stack_push(&(sc->LEVEL_SCANNERS[0].stack), element);

		for (uint64_t j = 1; j <= scan_size; ++j) {
			/*construct the key we expect*/
			memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
			sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i + j);
			k->key_size = strlen(k->key_buf) + 1;
			//log_info("Expecting key %s",k->key_buf);
			if (getNext(sc) == END_OF_DATABASE) {
				log_warn("DB end at key %s is this correct? yes", k->key_buf);
				break;
			}
			if (memcmp(k, sc->keyValue, k->key_size) != 0) {
				log_fatal("Test failed key %s not found scanner instead returned %s", k->key_buf,
					  sc->keyValue + sizeof(uint32_t));
				exit(EXIT_FAILURE);
			}
			//log_info("done");
		}

		if (i % 100000 == 0)
			log_info("</Scan no %llu>", i);
		closeScanner(sc);
		sc = NULL;
		sc = (scannerHandle *)calloc(1, sizeof(scannerHandle));
	}
	log_info("scan test Successfull");
	free(k);
	return 1;
}

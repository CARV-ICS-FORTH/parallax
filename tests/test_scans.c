#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <log.h>
#include "../kreon_lib/btree/btree.h"
#include "../kreon_lib/scanner/scanner.h"
#include "../kreon_lib/scanner/min_max_heap.h"
#define KEY_PREFIX "userakias_computerakias"
#define KV_SIZE 1024
#define VOLUME_NAME "/usr/local/gesalous/mounts/kreon.dat"
#define NUM_KEYS 10000000
#define SCAN_SIZE 16
#define BASE 100000000
#define NUM_OF_ROUNDS 2
#define NUM_TESTERS 2
typedef struct key {
	uint32_t key_size;
	char key_buf[0];
} key;

typedef struct value {
	uint32_t value_size;
	char value_buf[0];
} value;

struct scan_tester_args {
	pthread_t cnxt;
	struct db_handle *handle;
	uint64_t base;
	uint64_t num_keys;
};

void *scan_tester(void *args)
{
	struct scan_tester_args *my_args = (struct scan_tester_args *)args;

	scannerHandle *sc = (scannerHandle *)malloc(sizeof(scannerHandle));
	uint64_t i = 0;
	uint64_t j = 0;
	key *k = (key *)malloc(KV_SIZE);

	for (int round = 0; round < NUM_OF_ROUNDS; ++round) {
		log_info("Round %d Starting population for %lu keys...", round, my_args->num_keys);
		int local_base = my_args->base + (round * my_args->num_keys);
		for (i = local_base; i < local_base + my_args->num_keys; i++) {
			memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
			sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
			k->key_size = strlen(k->key_buf) + 1;
			value *v = (value *)((uint64_t)k + sizeof(key) + k->key_size);
			v->value_size = KV_SIZE - ((2 * sizeof(key)) + k->key_size);
			memset(v->value_buf, 0xDD, v->value_size);
			insert_key_value(my_args->handle, k->key_buf, v->value_buf, k->key_size, v->value_size);
		}
		log_info("Population ended, snapshot and testing scan");
		snapshot(my_args->handle->volume_desc);

		log_info("Cornercase scenario...");
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)my_args->base + 99);
		k->key_size = strlen(k->key_buf) + 1;
		init_dirty_scanner(sc, my_args->handle, (key *)k, GREATER);
		assert(sc->keyValue != NULL);
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)my_args->base + 100);
		k->key_size = strlen(k->key_buf) + 1;
		if (memcmp(k->key_buf, sc->keyValue + sizeof(uint32_t), k->key_size) != 0) {
			log_fatal("seek failed key %s not found scanner instead returned %d:%s", k->key_buf,
				  *(uint32_t *)sc->keyValue, sc->keyValue + sizeof(uint32_t));
			exit(EXIT_FAILURE);
		}
		log_info("milestone 1");
		getNext(sc);
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)my_args->base + 101);
		k->key_size = strlen(k->key_buf) + 1;
		if (memcmp(k->key_buf, sc->keyValue + sizeof(uint32_t), k->key_size) != 0) {
			log_fatal("Test failed key %s not found scanner instead returned %d:%s", k->key_buf,
				  *(uint32_t *)sc->keyValue, sc->keyValue + sizeof(uint32_t));
			exit(EXIT_FAILURE);
		}
		closeScanner(sc);
		log_info("milestone 2");
		log_info("Cornercase scenario...DONE");

		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		for (i = local_base; i < local_base + my_args->num_keys; i++) {
			if (i % 100000 == 0)
				log_info("<Scan no %llu>", i);

			sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
			k->key_size = strlen(k->key_buf) + 1;

			init_dirty_scanner(sc, my_args->handle, (key *)k, GREATER_OR_EQUAL);
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
			int scan_size;
			if ((local_base + my_args->num_keys) - i > SCAN_SIZE)
				scan_size = SCAN_SIZE;
			else
				scan_size = (local_base + my_args->num_keys) - i;

			for (j = 1; j < scan_size; j++) {
				/*construct the key we expect*/
				memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
				sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i + j);
				k->key_size = strlen(k->key_buf) + 1;
				//log_info("Expecting key %s",k->key_buf);
				if (getNext(sc) == END_OF_DATABASE) {
					log_fatal("DB end at key %s is this correct? NO", k->key_buf);
					exit(EXIT_FAILURE);
				}
				if (k->key_size != *(uint32_t *)sc->keyValue ||
				    memcmp(k->key_buf, sc->keyValue + 4, k->key_size) != 0) {
					log_fatal("Test failed key %s not found scanner instead returned %s",
						  k->key_buf, sc->keyValue + sizeof(uint32_t));
					log_info("Min heap state is");
					struct sh_heap_node nd;
					while (sh_remove_min(&sc->heap, &nd) != EMPTY_MIN_HEAP) {
						log_info("Key %s from Tree[%d][%d]", nd.data + 4, nd.level_id,
							 nd.active_tree);
					}
					log_info("Is it actually there? Let's search and report the stack");

					struct scannerHandle *scd = (scannerHandle *)malloc(sizeof(scannerHandle));
					init_dirty_scanner(scd, my_args->handle, (key *)k, GREATER_OR_EQUAL);
					log_info("Scanner returned %s", scd->keyValue + 4);
					while (sh_remove_min(&scd->heap, &nd) != EMPTY_MIN_HEAP) {
						log_info("Key %s from Tree[%d][%d]", nd.data + 4, nd.level_id,
							 nd.active_tree);
					}
					exit(EXIT_FAILURE);
				}
				//log_info("done");
			}

			if (i % 100000 == 0)
				log_info("</Scan no %llu>", i);
			closeScanner(sc);
		}
		log_info("Round %d of scan test Successfull", round + 1);
		if (round < NUM_OF_ROUNDS - 1)
			log_info("Proceeding to next %d round", round);
	}
	free(k);
	free(sc);
	return NULL;
}

int main()
{
	char db_name[64];
	struct scan_tester_args *s_args =
		(struct scan_tester_args *)malloc(sizeof(struct scan_tester_args) * NUM_TESTERS);

	struct db_handle *hd = NULL;
	if (NUM_TESTERS % 2 != 0) {
		log_fatal("Threads must be a multiple of 2");
		exit(EXIT_FAILURE);
	}
	for (int i = 0; i < NUM_TESTERS; i++) {
		if (i % 2 == 0) {
			sprintf(db_name, "%s_%d", "scan_test", i);
			hd = db_open(VOLUME_NAME, 0, (120 * 1024 * 1024 * 1024L), "scan_test", CREATE_DB);
		}
		s_args[i].handle = hd;
		s_args[i].base = BASE + (i * NUM_OF_ROUNDS * NUM_KEYS);
		s_args[i].num_keys = NUM_KEYS;
		if (pthread_create(&s_args[i].cnxt, NULL, scan_tester, &s_args[i]) != 0) {
			log_fatal("Failed to spawn scan_tester number %d", i);
			exit(EXIT_FAILURE);
		}
	}
	for (int i = 0; i < NUM_TESTERS; i++) {
		if (pthread_join(s_args[i].cnxt, NULL) != 0) {
			log_fatal("Failed to join for tester %d", i);
			exit(EXIT_FAILURE);
		}
	}
	free(s_args);
	log_info("All tests successfull");
}

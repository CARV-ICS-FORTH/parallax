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
#include "btree/btree.h"
#include <allocator/volume_manager.h>
#include <assert.h>
#include <fcntl.h>
#include <log.h>
#include <parallax/parallax.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if 0
#define KEY_PREFIX "ld"
#define KV_SIZE 512
//#define VOLUME_NAME "/tmp/ramdisk/kreon1.dat"
//#define VOLUME_SIZE (40 * 1024 * 1024 * 1024L)
#define NUM_KEYS 10000000
#define SCAN_SIZE 16
#define BASE 100000000
#define NUM_OF_ROUNDS 1
#define NUM_TESTERS 1

struct scan_tester_args {
	pthread_t cnxt;
	par_handle handle;
	uint64_t base;
	uint64_t num_keys;
};

void *scan_tester(void *args)
{
	struct scan_tester_args *my_args = (struct scan_tester_args *)args;
	struct par_key_value kv;
	uint64_t i = 0;
	uint64_t j = 0;
	kv.k.data = (char *)malloc(KV_SIZE);
	kv.v.data = (char *)malloc(KV_SIZE);

	for (int round = 0; round < NUM_OF_ROUNDS; ++round) {
		log_info("Round %d Starting population for %lu keys...", round, my_args->num_keys);
		int local_base = my_args->base + (round * my_args->num_keys);
		for (i = local_base; i < local_base + my_args->num_keys; i++) {
			memcpy((char *)kv.k.data, KEY_PREFIX, strlen(KEY_PREFIX));
			sprintf((char *)kv.k.data + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
			kv.k.size = strlen(kv.k.data) + 1;
			kv.v.size = KV_SIZE;
			memset((char *)kv.v.data, 0xDD, kv.v.size);
			if (par_put(my_args->handle, &kv) != PAR_SUCCESS) {
				log_fatal("Put failed");
				exit(EXIT_FAILURE);
			}
			if (i % 10000 == 0)
				log_info("put ops %lu", i);
		}
		log_info("Population ended, testing scan");
		par_sync(my_args->handle);

		memcpy((char *)kv.k.data, KEY_PREFIX, strlen(KEY_PREFIX));
		for (i = local_base; i < local_base + my_args->num_keys; i++) {
			if (i % 100000 == 0)
				log_info("<Scan no %llu>", i);

			sprintf((char *)kv.k.data + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
			kv.k.size = strlen(kv.k.data) + 1;

			par_scanner s = par_init_scanner(my_args->handle, &kv.k, PAR_GREATER_OR_EQUAL);
			assert(par_is_valid(s));

			struct par_key keyptr = par_get_key(s);
			if (keyptr.size != kv.k.size || memcmp(kv.k.data, keyptr.data, kv.k.size) != 0) {
				log_fatal("Test failed key %s not found scanner instead returned %d:%s", kv.k.data,
					  keyptr.size, keyptr);

				exit(EXIT_FAILURE);
			}

			// element = stack_pop(&(sc->LEVEL_SCANNERS[0].stack));
			// assert(element.node->type == leafNode);
			// stack_push(&(sc->LEVEL_SCANNERS[0].stack), element);
			uint64_t scan_size;
			if ((local_base + my_args->num_keys) - i > SCAN_SIZE)
				scan_size = SCAN_SIZE;
			else
				scan_size = (local_base + my_args->num_keys) - i;

			for (j = 1; j < scan_size; j++) {
				/*construct the key we expect*/
				memcpy((char *)kv.k.data, KEY_PREFIX, strlen(KEY_PREFIX));
				sprintf((char *)kv.k.data + strlen(KEY_PREFIX), "%llu", (long long unsigned)i + j);
				kv.k.size = strlen(kv.k.data) + 1;
				// log_info("Expecting key %s",k->key_buf);
				if (par_get_next(s) && !par_is_valid(s)) {
					log_fatal("DB end at key %s is this correct? NO", kv.k.data);
					exit(EXIT_FAILURE);
				}
				keyptr = par_get_key(s);
				if (kv.k.size != keyptr.size || memcmp(kv.k.data, keyptr.data, kv.k.size) != 0) {
					log_fatal("Test failed key %s not found scanner instead returned %s", kv.k.data,
						  keyptr);
				}
				// log_info("done");
			}

			if (i % 100000 == 0)
				log_info("</Scan no %llu>", i);
			par_close_scanner(s);
		}
		log_info("Round %d of scan test Successfull", round + 1);

		// gets now
		log_info("Now testing gets");
		local_base = my_args->base + (round * my_args->num_keys);
		for (i = local_base; i < local_base + my_args->num_keys; i++) {
			if (i % 500000 == 0)
				log_info("Success up to key %s", kv.k.data);
			memcpy((char *)kv.k.data, KEY_PREFIX, strlen(KEY_PREFIX));
			sprintf((char *)kv.k.data + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
			kv.k.size = strlen(kv.k.data) + 1;
			struct par_value *value = NULL;
			if (find_key(my_args->handle, (char *)&kv.k.data, kv.k.size) != PAR_SUCCESS) {
				log_fatal("Key %s not found !", kv.k.data);
				exit(EXIT_FAILURE);
			}
			free(value);
		}
		log_info("Get test successful!");

		log_info("Delete test deleting odd keys isnt supported yet..");
		memcpy((char *)kv.k.data, KEY_PREFIX, strlen(KEY_PREFIX));
		for (i = local_base + 1; i < (local_base + my_args->num_keys); i = i + 2) {
			sprintf((char *)kv.k.data + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
			kv.k.size = strlen(kv.k.data) + 1;
			/* if (par_delete(my_args->handle, &kv.k) != PAR_SUCCESS) { */
			/* 	log_fatal("Failed to delete key %s", kv.k.data); */
			/* 	exit(EXIT_FAILURE); */
			/* } */
		}

		memcpy((char *)kv.k.data, KEY_PREFIX, strlen(KEY_PREFIX));
		//log_info("Deleting done now looking up");
		for (i = local_base; i < local_base + my_args->num_keys; i++) {
			sprintf((char *)kv.k.data + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
			kv.k.size = strlen(kv.k.data) + 1;
			struct par_value *value = NULL;
			int ret;
			if (find_key(my_args->handle, (char *)&kv.k.data, kv.k.size) != PAR_SUCCESS)
				ret = PAR_KEY_NOT_FOUND;
			else
				ret = PAR_SUCCESS;

			//Delete isnt supported yet so this part would not work. Just check that all keys are live again for now
			if (ret == PAR_KEY_NOT_FOUND) {
				log_fatal("Didnt found key %s that should be live", kv.k.data);
				assert(EXIT_FAILURE);
			}
			/*if (ret == PAR_KEY_NOT_FOUND && i % 2 == 0) {
				log_fatal("key %s not found! i = %d", kv.k.data, i);
				exit(EXIT_FAILURE);
			}
			if (ret != PAR_KEY_NOT_FOUND && i % 2 == 1) {
				log_fatal("key %s found whereas was deleted previously i %d", kv.k.data, i);
				exit(EXIT_FAILURE);
			}*/

			free(value);
			if (i % 500000 == 0)
				log_info("Success up to key %s", kv.k.data);
		}
		//log_info("Delete test successful!");
		log_info("Finally testing that scans ignore deleted KV pairs. Deletes are not implemented just yet..");
		/*memcpy((char *)kv.k.data, KEY_PREFIX, strlen(KEY_PREFIX));
		for (i = local_base; i < local_base + my_args->num_keys; i += 2) {
			if (i % 100000 == 0)
				log_info("<Scan no %llu>", i);

			sprintf((char *)kv.k.data + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
			kv.k.size = strlen(kv.k.data) + 1;

			par_scanner s = par_init_scanner(my_args->handle, &kv.k, PAR_GREATER_OR_EQUAL);
			assert(par_is_valid(s));
			// log_info("key is %d:%s  malloced %d scanner size
			// %d",k->key_size,k->key_buf,sc->malloced,sizeof(scannerHandle));
			// log_info("key of scanner %d:%s",*(uint32_t *)sc->keyValue,sc->keyValue
			// + sizeof(uint32_t));
			struct par_key keyptr = par_get_key(s);
			if (keyptr.size != kv.k.size || memcmp(kv.k.data, keyptr.data, kv.k.size) != 0) {
				log_fatal("Test failed key %s not found scanner instead returned %d:%s", kv.k.data,
					  keyptr.size, keyptr);

				exit(EXIT_FAILURE);
			}

			// element = stack_pop(&(sc->LEVEL_SCANNERS[0].stack));
			// assert(element.node->type == leafNode);
			// stack_push(&(sc->LEVEL_SCANNERS[0].stack), element);
			uint64_t scan_size;
			if ((local_base + my_args->num_keys) - i > SCAN_SIZE)
				scan_size = SCAN_SIZE;
			else
				scan_size = (local_base + my_args->num_keys) - i;

			for (j = 2; j < scan_size; j += 2) {
			    //construct the key we expect
				memcpy((char *)kv.k.data, KEY_PREFIX, strlen(KEY_PREFIX));
				sprintf((char *)kv.k.data + strlen(KEY_PREFIX), "%llu", (long long unsigned)i + j);
				kv.k.size = strlen(kv.k.data) + 1;
				// log_info("Expecting key %s",k->key_buf);
				if (par_get_next(s) && !par_is_valid(s)) {
					log_fatal("DB end at key %s is this correct? NO", kv.k.data);
					exit(EXIT_FAILURE);
				}
				keyptr = par_get_key(s);
				if (kv.k.size != keyptr.size || memcmp(kv.k.data, keyptr.data, kv.k.size) != 0) {
					log_fatal("Test failed key %s not found scanner instead returned %s", kv.k.data,
						  keyptr);
				}
			}

			if (i % 100000 == 0)
				log_info("</Scan no %llu>", i);
			par_close_scanner(s);
		}
		log_info("Scans after delete successfull!");
		*/
		if (round < NUM_OF_ROUNDS - 1)
			log_info("Proceeding to next %d round", round);
	}

	free((char *)kv.k.data);
	free((char *)kv.v.data);
	return NULL;
}
#endif

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	return 1;
#if 0
	if (argc < 2) {
		log_fatal("Wrong input. Usage ./test_api <filename>");
		exit(EXIT_FAILURE);
	}
	char db_name[64];
	struct scan_tester_args *s_args =
		(struct scan_tester_args *)malloc(sizeof(struct scan_tester_args) * NUM_TESTERS);
	par_db_options db_options;
	if (NUM_TESTERS > 1 && NUM_TESTERS % 2 != 0) {
		log_fatal("Threads must be a multiple of 2");
		exit(EXIT_FAILURE);
	}

	if (strlen(argv[1]) >= 5 && strncmp(argv[1], "/dev/", 5) == 0) {
		log_fatal("Volume is a raw device %s current version does not support it!", argv[1]);
		exit(EXIT_FAILURE);
	} else {
		int64_t size;
		int fd = open(argv[1], O_RDWR);
		if (fd == -1) {
			perror("open");
			exit(EXIT_FAILURE);
		}
		size = lseek(fd, 0, SEEK_END);
		if (size == -1) {
			log_fatal("failed to determine file size exiting...");
			perror("ioctl");
			exit(EXIT_FAILURE);
		}
		close(fd);
		log_info("Size is %lld", size);
		volume_init(argv[1], 0, size, 1);
		db_options.volume_size = size;
	}

	db_options.volume_start = 0;
	db_options.volume_name = argv[1];

	db_options.create_flag = PAR_CREATE_DB;

	par_handle hd;
	for (int i = 0; i < NUM_TESTERS; i++) {
		if (i % 2 == 0) {
			sprintf(db_name, "%s_%d", "scan_test", i);
			db_options.db_name = db_name;
			hd = par_open(&db_options);
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
	char * error_message = par_close(hd);
	if(error_message){
		log_fatal("%s",error_message);
		free(error_message);
		return EXIT_FAILURE;
	}
	log_info("All tests successfull");
#endif
}

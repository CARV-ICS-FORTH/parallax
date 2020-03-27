#include <assert.h>
#include <stdio.h>
#include <alloca.h>
#include <string.h>
#include <stdlib.h>
#include "../build/external-deps/log/src/log.h"
#include "../kreon_lib/btree/btree.h"
#include "../kreon_rdma_client/kreon_rdma_client.h"
#define TOTAL_KEYS 1000000
#define KEY_PREFIX "userakias_computerakias"
#define KV_SIZE 1024
#define NUM_KEYS 1000000
#define SCAN_SIZE 50
#define PREFETCH_ENTRIES 16
#define PREFETCH_MEM_SIZE (32 * 1024)
#define ZOOKEEPER "127.0.0.1"

typedef struct key {
	uint32_t key_size;
	char key_buf[0];
} key;

typedef struct value {
	uint32_t value_size;
	char value_buf[0];
} value;

int main()
{
	uint32_t error_code;
	krc_handle *hd = krc_init(ZOOKEEPER, 2181, &error_code);
	if (error_code != KREON_SUCCESS) {
		log_fatal("failed to init");
		exit(EXIT_FAILURE);
	}

	uint64_t i = 0;
	uint64_t j = 0;
	krc_scanner *sc;
	key *k = (key *)malloc(KV_SIZE);
	log_info("Starting population for %lu keys...", NUM_KEYS);
	for (i = 100000000; i < (100000000 + NUM_KEYS); i++) {
		strncpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		value *v = (value *)((uint64_t)k + sizeof(key) + k->key_size);
		v->value_size = KV_SIZE - ((2 * sizeof(key)) + k->key_size);
		memset(v->value_buf, 0xDD, v->value_size);
		krc_put(hd, k->key_size, k->key_buf, v->value_size, v->value_buf);
	}
	log_info("Population ended, testing scan");

	for (i = 100000000; i < (100000000 + (NUM_KEYS - SCAN_SIZE)); i++) {
		if (i % 100000 == 0)
			log_info("<Scan no %llu>", i);
		strncpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;

		sc = krc_scan_init(hd, PREFETCH_ENTRIES, PREFETCH_MEM_SIZE);
		krc_scan_set_start(sc, k->key_size, k->key_buf);
		//log_info("key is %d:%s  malloced %d scanner size %d",k->key_size,k->key_buf,sc->malloced,sizeof(scannerHandle));
		//log_info("key of scanner %d:%s",*(uint32_t *)sc->keyValue,sc->keyValue + sizeof(uint32_t));
		if (!krc_scan_is_valid(sc) || k->key_size != sc->curr_key->key_size ||
		    memcmp(k->key_buf, sc->curr_key->key_buf, k->key_size) != 0) {
			log_fatal("Test failed key %s not found scanner instead returned %d:%s", k->key_buf,
				  sc->curr_key->key_size, sc->curr_key->key_buf);
			exit(EXIT_FAILURE);
		}

		for (j = 1; j <= SCAN_SIZE; j++) {
			/*construct the key we expect*/
			strncpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
			sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i + j);
			k->key_size = strlen(k->key_buf) + 1;
			//log_info("Expecting key %s",k->key_buf);
			krc_scan_get_next(sc);
			if (!krc_scan_is_valid(sc) || k->key_size != sc->curr_key->key_size ||
			    memcmp(k->key_buf, sc->curr_key->key_buf, k->key_size) != 0) {
				log_fatal("Test failed key %s not found scanner instead returned %d:%s", k->key_buf,
					  sc->curr_key->key_size, sc->curr_key->key_buf);
				exit(EXIT_FAILURE);
			}
		}

		if (i % 100000 == 0)
			log_info("</Scan no %llu>", i);
		krc_scan_close(sc);
	}
	log_info("small scan test Successfull");
	log_info("Running a full scan");

	sc = krc_scan_init(hd, PREFETCH_ENTRIES, PREFETCH_MEM_SIZE);
	krc_scan_set_start(sc, 7, "0000000");
	for (i = 100000000; i < (100000000 + NUM_KEYS); i++) {
		strncpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		//log_info("key is %d:%s  malloced %d scanner size %d",k->key_size,k->key_buf,sc->malloced,sizeof(scannerHandle));
		//log_info("key of scanner %d:%s",*(uint32_t *)sc->keyValue,sc->keyValue + sizeof(uint32_t));
		if (!krc_scan_is_valid(sc) || k->key_size != sc->curr_key->key_size ||
		    memcmp(k->key_buf, sc->curr_key->key_buf, k->key_size) != 0) {
			log_fatal("Test failed key %s not found scanner instead returned %d:%s", k->key_buf,
				  sc->curr_key->key_size, sc->curr_key->key_buf);
			exit(EXIT_FAILURE);
		}
		krc_scan_close(sc);
	}
	log_info("full scan test Successfull");
	return 1;
}



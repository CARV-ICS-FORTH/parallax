#include <assert.h>
#include <stdio.h>
#include <alloca.h>
#include <string.h>
#include <stdlib.h>
#include "../build/external-deps/log/src/log.h"
#include "../kreon_lib/btree/btree.h"
#include "../kreon_lib/scanner/scanner.h"
#define TOTAL_KEYS 1000000
#define KEY_PREFIX "userakias_computerakias"
#define KV_SIZE 1024
#define VOLUME_NAME "/dev/nvme0n1"
#define NUM_KEYS 1000000
#define SCAN_SIZE 50

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
	bt_insert_req req;
	stackElementT element;
	db_handle *hd = db_open(VOLUME_NAME, 0, 250059350016L, "scan_test", CREATE_DB);

	scannerHandle *sc = (scannerHandle *)malloc(sizeof(scannerHandle));
	uint64_t i = 0;
	uint64_t j = 0;
	key *k = (key *)malloc(KV_SIZE);
	log_info("Starting population for %lu keys...", NUM_KEYS);
	for (i = 100000000; i < (100000000 + NUM_KEYS); i++) {
		strncpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		value *v = (value *)((uint64_t)k + sizeof(key) + k->key_size);
		v->value_size = KV_SIZE - ((2 * sizeof(key)) + k->key_size);
		memset(v->value_buf, 0xDD, v->value_size);

		req.handle = hd;
		req.kv_size = k->key_size + v->value_size + (2 * sizeof(uint32_t));
		assert(req.kv_size == KV_SIZE);
		req.key_value_buf = k;
		req.level_id = 0;
		req.key_format = KV_FORMAT;
		req.append_to_log = 1;
		req.gc_request = 0;
		req.recovery_request = 0;
		_insert_key_value(&req);
	}
	log_info("Population ended, snapshot and testing scan");
	snapshot(hd->volume_desc);

	for (i = 100000000; i < (100000000 + (NUM_KEYS - SCAN_SIZE)); i++) {
		if (i % 100000 == 0)
			log_info("<Scan no %llu>", i);
		strncpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;

		initScanner(sc, hd, (key *)k, GREATER_OR_EQUAL);
		assert(sc->keyValue != NULL);
		//log_info("key is %d:%s  malloced %d scanner size %d",k->key_size,k->key_buf,sc->malloced,sizeof(scannerHandle));
		//log_info("key of scanner %d:%s",*(uint32_t *)sc->keyValue,sc->keyValue + sizeof(uint32_t));
		if (memcmp(k->key_buf, sc->keyValue + sizeof(uint32_t), k->key_size) != 0) {
			log_fatal("Test failed key %s not found scanner instead returned %d:%s", k->key_buf,
				  *(uint32_t *)sc->keyValue, sc->keyValue + sizeof(uint32_t));
			exit(EXIT_FAILURE);
		}
		element = stack_pop(&(sc->LEVEL_SCANNERS[0].stack));
		assert(element.node->type == leafNode);
		stack_push(&(sc->LEVEL_SCANNERS[0].stack), element);

		for (j = 1; j <= SCAN_SIZE; j++) {
			/*construct the key we expect*/
			strncpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
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
	}
	log_info("scan test Successfull");
	free(k);
	free(sc);
	return 1;
}

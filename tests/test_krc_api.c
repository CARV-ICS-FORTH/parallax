#include <assert.h>
#include <stdio.h>
#include <alloca.h>
#include <string.h>
#include <stdlib.h>
#include <log.h>
//#include "../kreon_lib/btree/btree.h"
#include "../kreon_rdma_client/kreon_rdma_client.h"
#include "../kreon_server/globals.h"
#include "../kreon_server/create_regions_utils.h"

#define PREFIX_TEST_KEYS 300
#define PREFIX_1 "userakiaslala"
#define PREFIX_2 "userakiaslalb"
#define PREFIX_3 "userakiaslalc"
#define infinity "+oo"
#define NUM_KEYS 1000 //1000000
#define BASE 1000000
#define NUM_REGIONS 16
#define KEY_PREFIX "userakias"
#define KV_SIZE 1024
#define UPDATES 100
#define SCAN_SIZE 50
#define PREFETCH_ENTRIES 16
#define PREFETCH_MEM_SIZE (32 * 1024)
char ZOOKEEPER[256];
char HOST[256]; //"tie3.cluster.ics.forth.gr-8080"

extern ZooLogLevel logLevel;
typedef struct key {
	uint32_t key_size;
	char key_buf[];
} key;

typedef struct value {
	uint32_t value_size;
	char value_buf[];
} value;

int main(int argc, char *argv[])
{
	krc_value *val;
	uint32_t region_id = 0;
	uint64_t range = NUM_KEYS / NUM_REGIONS;
	uint64_t min_key, max_key;
	uint32_t error_code;
	if (argc == 1) {
		log_fatal("Wrong format test_krc_api <zookeeper_host:port>");
		exit(EXIT_FAILURE);
	} else if (argc == 2) {
		strcpy(ZOOKEEPER, argv[1]);
	} else if (argc > 2 && strcmp(argv[3], "--create_regions") == 0) {
		strcpy(ZOOKEEPER, argv[1]);
		strcpy(HOST, argv[2]);
		globals_set_zk_host(ZOOKEEPER);
		log_info("Creating %d regions", NUM_REGIONS);

		char *args_buf[14];
		args_buf[1] = strdup("-c");
		/*static fields*/
		args_buf[8] = "--size";
		args_buf[9] = "1000000";

		args_buf[10] = "--host";
		args_buf[11] = strdup(HOST);
		args_buf[12] = "--zookeeper";
		args_buf[13] = strdup(ZOOKEEPER);

		args_buf[4] = strdup("--minkey");
		args_buf[5] = malloc(16);
		args_buf[6] = strdup("--maxkey");
		args_buf[7] = malloc(16);
		/*dynamic fields*/
		for (region_id = 0; region_id < NUM_REGIONS - 1; region_id++) {
			min_key = BASE + (region_id * range);
			max_key = min_key + range;
			args_buf[2] = strdup("--region");
			args_buf[3] = (char *)malloc(16);
			sprintf(args_buf[3], "%u", region_id);
			if (region_id == 0)
				sprintf(args_buf[5], "%s", "0000000");
			else
				sprintf(args_buf[5], "userakias%lu", min_key);
			sprintf(args_buf[7], "userakias%lu", max_key);
			create_region(13, args_buf);
			log_info("Created region id %s minkey %s maxkey %s", args_buf[2], args_buf[4], args_buf[6]);
		}
		/*last region*/
		min_key = BASE + (region_id * range);
		sprintf(args_buf[3], "%u", region_id);
		sprintf(args_buf[5], "userakias%lu", min_key);
		sprintf(args_buf[7], "+oo");
		create_region(13, args_buf);
		log_info("Created region id %s minkey %s maxkey %s", args_buf[2], args_buf[4], args_buf[6]);
	}
	logLevel = ZOO_LOG_LEVEL_INFO;

	if (krc_init(ZOOKEEPER, 2181) != KRC_SUCCESS) {
		log_fatal("Failed to init library");
		exit(EXIT_FAILURE);
	}

	uint64_t i = 0;
	uint64_t j = 0;
	krc_scanner *sc;
	key *k = (key *)malloc(KV_SIZE);
	log_info("Starting population for %lu keys...", NUM_KEYS);
	for (i = BASE; i < (BASE + NUM_KEYS); i++) {
		strncpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		if (i % 100000 == 0)
			log_info("inserted up to %llu th key", i);

		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		value *v = (value *)((uint64_t)k + sizeof(key) + k->key_size);
		v->value_size = KV_SIZE - ((2 * sizeof(key)) + k->key_size);
		memset(v->value_buf, 0xDD, v->value_size);
		krc_put(k->key_size, k->key_buf, v->value_size, v->value_buf);
	}
	log_info("Population ended, testing gets");
	for (i = BASE; i < (BASE + NUM_KEYS); i++) {
		strncpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		if (i % 100000 == 0)
			log_info("looked up to %llu th key", i);

		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		val = krc_get(k->key_size, k->key_buf, 2 * 1024, &error_code);
		if (error_code != KRC_SUCCESS) {
			log_fatal("key %s not found test failed!");
			exit(EXIT_FAILURE);
		}
		free(val);
	}

	log_info("Gets successful ended, testing small put/get with offset....");
	uint64_t offset = 0;
	uint32_t sum = 0;
	uint32_t sum_g = 0;
	strncpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
	sprintf(k->key_buf + strlen(KEY_PREFIX), "%d", 40000000);
	k->key_size = strlen(k->key_buf) + 1;
	value *v = (value *)((uint64_t)k + sizeof(key) + k->key_size);
	v->value_size = sizeof(uint32_t);

	krc_put_with_offset(k->key_size, k->key_buf, 0, sizeof(uint32_t) * UPDATES, v->value_buf);
	for (i = 0; i < UPDATES; i++) {
		*(uint32_t *)(v->value_buf) = i;
		krc_put_with_offset(k->key_size, k->key_buf, offset, v->value_size, v->value_buf);
		sum += i;
		offset += sizeof(uint32_t);
	}
	/*perform get with offset to verify it is correct*/

	offset = 0;
	for (i = 0; i < UPDATES; i++) {
		val = krc_get_with_offset(k->key_size, k->key_buf, offset, sizeof(uint32_t), &error_code);
		if (val == NULL) {
			log_fatal("key not found");
			exit(EXIT_FAILURE);
		}
		sum_g += (*(uint32_t *)val->val_buf);
		free(val);
		offset += sizeof(uint32_t);
	}
	if (sum_g != sum) {
		log_fatal("Sums differ expected %sum got %u", sum, sum_g);
		exit(EXIT_FAILURE);
	}

	log_info("Put/get with offset successful expected %u got %u, testing small scans....", sum, sum_g);

	for (i = BASE; i < (BASE + (NUM_KEYS - SCAN_SIZE)); i++) {
		if (i % 10000 == 0)
			log_info("<Scan no %llu>", i);

		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		strncpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;

		sc = krc_scan_init(PREFETCH_ENTRIES, PREFETCH_MEM_SIZE);
		krc_scan_set_start(sc, k->key_size, k->key_buf, KRC_GREATER_OR_EQUAL);
		krc_scan_get_next(sc);
		if (!krc_scan_is_valid(sc)) {
			log_fatal("Test failed key %s invalid scanner (it shoulddn't!)", k->key_buf);
			exit(EXIT_FAILURE);
		}
		if (k->key_size != sc->curr_key->key_size ||
		    memcmp(k->key_buf, sc->curr_key->key_buf, k->key_size) != 0) {
			log_fatal("Test failed key %s not found scanner instead returned %d:%s", k->key_buf,
				  sc->curr_key->key_size, sc->curr_key->key_buf);
			assert(0);
			exit(EXIT_FAILURE);
		}

		for (j = 1; j <= SCAN_SIZE; j++) {
			/*construct the key we expect*/
			strncpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
			sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i + j);
			k->key_size = strlen(k->key_buf) + 1;
			//log_info("Expecting key %s",k->key_buf);
			krc_scan_get_next(sc);
			if (!krc_scan_is_valid(sc)) {
				log_fatal("Test failed key %s not found scanner reason scan invalid!(it shouldn't)",
					  k->key_buf);
				assert(0);
				exit(EXIT_FAILURE);
			}
			if (k->key_size != sc->curr_key->key_size ||
			    memcmp(k->key_buf, sc->curr_key->key_buf, k->key_size) != 0) {
				log_fatal("Test failed key %s not found scanner instead returned %d:%s", k->key_buf,
					  sc->curr_key->key_size, sc->curr_key->key_buf);
				exit(EXIT_FAILURE);
			}
		}

		if (i % 10000 == 0)
			log_info("</Scan no %llu>", i);
		krc_scan_close(sc);
	}
	log_info("small scan test Successfull");

	log_info("Running a full scan");

	sc = krc_scan_init(PREFETCH_ENTRIES, PREFETCH_MEM_SIZE);
	krc_scan_set_start(sc, 7, "0000000", KRC_GREATER_OR_EQUAL);
	for (i = BASE; i < (BASE + NUM_KEYS); i++) {
		strncpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;

		krc_scan_get_next(sc);
		if (!krc_scan_is_valid(sc)) {
			log_fatal("Test failed key %s invalid scanner (it shoulddn't!)", k->key_buf);
			exit(EXIT_FAILURE);
		}
		if (k->key_size != sc->curr_key->key_size ||
		    memcmp(k->key_buf, sc->curr_key->key_buf, k->key_size) != 0) {
			log_fatal("Test failed key %s not found scanner instead returned %d:%s", k->key_buf,
				  sc->curr_key->key_size, sc->curr_key->key_buf);
			exit(EXIT_FAILURE);
		}
	}
	krc_scan_close(sc);
	log_info("full scan test Successfull");

	int tuples = 0;
	log_info("Testing stop key");
	sc = krc_scan_init(PREFETCH_ENTRIES, PREFETCH_MEM_SIZE);
	krc_scan_set_start(sc, 7, "0000000", KRC_GREATER_OR_EQUAL);
	sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)BASE + (NUM_KEYS / 2));
	krc_scan_set_stop(sc, strlen(k->key_buf), k->key_buf, KRC_GREATER);
	for (i = BASE; i < (BASE + NUM_KEYS); i++) {
		strncpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		krc_scan_get_next(sc);
		if (!krc_scan_is_valid(sc))
			break;
		if (k->key_size != sc->curr_key->key_size ||
		    memcmp(k->key_buf, sc->curr_key->key_buf, k->key_size) != 0) {
			log_fatal("Test failed key %s not found scanner instead returned %d:%s", k->key_buf,
				  sc->curr_key->key_size, sc->curr_key->key_buf);
			exit(EXIT_FAILURE);
		}
		++tuples;
	}
	if (tuples != NUM_KEYS / 2) {
		log_fatal("Error tuples got %d expected %d", tuples, NUM_KEYS / 2);
		exit(EXIT_FAILURE);
	}

	krc_scan_close(sc);
	log_info("Stop key test successful");
	log_info("Testing prefix key");
	tuples = 0;
	sc = krc_scan_init(PREFETCH_ENTRIES, PREFETCH_MEM_SIZE);
	krc_scan_set_start(sc, 7, "0000000", KRC_GREATER_OR_EQUAL);
	sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)BASE + 111);
	krc_scan_set_prefix_filter(sc, strlen(k->key_buf), k->key_buf);
	for (i = BASE; i < (BASE + NUM_KEYS); i++) {
		krc_scan_get_next(sc);
		if (!krc_scan_is_valid(sc))
			break;
		++tuples;
	}
	if (tuples != 1) {
		log_fatal("Error tuples got %d expected %d", tuples, 1);
		exit(EXIT_FAILURE);
	}
	log_info("Prefix key test successful");
	krc_scan_close(sc);
	log_info("Deleting half keys");
	for (i = BASE; i < BASE + (NUM_KEYS / 2); i++) {
		strncpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		if (i % 100000 == 0)
			log_info("deleted up to %llu th key", i);

		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		if (krc_delete(k->key_size, k->key_buf) != KRC_SUCCESS) {
			log_fatal("key %s not found failed to delete test failed!");
			exit(EXIT_FAILURE);
		}
	}
	log_info("Verifying delete outcome");
	tuples = 0;
	for (i = BASE; i < (BASE + NUM_KEYS); i++) {
		if (i % 100000 == 0)
			log_info("looked up to %llu th key", i);

		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		if (krc_exists(k->key_size, k->key_buf))
			++tuples;
	}
	if (tuples != NUM_KEYS / 2) {
		log_fatal("Test failed found %u keys should find %u", tuples, NUM_KEYS / 2);
		exit(EXIT_FAILURE);
	}
	log_info("Delete test success! :-)");
	log_info("Testing prefix match scans");
	log_info("loading keys %u keys with prefix %s", PREFIX_TEST_KEYS, PREFIX_1);
	strncpy(k->key_buf, PREFIX_1, strlen(PREFIX_1));
	for (i = 0; i < PREFIX_TEST_KEYS; i++) {
		sprintf(k->key_buf + strlen(PREFIX_1), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		value *v = (value *)((uint64_t)k + sizeof(key) + k->key_size);
		v->value_size = KV_SIZE - ((2 * sizeof(key)) + k->key_size);
		memset(v->value_buf, 0xDD, v->value_size);
		krc_put(k->key_size, k->key_buf, v->value_size, v->value_buf);
	}
	log_info("Done loading keys %u keys with prefix %s", PREFIX_TEST_KEYS, PREFIX_1);
	log_info("loading keys %u keys with prefix %s", PREFIX_TEST_KEYS, PREFIX_2);
	strncpy(k->key_buf, PREFIX_2, strlen(PREFIX_2));
	for (i = 0; i < PREFIX_TEST_KEYS; i++) {
		sprintf(k->key_buf + strlen(PREFIX_2), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		value *v = (value *)((uint64_t)k + sizeof(key) + k->key_size);
		v->value_size = KV_SIZE - ((2 * sizeof(key)) + k->key_size);
		memset(v->value_buf, 0xDD, v->value_size);
		krc_put(k->key_size, k->key_buf, v->value_size, v->value_buf);
	}
	log_info("Done loading keys %u keys with prefix %s", PREFIX_TEST_KEYS, PREFIX_2);
	log_info("loading keys %u keys with prefix %s", PREFIX_TEST_KEYS, PREFIX_3);
	strncpy(k->key_buf, PREFIX_3, strlen(PREFIX_3));
	for (i = 0; i < PREFIX_TEST_KEYS; i++) {
		sprintf(k->key_buf + strlen(PREFIX_1), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		value *v = (value *)((uint64_t)k + sizeof(key) + k->key_size);
		v->value_size = KV_SIZE - ((2 * sizeof(key)) + k->key_size);
		memset(v->value_buf, 0xDD, v->value_size);
		krc_put(k->key_size, k->key_buf, v->value_size, v->value_buf);
	}
	log_info("Done loading keys %u keys with prefix %s", PREFIX_TEST_KEYS, PREFIX_3);
	char *prefix_start;
	char *prefix_stop;

	for (j = 0; j < 3; j++) {
		switch (j) {
		case 0:
			prefix_start = PREFIX_1;
			prefix_stop = PREFIX_2;
			break;
		case 1:
			prefix_start = PREFIX_2;
			prefix_stop = PREFIX_3;
			break;
		case 2:
			prefix_start = PREFIX_3;
			prefix_stop = infinity;
			break;
		}
		sc = krc_scan_init(PREFETCH_ENTRIES, PREFETCH_MEM_SIZE);
		strcpy(k->key_buf, prefix_start);
		k->key_size = strlen(k->key_buf) + 1;
		krc_scan_set_start(sc, k->key_size, k->key_buf, KRC_GREATER_OR_EQUAL);
		strcpy(k->key_buf, prefix_stop);
		k->key_size = strlen(k->key_buf) + 1;
		krc_scan_set_stop(sc, k->key_size, k->key_buf, KRC_GREATER_OR_EQUAL);
		krc_scan_get_next(sc);
		tuples = 0;
		while (krc_scan_is_valid(sc)) {
			//log_info("Got key %s", sc->curr_key->key_buf);
			krc_scan_get_next(sc);
			++tuples;
		}
		if (tuples != PREFIX_TEST_KEYS) {
			log_fatal("Test failed got %u expected %u", tuples, PREFIX_TEST_KEYS);
			exit(EXIT_FAILURE);
		}
		log_info("Ok for start %s stop %s", prefix_start, prefix_stop);
	}
	log_info("prefix test scans successfull");
	krc_scan_close(sc);
	return 1;
}

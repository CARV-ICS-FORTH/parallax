#define _LARGEFILE64_SOURCE
#include "arg_parser.h"
#include <allocator/volume_manager.h>
#include <assert.h>
#include <btree/btree.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <log.h>
#include <scanner/scanner.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#define SMALL_KEY_PREFIX "ts"
#define MEDIUM_KEY_PREFIX "tm"
#define LARGE_KEY_PREFIX "tl"
#define SMALL_STATIC_SIZE_PREFIX "zs"
#define MEDIUM_STATIC_SIZE_PREFIX "zm"
#define LARGE_STATIC_SIZE_PREFIX "zl"

#define SMALL_KV_SIZE 48
#define MEDIUM_KV_SIZE 256
#define LARGE_KV_SIZE 1500

typedef struct key {
	uint32_t key_size;
	char key_buf[];
} key;

typedef struct value {
	uint32_t value_size;
	char value_buf[];
} value;

enum kv_type { SMALL, MEDIUM, LARGE };
enum kv_size_type { RANDOM, STATIC };

static uint64_t generate_random_small_kv_size(void)
{
	uint64_t size = rand() % (100 + 1 - 1) + 1;
	assert(size <= 100);
	return size;
}

static uint64_t generate_random_medium_kv_size(void)
{
	uint64_t size = rand() % (1024 + 1 - 100) + 100;
	assert(size > 100 && size <= 1024);
	return size;
}

static uint64_t generate_random_big_kv_size(void)
{
	uint64_t size = rand() % (KV_MAX_SIZE + 1 - 1024) + 1024;
	assert(size > 1024);
	if (size > KV_MAX_SIZE)
		size = KV_MAX_SIZE - 1;
	return size;
}

void init_small_kv(uint64_t *kv_size, char **key_prefix, enum kv_size_type size_type)
{
	if (size_type == RANDOM) {
		*kv_size = generate_random_small_kv_size();
		*key_prefix = strdup(SMALL_KEY_PREFIX);
	} else if (size_type == STATIC) {
		*kv_size = SMALL_KV_SIZE;
		*key_prefix = strdup(SMALL_STATIC_SIZE_PREFIX);
	} else
		assert(0);
}

void init_medium_kv(uint64_t *kv_size, char **key_prefix, enum kv_size_type size_type)
{
	if (size_type == RANDOM) {
		*kv_size = generate_random_medium_kv_size();
		*key_prefix = strdup(MEDIUM_KEY_PREFIX);
	} else if (size_type == STATIC) {
		*kv_size = MEDIUM_KV_SIZE;
		*key_prefix = strdup(MEDIUM_STATIC_SIZE_PREFIX);
	} else
		assert(0);
}

void init_large_kv(uint64_t *kv_size, char **key_prefix, enum kv_size_type size_type)
{
	if (size_type == RANDOM) {
		*kv_size = generate_random_big_kv_size();
		*key_prefix = strdup(LARGE_KEY_PREFIX);
	} else if (size_type == STATIC) {
		*kv_size = LARGE_KV_SIZE;
		*key_prefix = strdup(LARGE_STATIC_SIZE_PREFIX);
	} else
		assert(0);
}

typedef void init_kv_func(uint64_t *kv_size, char **key_prefix, enum kv_size_type size_type);

init_kv_func *init_kv[3] = { init_small_kv, init_medium_kv, init_large_kv };

static void populate_db(db_handle *hd, uint64_t from, uint64_t num_keys, enum kv_type type, enum kv_size_type size_type)
{
	uint64_t i;
	key *k;
	char *key_prefix;
	uint64_t kv_size = 0;

	if (type == SMALL) {
		switch (size_type) {
		case RANDOM:
			init_kv[type](&kv_size, &key_prefix, RANDOM);
			//error handing for too small kv (since key is by default 12 in this test) minimum key is 30
			if (kv_size <= sizeof(SMALL_KEY_PREFIX) + sizeof(long long unsigned))
				kv_size = 30;
			break;
		case STATIC:
			init_kv[type](&kv_size, &key_prefix, STATIC);
			break;
		}
	} else if (type == MEDIUM)
		init_kv[type](&kv_size, &key_prefix, size_type);
	else if (type == LARGE)
		init_kv[type](&kv_size, &key_prefix, size_type);
	else
		assert(0);

	assert(kv_size != 0);
	k = (key *)calloc(1, kv_size);
	if (k == NULL) {
		log_info("Calloc returned NULL, not enough memory exiting...");
		exit(EXIT_FAILURE);
	}
	for (i = from; i < num_keys; i++) {
		memcpy(k->key_buf, key_prefix, strlen(key_prefix));
		sprintf(k->key_buf + strlen(key_prefix), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		value *v = (value *)((uint64_t)k + sizeof(key) + k->key_size);
		v->value_size = kv_size - ((2 * sizeof(key)) + k->key_size);
		memset(v->value_buf, 0xDD, v->value_size);
		if (i % 1000 == 0)
			log_info("%s", k->key_buf);
		insert_key_value(hd, k->key_buf, v->value_buf, k->key_size, v->value_size);
	}

	free(k);
}

static void validate_serially(db_handle *hd, uint64_t from, uint64_t num_keys, enum kv_type type)
{
	uint64_t i;
	char *key_prefix;
	uint64_t kv_size = 0;

	init_kv[type](&kv_size, &key_prefix, STATIC);

	assert(kv_size != 0);
	key *k = (key *)calloc(1, kv_size);

	if (k == NULL) {
		log_info("Calloc returned NULL, not enough memory, exiting...");
		exit(EXIT_FAILURE);
	}
	for (i = from; i < num_keys; i++) {
		memcpy(k->key_buf, key_prefix, strlen(key_prefix));
		sprintf(k->key_buf + strlen(key_prefix), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		if (find_key(hd, k->key_buf, k->key_size) == NULL) {
			log_fatal("key not found %s", k->key_buf);
			find_key(hd, k->key_buf, k->key_size);
		}
	}
}

static void validate_number_of_kvs(db_handle *hd, uint64_t num_keys)
{
	char start_key[5] = { 0 };
	*(uint32_t *)start_key = 1;

	scannerHandle *sc = (scannerHandle *)calloc(1, sizeof(scannerHandle));
	if (!sc) {
		log_fatal("Error calloc did not allocate memory\n");
		exit(EXIT_FAILURE);
	}
	sc->type_of_scanner = FORWARD_SCANNER;
	init_dirty_scanner(sc, hd, start_key, GREATER_OR_EQUAL);
	uint64_t key_count = 1;
	while (isValid(sc)) {
		if (getNext(sc) == END_OF_DATABASE)
			break;
		key_count++;
	}

	if (key_count != num_keys) {
		log_fatal("Scanner did not found all keys. Phase one of validator failed...");
		assert(0);
	}
}

static unsigned int get_kv_size(void *kv_buf)
{
	return (KEY_SIZE(kv_buf) + VALUE_SIZE(kv_buf + sizeof(uint32_t) + KEY_SIZE(kv_buf)) + 2 * sizeof(uint32_t));
}

static int check_correctness_of_size(void *kv_buf, enum kv_type key_type, enum kv_size_type size_type)
{
	if (key_type == SMALL) {
		if (size_type == RANDOM) {
			if (!(get_kv_size(kv_buf) < 100))
				return 0;
		} else if (size_type == STATIC) {
			if (get_kv_size(kv_buf) != SMALL_KV_SIZE)
				return 0;
		}
	} else if (key_type == MEDIUM) {
		if (size_type == RANDOM) {
			if (!(get_kv_size(kv_buf) > 100 && get_kv_size(kv_buf) < 1024))
				return 0;
		} else if (size_type == STATIC) {
			if (get_kv_size(kv_buf) != MEDIUM_KV_SIZE)
				return 0;
		}
	} else if (key_type == LARGE) {
		if (size_type == RANDOM) {
			if (!(get_kv_size(kv_buf) > 1024))
				return 0;
		} else if (size_type == STATIC) {
			if (get_kv_size(kv_buf) != LARGE_KV_SIZE)
				return 0;
		}
	}

	return 1;
}

static void validate_random_size_of_kvs(db_handle *hd, uint64_t from, uint64_t to, enum kv_type key_type,
					enum kv_size_type size_type)
{
	char *key_prefix;
	uint64_t kv_size;
	scannerHandle *sc = (scannerHandle *)calloc(1, sizeof(scannerHandle));

	if (!sc) {
		log_info("Calloc returned NULL, not enough memory, exiting...");
		exit(EXIT_FAILURE);
	}
	sc->type_of_scanner = FORWARD_SCANNER;

	key k;

	init_kv[key_type](&kv_size, &key_prefix, RANDOM);

	memcpy(k.key_buf, key_prefix, strlen(key_prefix));

	//strlen because random keys use srand to generate their sizes, kvsize is different from the correct one
	//when created on population phase
	k.key_size = strlen(key_prefix);

	init_dirty_scanner(sc, hd, &k, GREATER_OR_EQUAL);

	assert(sc->keyValue != NULL);
	if (!check_correctness_of_size(sc->keyValue, key_type, size_type)) {
		log_fatal("found a kv with size out of its category range");
		assert(0);
	}

	for (uint64_t i = from + 1; i < to; i++) {
		getNext(sc);
		assert(sc->keyValue != NULL);
		if (!check_correctness_of_size(sc->keyValue, key_type, size_type)) {
			log_fatal("found a kv with size out of its category range");
			assert(0);
		}
	}
}

static void validate_static_size_of_kvs(db_handle *hd, uint64_t from, uint64_t to, enum kv_type key_type,
					enum kv_size_type size_type)
{
	char *key_prefix;
	uint64_t kv_size;
	scannerHandle *sc = (scannerHandle *)calloc(1, sizeof(scannerHandle));

	if (!sc) {
		log_info("Calloc returned NULL, not enough memory, exiting...");
		exit(EXIT_FAILURE);
	}

	sc->type_of_scanner = FORWARD_SCANNER;
	key k;

	init_kv[key_type](&kv_size, &key_prefix, STATIC);

	memcpy(k.key_buf, key_prefix, strlen(key_prefix));
	k.key_size = strlen(key_prefix);

	init_dirty_scanner(sc, hd, &k, GREATER_OR_EQUAL);
	assert(sc->keyValue != NULL);
	if (!check_correctness_of_size(sc->keyValue, key_type, size_type)) {
		log_fatal("Found a kv with size out of its category range");
		assert(0);
	}

	for (uint64_t i = from + 1; i < to; i++) {
		getNext(sc);
		assert(sc->keyValue != NULL);
		if (!check_correctness_of_size(sc->keyValue, key_type, size_type)) {
			log_fatal("Found a kv with size out of its category range");
			assert(0);
		}
	}
}

static void validate_number_of_kvs_reversally(db_handle *hd, uint64_t num_keys)
{
	scannerHandle *sc = (scannerHandle *)calloc(1, sizeof(scannerHandle));
	sc->type_of_scanner = BACKWARD_SCANNER;

	seek_to_last(sc, hd);
	assert(sc->keyValue != NULL);
	uint64_t key_count = 1;

	while (isValid(sc)) {
		if (getPrev(sc) == END_OF_DATABASE)
			break;

		key_count++;
	}

	if (key_count != num_keys) {
		log_fatal("Reverse scanner did not found all keys, found %lu out of %lu. Phase 4 validator failed...",
			  key_count, num_keys);
		assert(0);
	}
}

static void test_reverse_scans(db_handle *hd, uint64_t num_keys)
{
	log_info("Testing reverse scans");
	validate_number_of_kvs_reversally(hd, num_keys);
}

static void validate_kvs(db_handle *hd, uint64_t num_keys, uint64_t small_kv_perc, uint64_t medium_kv_perc,
			 uint64_t large_kv_perc)
{
	uint64_t small_num_keys = (num_keys * small_kv_perc) / 100;
	uint64_t medium_num_keys = (num_keys * medium_kv_perc) / 100;
	uint64_t large_num_keys = (num_keys * large_kv_perc) / 100;

	//first stage
	//check if num of inserted  keys == num_key using scanners
	validate_number_of_kvs(hd, num_keys);

	//second stage
	// validate that the sizes of keys are correct accross random types
	log_info("Validating random size of small kvs");
	validate_random_size_of_kvs(hd, 0, small_num_keys / 2, SMALL, RANDOM);
	log_info("Validating random size of medium kvs");
	validate_random_size_of_kvs(hd, 0, medium_num_keys / 2, MEDIUM, RANDOM);
	log_info("Validating random size of large kvs");
	validate_random_size_of_kvs(hd, 0, large_num_keys / 2, LARGE, RANDOM);
	//change prefix of static sized keys....
	log_info("Validating static size of small kvs");
	validate_static_size_of_kvs(hd, 0, small_num_keys / 2, SMALL, STATIC);
	log_info("Validating static size of medium kvs");
	validate_static_size_of_kvs(hd, 0, medium_num_keys / 2, MEDIUM, STATIC);
	log_info("Validating static size of large kvs");
	validate_static_size_of_kvs(hd, 0, large_num_keys / 2, LARGE, STATIC);

	//third stage
	//find static keys in the DB
	log_info("Validating %lu medium static size keys...", medium_num_keys / 2);
	validate_serially(hd, 0, medium_num_keys / 2, MEDIUM);
	log_info("Validating %lu large static size keys...", large_num_keys / 2);
	validate_serially(hd, 0, large_num_keys / 2, LARGE);
	log_info("Validating %lu small static size keys...", small_num_keys / 2);
	validate_serially(hd, 0, small_num_keys / 2, SMALL);

	//the FORWARD scans have been tested inside validate_kvs. Now its time for the backward scans
	test_reverse_scans(hd, num_keys);

	return;
}

static void insert_keys(db_handle *hd, uint64_t num_keys, uint64_t small_kv_perc, uint64_t medium_kv_perc,
			uint64_t large_kv_perc)
{
	uint64_t small_num_keys = (num_keys * small_kv_perc) / 100;
	uint64_t medium_num_keys = (num_keys * medium_kv_perc) / 100;
	uint64_t large_num_keys = (num_keys * large_kv_perc) / 100;

	//populate half random size keys in small -> medium -> large order
	log_info("Starting population of %lu small random size kvs..", small_num_keys / 2);
	populate_db(hd, 0, small_num_keys / 2, SMALL, RANDOM);
	log_info("Starting population of %lu medium random size kvs..", medium_num_keys / 2);
	populate_db(hd, 0, medium_num_keys / 2, MEDIUM, RANDOM);
	log_info("Starting population of %lu large random size kvs..", large_num_keys / 2);
	populate_db(hd, 0, large_num_keys / 2, LARGE, RANDOM);

	// polulate the db again in medium->large->small with static sizes order
	log_info("populating %lu medium static size keys..", medium_num_keys / 2);
	populate_db(hd, 0, medium_num_keys / 2, MEDIUM, STATIC);
	log_info("populating %lu large static size keys..", large_num_keys / 2);
	populate_db(hd, 0, large_num_keys / 2, LARGE, STATIC);
	log_info("populating %lu small static size keys..", small_num_keys / 2);
	populate_db(hd, 0, small_num_keys / 2, SMALL, STATIC);

	return;
}

/* ./test_medium | path to file  | number_of_operations | percentage of small kvs |
 * percentage of medium kvs | percentage of big kvs*/
int main(int argc, char *argv[])
{
	struct parallax_options *opts = arg_parser(argc, argv);
	char *path = strdup(opts->file);
	uint64_t num_keys = opts->num_of_kvs;
	uint64_t small_kv_percentage = opts->small_kvs_percentage;
	uint64_t medium_kv_percentage = opts->medium_kvs_percentage;
	uint64_t big_kv_percentage = opts->large_kvs_percentage;
	int fd = open(path, O_RDONLY);
	int64_t size;
	db_handle *handle;

	assert(small_kv_percentage + medium_kv_percentage + big_kv_percentage == 100);

	if (fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (ioctl(fd, BLKGETSIZE64, &size) == -1) {
		perror("ioctl");
		printf("[%s:%s:%d] querying file size\n", __FILE__, __func__, __LINE__);
		size = lseek64(fd, 0, SEEK_END);
		if (size == -1) {
			printf("[%s:%s:%d] failed to determine volume size exiting...\n", __FILE__, __func__, __LINE__);
			perror("ioctl");
			exit(EXIT_FAILURE);
		}
	}

	close(fd);

	handle = db_open(path, 0, size, "test.db", CREATE_DB);
	assert(handle);
	srand(time(NULL));

	insert_keys(handle, num_keys, small_kv_percentage, medium_kv_percentage, big_kv_percentage);

	validate_kvs(handle, num_keys, small_kv_percentage, medium_kv_percentage, big_kv_percentage);

	log_info("test successfull");
	return 1;
}

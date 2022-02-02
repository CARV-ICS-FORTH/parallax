#define _LARGEFILE64_SOURCE
#include "../lib/include/parallax.h"
#include "arg_parser.h"
#include "scanner/scanner.h"
#include <assert.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <log.h>
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

enum kv_type { SMALL, MEDIUM, BIG };
enum kv_size_type { RANDOM, STATIC };

static par_handle open_db(const char *path)
{
	par_db_options db_options;
	db_options.volume_name = (char *)path;
	db_options.volume_start = 0;
	db_options.volume_size = 0;
	db_options.create_flag = PAR_CREATE_DB;
	db_options.db_name = "testmedium.db";

	par_handle handle = par_open(&db_options);
	return handle;
}

void init_small_kv(uint64_t *kv_size, char **key_prefix, enum kv_size_type size_type)
{
	if (size_type == STATIC) {
		*kv_size = SMALL_KV_SIZE;
		*key_prefix = strdup(SMALL_STATIC_SIZE_PREFIX);
	} else
		assert(0);
}

void init_medium_kv(uint64_t *kv_size, char **key_prefix, enum kv_size_type size_type)
{
	if (size_type == STATIC) {
		*kv_size = MEDIUM_KV_SIZE;
		*key_prefix = strdup(MEDIUM_STATIC_SIZE_PREFIX);
	} else
		assert(0);
}

void init_big_kv(uint64_t *kv_size, char **key_prefix, enum kv_size_type size_type)
{
	if (size_type == STATIC) {
		*kv_size = LARGE_KV_SIZE;
		*key_prefix = strdup(LARGE_STATIC_SIZE_PREFIX);
	} else
		assert(0);
}

typedef void init_kv_func(uint64_t *kv_size, char **key_prefix, enum kv_size_type size_type);

init_kv_func *init_kv[3] = { init_small_kv, init_medium_kv, init_big_kv };

static void populate_db(par_handle hd, uint64_t from, uint64_t num_keys, enum kv_type type, enum kv_size_type size_type)
{
	uint64_t i;
	key *k;
	char *key_prefix;
	uint64_t kv_size = 0;

	init_kv[type](&kv_size, &key_prefix, size_type);

	assert(kv_size != 0);

	k = (key *)calloc(1, kv_size);

	for (i = from; i < num_keys; i++) {
		memcpy(k->key_buf, key_prefix, strlen(key_prefix));
		sprintf(k->key_buf + strlen(key_prefix), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		value *v = (value *)((uint64_t)k + sizeof(key) + k->key_size);
		v->value_size = kv_size - ((2 * sizeof(key)) + k->key_size);
		memset(v->value_buf, 0xDD, v->value_size);
		if (i % 1000 == 0)
			log_info("%s", k->key_buf);

		struct par_key_value kv = { .k.data = (const char *)k->key_buf,
					    .k.size = k->key_size,
					    .v.val_buffer = v->value_buf,
					    .v.val_size = v->value_size };

		if (par_put(hd, &kv) != PAR_SUCCESS) {
			log_fatal("Put failed!");
			exit(EXIT_FAILURE);
		}
	}
	free(k);
	log_info("Population ended");
}

static void insert_keys(par_handle handle, uint64_t num_of_keys, uint32_t small_kvs_percentage,
			uint32_t medium_kvs_percentage, uint32_t big_kvs_percentage)
{
	uint64_t small_kvs_num = (num_of_keys * small_kvs_percentage) / 100;
	uint64_t medium_kvs_num = (num_of_keys * medium_kvs_percentage) / 100;
	uint64_t big_kvs_num = (num_of_keys * big_kvs_percentage) / 100;

	assert(small_kvs_num + medium_kvs_num + big_kvs_num == num_of_keys);

	log_info("populating %lu medium static size keys..", medium_kvs_num);
	populate_db(handle, 0, medium_kvs_num, MEDIUM, STATIC);
	log_info("populating %lu large static size keys..", big_kvs_num);
	populate_db(handle, 0, big_kvs_num, BIG, STATIC);
	log_info("populating %lu small static size keys..", small_kvs_num);
	populate_db(handle, 0, small_kvs_num, SMALL, STATIC);
}

static void scanner_validate_number_of_kvs(par_handle hd, uint64_t num_keys)
{
	uint64_t key_count = 0;
	par_scanner sc = par_init_scanner(hd, NULL, PAR_FETCH_FIRST);
	assert(par_is_valid(sc));

	while (par_is_valid(sc)) {
		++key_count;
		par_get_next(sc);
	}

	log_info("scanner found %lu kvs", key_count);
	if (key_count != num_keys) {
		log_fatal("Scanner did not found all keys. Phase one of validator failed...");
		assert(0);
	}
	par_close_scanner(sc);
}

static unsigned int scanner_kv_size(par_scanner sc)
{
	struct par_key scanner_key = par_get_key(sc);
	struct par_value scanner_value = par_get_value(sc);

	return (scanner_key.size + scanner_value.val_size + 2 * sizeof(uint32_t));
}

static int check_correctness_of_size(par_scanner sc, enum kv_type key_type, enum kv_size_type size_type)
{
	if (key_type == SMALL) {
		if (size_type == STATIC) {
			if (scanner_kv_size(sc) != SMALL_KV_SIZE)
				return 0;
		}
	} else if (key_type == MEDIUM) {
		if (size_type == STATIC) {
			if (scanner_kv_size(sc) != MEDIUM_KV_SIZE)
				return 0;
		}
	} else if (key_type == BIG) {
		if (size_type == STATIC) {
			if (scanner_kv_size(sc) != LARGE_KV_SIZE)
				return 0;
		}
	}

	return 1;
}

static void validate_static_size_of_kvs(par_handle hd, uint64_t from, uint64_t to, enum kv_type key_type,
					enum kv_size_type size_type)
{
	char *key_prefix;
	uint64_t kv_size;
	struct par_key k;

	init_kv[key_type](&kv_size, &key_prefix, STATIC);
	k.data = (char *)malloc(kv_size);

	memcpy((char *)k.data, key_prefix, strlen(key_prefix));
	sprintf((char *)k.data + strlen(key_prefix), "%llu", (long long unsigned)0);
	k.size = strlen(k.data) + 1;

	par_scanner sc = par_init_scanner(hd, &k, PAR_GREATER_OR_EQUAL);
	assert(par_is_valid(sc));

	if (!check_correctness_of_size(sc, key_type, size_type)) {
		log_fatal("Found a kv that has size out of its category range");
		assert(0);
	}

	for (uint64_t i = from + 1; i < to; i++) {
		par_get_next(sc);
		assert(par_is_valid(sc));
		if (!check_correctness_of_size(sc, key_type, size_type)) {
			log_fatal("Found a KV that has size out of its category range");
			assert(0);
		}
	}

	par_close_scanner(sc);
}

static void validate_kvs(par_handle *hd, uint64_t num_keys, uint64_t small_kv_perc, uint64_t medium_kv_perc,
			 uint64_t large_kv_perc)
{
	uint64_t small_num_keys = (num_keys * small_kv_perc) / 100;
	uint64_t medium_num_keys = (num_keys * medium_kv_perc) / 100;
	uint64_t large_num_keys = (num_keys * large_kv_perc) / 100;

	/*first stage
	 * check if num of inserted  keys == num_key using scanners
	*/
	scanner_validate_number_of_kvs(hd, num_keys);

	/* second stage
	 * validate that the sizes of keys are correctx
	*/
	log_info("Validating static size of small kvs");
	validate_static_size_of_kvs(hd, 0, small_num_keys, SMALL, STATIC);
	log_info("Validating static size of medium kvs");
	validate_static_size_of_kvs(hd, 0, medium_num_keys, MEDIUM, STATIC);
	log_info("Validating static size of large kvs");
	validate_static_size_of_kvs(hd, 0, large_num_keys, BIG, STATIC);

	return;
}

int main(int argc, char *argv[])
{
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
		{ { "medium_kv_percentage", required_argument, 0, 'c' },
		  "--medium_kv_percentage=number, percentage of medium category kvs out of num_of_kvs to be inserted",
		  NULL,
		  INTEGER },
		{ { "small_kv_percentage", required_argument, 0, 'd' },
		  "--small_kv_percentage=number, percentage of small category kvs out of num_of_kvs to be inserted",
		  NULL,
		  INTEGER },
		{ { "big_kv_percentage", required_argument, 0, 'e' },
		  "--big_kv_percentage=number, percentage of big category kvs out of num_of_kvs to be inserted",
		  NULL,
		  INTEGER },
		{ { 0, 0, 0, 0 }, "End of arguments", NULL, INTEGER }
	};
	unsigned options_len = (sizeof(options) / sizeof(struct wrap_option));

	arg_parse(argc, argv, options, options_len);

	const char *path = get_option(options, 1);
	const uint64_t num_of_keys = *(int *)get_option(options, 2);
	const uint32_t medium_kvs_percentage = *(int *)get_option(options, 3);
	const uint32_t small_kvs_percentage = *(int *)get_option(options, 4);
	const uint32_t big_kvs_percentage = *(int *)get_option(options, 5);

	/*sum of percentages must be equal 100*/
	assert(medium_kvs_percentage + small_kvs_percentage + big_kvs_percentage == 100);

	par_handle handle = open_db(path);

	insert_keys(handle, num_of_keys, small_kvs_percentage, medium_kvs_percentage, big_kvs_percentage);

	validate_kvs(handle, num_of_keys, small_kvs_percentage, medium_kvs_percentage, big_kvs_percentage);

	par_close(handle);
	log_info("test successfull");
	return 1;
}

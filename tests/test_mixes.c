#include "arg_parser.h"
#include "common/common.h"
#include <assert.h>
#include <fcntl.h>
#include <include/parallax.h>
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

#define SMALLEST_KV_FORMAT_SIZE(x) (x + 2 * sizeof(uint32_t) + 1)
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

/** kv_size generators logic follow */
static uint64_t generate_random_small_kv_size(void)
{
	/*minimum kv will have 5 size*/
	uint64_t size = rand() % (100 + 1 - 5) + 5;
	assert(size >= 5 && size <= 100);
	return size;
}

static uint64_t generate_random_big_kv_size(void)
{
	/* we use rand without using srand to generate the same number of "random" kvs over many executions
	 * of this test */
	uint64_t size = rand() % (KV_MAX_SIZE + 1 - 1025) + 1025;
	assert(size > 1024 && size <= KV_MAX_SIZE);
	return size;
}

static uint64_t generate_random_medium_kv_size(void)
{
	uint64_t size = rand() % (1024 + 1 - 101) + 101;
	assert(size > 100 && size <= 1024);
	return size;
}

/** Functions for initializing a kv based on their category*/
static void init_small_kv(uint64_t *kv_size, char **key_prefix, enum kv_size_type size_type)
{
	switch (size_type) {
	case STATIC:
		*kv_size = SMALL_KV_SIZE;
		*key_prefix = strdup(SMALL_STATIC_SIZE_PREFIX);
		break;
	case RANDOM:
		*kv_size = generate_random_small_kv_size();
		*key_prefix = strdup(SMALL_KEY_PREFIX);
		break;
	default:
		BUG_ON();
	}
}

static void init_medium_kv(uint64_t *kv_size, char **key_prefix, enum kv_size_type size_type)
{
	switch (size_type) {
	case STATIC:
		*kv_size = MEDIUM_KV_SIZE;
		*key_prefix = strdup(MEDIUM_STATIC_SIZE_PREFIX);
		break;
	case RANDOM:
		*kv_size = generate_random_medium_kv_size();
		*key_prefix = strdup(MEDIUM_KEY_PREFIX);
		break;
	default:
		BUG_ON();
	}
}

static void init_big_kv(uint64_t *kv_size, char **key_prefix, enum kv_size_type size_type)
{
	switch (size_type) {
	case STATIC:
		*kv_size = LARGE_KV_SIZE;
		*key_prefix = strdup(LARGE_STATIC_SIZE_PREFIX);
		break;
	case RANDOM:
		*kv_size = generate_random_big_kv_size();
		*key_prefix = strdup(LARGE_KEY_PREFIX);
		break;
	default:
		BUG_ON();
	}
}

typedef void init_kv_func(uint64_t *kv_size, char **key_prefix, enum kv_size_type size_type);
init_kv_func *init_kv[3] = { init_small_kv, init_medium_kv, init_big_kv };

/** Function allocating enough space for a kv*/
static uint64_t space_needed_for_the_kv(uint64_t kv_size, char *key_prefix, uint64_t i)
{
	char *buf = (char *)malloc(LARGE_KV_SIZE);
	memcpy(buf, key_prefix, strlen(key_prefix));
	sprintf(buf + strlen(key_prefix), "%llu", (long long unsigned)i);
	uint64_t keybuf_size = strlen(buf) + 1;

	/* a random generated key do not have enough space
	 * allocate minimum needed space for the KV
	*/
	if (kv_size < SMALLEST_KV_FORMAT_SIZE(keybuf_size))
		kv_size = SMALLEST_KV_FORMAT_SIZE(keybuf_size);

	free(buf);
	return kv_size;
}

/** Main insert logic for populating the db with a kv category*/
static void populate_db(par_handle hd, uint64_t from, uint64_t num_keys, enum kv_type type, enum kv_size_type size_type)
{
	char *key_prefix;
	uint64_t kv_size = 0;

	for (uint64_t i = from; i < num_keys; i++) {
		init_kv[type](&kv_size, &key_prefix, size_type);
		kv_size = space_needed_for_the_kv(kv_size, key_prefix, i);
		key *k = (key *)calloc(1, kv_size);

		memcpy(k->key_buf, key_prefix, strlen(key_prefix));
		sprintf(k->key_buf + strlen(key_prefix), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		value *v = (value *)((uint64_t)k + sizeof(uint32_t) + k->key_size);
		v->value_size = kv_size - ((2 * sizeof(uint32_t)) + k->key_size);
		memset(v->value_buf, 0xDD, v->value_size);
		if (i % 1000 == 0)
			log_info("%s", k->key_buf);

		if (par_put_serialized(hd, (char *)k) != PAR_SUCCESS) {
			log_fatal("Put failed!");
			_exit(EXIT_FAILURE);
		}
		free(k);
	}
	log_info("Population ended");
}

/** This function populates the db in the above manner:
 *  First static size kvs are inserted following the - medium kvs - big kvs - small kvs - order
 *  After that random generated size keys are inserted followin the -big kvs - small kvs - medium kvs - order
 **/
static void insert_keys(par_handle handle, uint64_t num_of_keys, uint32_t small_kvs_percentage,
			uint32_t medium_kvs_percentage, uint32_t big_kvs_percentage)
{
	uint64_t small_kvs_num = (num_of_keys * small_kvs_percentage) / 100;
	uint64_t medium_kvs_num = (num_of_keys * medium_kvs_percentage) / 100;
	uint64_t big_kvs_num = (num_of_keys * big_kvs_percentage) / 100;

	assert(small_kvs_num + medium_kvs_num + big_kvs_num == num_of_keys);

	log_info("populating %lu medium static size keys..", medium_kvs_num / 2);
	populate_db(handle, 0, medium_kvs_num / 2, MEDIUM, STATIC);
	log_info("populating %lu large static size keys..", big_kvs_num / 2);
	populate_db(handle, 0, big_kvs_num / 2, BIG, STATIC);
	log_info("populating %lu small static size keys..", small_kvs_num / 2);
	populate_db(handle, 0, small_kvs_num / 2, SMALL, STATIC);

	log_info("population %lu large random size keys..", big_kvs_num / 2);
	populate_db(handle, 0, big_kvs_num / 2, BIG, RANDOM);
	log_info("population %lu small random size keys..", small_kvs_num / 2);
	populate_db(handle, 0, small_kvs_num / 2, SMALL, RANDOM);
	log_info("population %lu medium random size keys..", medium_kvs_num / 2);
	populate_db(handle, 0, medium_kvs_num / 2, MEDIUM, RANDOM);
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

static unsigned int scanner_kv_size(par_scanner sc, enum kv_size_type size_type, uint32_t kv_category_size)
{
	uint64_t key_count = 0;
	while (getNext(sc) != END_OF_DATABASE)
		++key_count;
	/*we can't know the the random generated size*/
	if (size_type == RANDOM)
		return 1;

	struct par_key scanner_key = par_get_key(sc);
	struct par_value scanner_value = par_get_value(sc);
	uint32_t scanner_kv_size = scanner_key.size + scanner_value.val_size + 2 * sizeof(uint32_t);

	if (scanner_kv_size == kv_category_size)
		return 1;

	log_debug("This is going to be an error, size is %d cat size is %d", scanner_kv_size, kv_category_size);
	return 0;
}

/** Function returning if the size of a kv corresponds to its kv_category*/
static int check_correctness_of_size(par_scanner sc, enum kv_type key_type, enum kv_size_type size_type)
{
	switch (key_type) {
	case SMALL:
		return scanner_kv_size(sc, size_type, SMALL_KV_SIZE);
	case MEDIUM:
		return scanner_kv_size(sc, size_type, MEDIUM_KV_SIZE);
	case BIG:
		return scanner_kv_size(sc, size_type, LARGE_KV_SIZE);
	default:
		BUG_ON();
	}
}

static void validate_static_size_of_kvs(par_handle hd, uint64_t from, uint64_t to, enum kv_type key_type,
					enum kv_size_type size_type)
{
	char *key_prefix;
	uint64_t kv_size = 0;
	struct par_key k;
	if (from == to) {
		/*this is an empty category dont try to validate anything*/
		return;
	}

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
		if (!check_correctness_of_size(sc, key_type, size_type)) {
			log_fatal("Found a KV that has size out of its category range");
			assert(0);
		}
	}

	par_close_scanner(sc);
}

static void validate_random_size_of_kvs(par_handle hd, uint64_t from, uint64_t to, enum kv_type key_type,
					enum kv_size_type size_type)
{
	char *key_prefix;
	uint64_t kv_size = 0;
	struct par_key k = { .size = 0, .data = NULL };

	init_kv[key_type](&kv_size, &key_prefix, RANDOM);
	k.data = (char *)malloc(kv_size);

	memcpy((char *)k.data, key_prefix, strlen(key_prefix));
	sprintf((char *)k.data + strlen(key_prefix), "%llu", (long long unsigned)0);

	k.size = strlen(k.data) + 1;

	par_scanner sc = par_init_scanner(hd, &k, PAR_GREATER_OR_EQUAL);
	assert(par_is_valid(sc));

	if (!check_correctness_of_size(sc, key_type, size_type)) {
		log_fatal("found a kv with size out of its category range");
		assert(0);
	}

	for (uint64_t i = from + 1; i < to; i++) {
		par_get_next(sc);
		assert(par_is_valid(sc));

		if (!check_correctness_of_size(sc, key_type, size_type)) {
			log_fatal("found a kv with size out of its category range");
			assert(0);
		}
	}
	par_close_scanner(sc);
}

/** Main retrieve-kvs logic*/
static void read_all_static_kvs(par_handle handle, uint64_t from, uint64_t to, enum kv_type kv_type,
				enum kv_size_type size_type)
{
	uint64_t kv_size = 0;
	char *key_prefix;
	struct par_key_value my_kv = { .k.size = 0, .k.data = NULL, .v.val_buffer = NULL };

	init_kv[kv_type](&kv_size, &key_prefix, size_type);
	/*allocate enough space for all kvs, won't use all of it*/
	char *buf = (char *)malloc(LARGE_KV_SIZE);

	for (uint64_t i = from; i < to; i++) {
		memcpy(buf, key_prefix, strlen(key_prefix));
		sprintf(buf + strlen(key_prefix), "%llu", (long long unsigned)i);
		my_kv.k.size = strlen(buf) + 1;
		my_kv.k.data = buf;
		if (par_get(handle, &my_kv.k, &my_kv.v) != PAR_SUCCESS) {
			log_fatal("Key %u:%s not found", my_kv.k.size, my_kv.k.data);
			_exit(EXIT_FAILURE);
		}
	}
}

/** Function validating the already populated kvs
 *  First it scans the whole db to ensure that the number of the inserted keys are equal to the benchmark size
 *  After it validates each static size kv category using scanners
 *  Then it validates each random size kv category using scanners
 *  Finally it retrieves all static size kvs using par_get to ensure that the kvs are correct */
static void validate_kvs(par_handle hd, uint64_t num_keys, uint64_t small_kv_perc, uint64_t medium_kv_perc,
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
	validate_static_size_of_kvs(hd, 0, small_num_keys / 2, SMALL, STATIC);
	log_info("Validating static size of medium kvs");
	validate_static_size_of_kvs(hd, 0, medium_num_keys / 2, MEDIUM, STATIC);
	log_info("Validating static size of large kvs");
	validate_static_size_of_kvs(hd, 0, large_num_keys / 2, BIG, STATIC);

	/* third stage
	 * validate that random kvs exist in the correct size category
	*/
	log_info("Validating random size of small kvs");
	validate_random_size_of_kvs(hd, 0, small_num_keys / 2, SMALL, RANDOM);
	log_info("Validating random size of medium kvs");
	validate_random_size_of_kvs(hd, 0, medium_num_keys / 2, MEDIUM, RANDOM);
	log_info("Validating random size of large kvs");
	validate_random_size_of_kvs(hd, 0, large_num_keys / 2, BIG, RANDOM);

	/* forth stage
	 * validate that all keys exist and have the correct size with par_get
	 */
	log_info("Validating %lu medium static size keys...", medium_num_keys / 2);
	read_all_static_kvs(hd, 0, medium_num_keys / 2, MEDIUM, STATIC);
	log_info("Validating %lu big static size keys...", large_num_keys / 2);
	read_all_static_kvs(hd, 0, large_num_keys / 2, BIG, STATIC);
	log_info("Validating %lu small static size keys...", small_num_keys / 2);
	read_all_static_kvs(hd, 0, small_num_keys / 2, SMALL, STATIC);
}
/** ./test_mixes --file=path_to_file --num_of_kvs=number_of_kvs --medium_kv_percentage=percentage_of_medium_kvs --small_kv_percentage=percentage_of_small_kvs --big_kv_percentage=percentage_of_big_kvs*/
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
	const uint64_t num_of_keys = *(uint64_t *)get_option(options, 2);
	const uint32_t medium_kvs_percentage = *(int *)get_option(options, 3);
	const uint32_t small_kvs_percentage = *(int *)get_option(options, 4);
	const uint32_t big_kvs_percentage = *(int *)get_option(options, 5);

	/*sum of percentages must be equal 100*/
	assert(medium_kvs_percentage + small_kvs_percentage + big_kvs_percentage == 100);
	par_format((char *)path, 128);
	par_handle handle = open_db(path);

	/*populate the db phase*/
	insert_keys(handle, num_of_keys, small_kvs_percentage, medium_kvs_percentage, big_kvs_percentage);
	/*validate the poppulated db phase*/
	validate_kvs(handle, num_of_keys, small_kvs_percentage, medium_kvs_percentage, big_kvs_percentage);

	par_close(handle);
	log_info("test successfull");
	return 0;
}

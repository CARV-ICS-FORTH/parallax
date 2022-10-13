#include "allocator/volume_manager.h"
#include "arg_parser.h"
#include <assert.h>
#include <btree/btree.h>
#include <common/common.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <log.h>
#include <parallax/parallax.h>
#include <scanner/scanner.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#define SMALL_KEY_PREFIX "ts"
#define MEDIUM_KEY_PREFIX "tmmmmmmmmmmm"
#define LARGE_KEY_PREFIX "tl"
#define SMALL_STATIC_SIZE_PREFIX "zs"
#define MEDIUM_STATIC_SIZE_PREFIX "zmmmmmmmmmmm"
#define LARGE_STATIC_SIZE_PREFIX "zl"

#define SMALLEST_KV_FORMAT_SIZE(x) (x + 2 * sizeof(uint32_t) + 1)
#define SMALL_KV_SIZE 29
#define MEDIUM_KV_SIZE 129
#define LARGE_KV_SIZE 1500
#define NUMBER_OF_KV_CATEGORIES 3 /*S M L*/

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

struct task {
	uint64_t from;
	uint64_t to;
	enum kv_type key_type;
	enum kv_size_type size_type;
};

struct test_info {
	uint64_t num_keys;
	uint64_t small_kv_percentage;
	uint64_t medium_kv_percentage;
	uint64_t large_kv_percentage;
};

struct init_key_values {
	uint64_t kv_size;
	char *key_prefix;
	enum kv_size_type size_type;
	enum kv_type kv_category;
};

struct random_sizes {
	uint32_t min;
	uint32_t max;
};

struct random_sizes random_sizes_table[NUMBER_OF_KV_CATEGORIES];

static par_handle open_db(const char *path)
{
	par_db_options db_options = { .volume_name = (char *)path,
				      .create_flag = PAR_CREATE_DB,
				      .db_name = "testmedium.db",
				      .options = par_get_default_options() };

	const char *error_message = NULL;
	par_handle handle = par_open(&db_options, &error_message);
	if (error_message) {
		log_fatal("%s", error_message);
		_Exit(EXIT_FAILURE);
	}

	return handle;
}

static uint64_t generate_random_size(enum kv_type kv_category)
{
	/* we use rand without using srand to generate the same number of "random" kvs over many executions
	 * of this test */
	return rand() % (random_sizes_table[kv_category].max + 1 - random_sizes_table[kv_category].min) +
	       random_sizes_table[kv_category].min;
}

/** This function initializes a kv by filling the fields of init_info*/
void init_kv(struct init_key_values *init_info)
{
	struct init_values {
		uint64_t static_kv_size;
		uint64_t random_kv_size;
		char *static_kv_prefix;
		char *random_kv_prefix;
	};
	struct init_values init_values_buffer[NUMBER_OF_KV_CATEGORIES];
	init_values_buffer[SMALL].random_kv_prefix = strdup(SMALL_KEY_PREFIX);
	init_values_buffer[SMALL].static_kv_prefix = strdup(SMALL_STATIC_SIZE_PREFIX);
	init_values_buffer[SMALL].static_kv_size = SMALL_KV_SIZE;
	init_values_buffer[SMALL].random_kv_size = generate_random_size(SMALL);

	init_values_buffer[MEDIUM].random_kv_prefix = strdup(MEDIUM_KEY_PREFIX);
	init_values_buffer[MEDIUM].static_kv_prefix = strdup(MEDIUM_STATIC_SIZE_PREFIX);
	init_values_buffer[MEDIUM].static_kv_size = MEDIUM_KV_SIZE;
	init_values_buffer[MEDIUM].random_kv_size = generate_random_size(MEDIUM);

	init_values_buffer[BIG].random_kv_prefix = strdup(LARGE_KEY_PREFIX);
	init_values_buffer[BIG].static_kv_prefix = strdup(LARGE_STATIC_SIZE_PREFIX);
	init_values_buffer[BIG].static_kv_size = LARGE_KV_SIZE;
	init_values_buffer[BIG].random_kv_size = generate_random_size(BIG);

	if (init_info->size_type == STATIC) {
		init_info->kv_size = init_values_buffer[init_info->kv_category].static_kv_size;
		init_info->key_prefix = strdup(init_values_buffer[init_info->kv_category].static_kv_prefix);
	} else {
		init_info->kv_size = init_values_buffer[init_info->kv_category].random_kv_size;
		init_info->key_prefix = strdup(init_values_buffer[init_info->kv_category].random_kv_prefix);
	}
	/*free the strdup space*/
	for (uint32_t i = 0; i < NUMBER_OF_KV_CATEGORIES; ++i) {
		free(init_values_buffer[i].random_kv_prefix);
		free(init_values_buffer[i].static_kv_prefix);
	}
}

/** Function allocating enough space for a kv*/
static uint64_t space_needed_for_the_kv(uint64_t kv_size, char *key_prefix, uint64_t i)
{
	char *buf = (char *)calloc(1, LARGE_KV_SIZE);
	memcpy(buf, key_prefix, strlen(key_prefix));
	sprintf(buf + strlen(key_prefix), "%llu", (long long unsigned)i);
	uint64_t keybuf_size = strlen(buf) + 1;

	/* A random generated key does not have enough space allocate minimum needed space for the KV.*/
	uint64_t smallest_kv_size = SMALLEST_KV_FORMAT_SIZE(keybuf_size);

	free(buf);
	return kv_size < smallest_kv_size ? smallest_kv_size : kv_size;
}

/** Main insert logic for populating the db with a kv category*/
static void populate_db(par_handle hd, struct task task_info)
{
	for (uint64_t i = task_info.from; i < task_info.to; ++i) {
		struct init_key_values init_info = { .kv_size = 0,
						     .key_prefix = NULL,
						     .size_type = task_info.size_type,
						     .kv_category = task_info.key_type };
		init_kv(&init_info);
		init_info.kv_size = space_needed_for_the_kv(init_info.kv_size, init_info.key_prefix, i);
		key *k = (key *)calloc(1, init_info.kv_size);

		memcpy(k->key_buf, init_info.key_prefix, strlen(init_info.key_prefix));
		sprintf(k->key_buf + strlen(init_info.key_prefix), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		value *v = (value *)((char *)k + sizeof(uint32_t) + k->key_size);
		v->value_size = init_info.kv_size - ((2 * sizeof(uint32_t)) + k->key_size);
		memset(v->value_buf, 0, v->value_size);

		struct par_key_value kv = { .k.data = (const char *)k->key_buf,
					    .k.size = k->key_size,
					    .v.val_buffer = v->value_buf,
					    .v.val_size = v->value_size };

		const char *error_message = NULL;
		par_put(hd, &kv, &error_message);
		if (error_message) {
			log_fatal("Put failed! %s", error_message);
			BUG_ON();
		}
		free(k);
		free(init_info.key_prefix);
	}
	log_info("Population ended");
}

/**
 * This function populates the db in the above manner:
 * @param handle is an initialised par_handle
 * @param info contains informations about the insertion process like the different percetages of kc categories
 * First static size kvs are inserted following the - medium kvs - big kvs - small kvs - order
 * After that random generated size keys are inserted followin the -big kvs - small kvs - medium kvs - order
 * */
static void insert_keys(par_handle handle, struct test_info info)
{
	uint64_t small_kvs_num = (info.num_keys * info.small_kv_percentage) / 100;
	uint64_t medium_kvs_num = (info.num_keys * info.medium_kv_percentage) / 100;
	uint64_t big_kvs_num = (info.num_keys * info.large_kv_percentage) / 100;

	log_info("populating %lu medium static size keys..", medium_kvs_num / 2);
	struct task population_info = { .from = 0, .to = medium_kvs_num / 2, .key_type = MEDIUM, .size_type = STATIC };
	populate_db(handle, population_info);
	log_info("populating %lu large static size keys..", big_kvs_num / 2);
	population_info.to = big_kvs_num / 2;
	population_info.key_type = BIG;
	populate_db(handle, population_info);
	log_info("populating %lu small static size keys..", small_kvs_num / 2);
	population_info.to = small_kvs_num / 2;
	population_info.key_type = SMALL;
	populate_db(handle, population_info);

	log_info("population %lu large random size keys..", big_kvs_num / 2);
	population_info.to = big_kvs_num / 2;
	population_info.key_type = BIG;
	population_info.size_type = RANDOM;
	populate_db(handle, population_info);
	log_info("population %lu small random size keys..", small_kvs_num / 2);
	population_info.to = small_kvs_num / 2;
	population_info.key_type = SMALL;
	populate_db(handle, population_info);
	log_info("population %lu medium random size keys..", medium_kvs_num / 2);
	population_info.to = medium_kvs_num / 2;
	population_info.key_type = MEDIUM;
	populate_db(handle, population_info);
}

/**
 * This function validates the total number of kvs using scanners and asserts that all kvs are present
 * @param handle is an initialised par_handle
 * @param num_keys are the total number of kvcs that we want this scanner to validate
 * */
static void scanner_validate_number_of_kvs(par_handle hd, uint64_t num_keys)
{
	uint64_t key_count = 0;
	const char *error_message = NULL;
	par_scanner sc = par_init_scanner(hd, NULL, PAR_FETCH_FIRST, &error_message);
	assert(par_is_valid(sc));

	while (par_is_valid(sc)) {
		++key_count;
		par_get_next(sc);
	}

	if (key_count != num_keys) {
		log_fatal("Scanner did not found all keys. Phase one of validator failed...");
		BUG_ON();
	}
	par_close_scanner(sc);
}

/**
 * This function asserts that the kv_size of a static size category is correct to its accordingly category size
 * @param sc is an initialized par_scanner
 * @param size_type indicates if the size category is either RANDOM or STATIC
 * @param kv_cateogry_size indicates if the kv category is SMALL|MEDIUM|BIG
 * */
static unsigned int scanner_kv_size(par_scanner sc, enum kv_size_type size_type, uint32_t kv_category_size)
{
	/*we can't know the the random generated size*/
	if (size_type == RANDOM)
		return 1;

	struct par_key scanner_key = par_get_key(sc);
	struct par_value scanner_value = par_get_value(sc);
	uint32_t scanner_kv_size = scanner_key.size + scanner_value.val_size + 2 * sizeof(uint32_t);

	if (scanner_kv_size == kv_category_size)
		return 1;

	log_fatal("size of kv found by scanner is %d cat size is %d", scanner_kv_size, kv_category_size);
	BUG_ON();
}

/** Function returning if the size of a kv corresponds to its kv_category*/
static int check_correctness_of_size(par_scanner sc, enum kv_type key_type, enum kv_size_type size_type)
{
	int kv_sizes[3] = { SMALL_KV_SIZE, MEDIUM_KV_SIZE, LARGE_KV_SIZE };
	return scanner_kv_size(sc, size_type, kv_sizes[key_type]);
}

static void validate_static_size_of_kvs(par_handle hd, struct task task_info)
{
	struct par_key k = { 0 };

	/*this is an empty category dont try to validate anything*/
	if (task_info.from == task_info.to)
		return;
	struct init_key_values init_info = {
		.kv_size = 0, .key_prefix = NULL, .size_type = STATIC, .kv_category = task_info.key_type
	};

	init_kv(&init_info);
	k.data = (char *)calloc(1, init_info.kv_size);

	memcpy((char *)k.data, init_info.key_prefix, strlen(init_info.key_prefix));
	sprintf((char *)k.data + strlen(init_info.key_prefix), "%llu", (long long unsigned)0);
	k.size = strlen(k.data) + 1;

	const char *error_message = NULL;
	par_scanner sc = par_init_scanner(hd, &k, PAR_GREATER_OR_EQUAL, &error_message);
	assert(par_is_valid(sc));

	if (!check_correctness_of_size(sc, task_info.key_type, task_info.size_type)) {
		log_fatal("Found a kv that has size out of its category range");
		BUG_ON();
	}

	for (uint64_t i = task_info.from + 1; i < task_info.to; ++i) {
		par_get_next(sc);
		if (!check_correctness_of_size(sc, task_info.key_type, task_info.size_type)) {
			log_fatal("Found a KV that has size out of its category range");
			BUG_ON();
		}
	}
	par_close_scanner(sc);
	free((void *)k.data);
}

static void validate_random_size_of_kvs(par_handle hd, struct task task_info)
{
	struct par_key k = { 0 };
	struct init_key_values init_info = {
		.kv_size = 0, .key_prefix = NULL, .size_type = RANDOM, .kv_category = task_info.key_type
	};

	init_kv(&init_info);
	k.data = (char *)malloc(init_info.kv_size);

	memcpy((char *)k.data, init_info.key_prefix, strlen(init_info.key_prefix));
	sprintf((char *)k.data + strlen(init_info.key_prefix), "%llu", (long long unsigned)0);

	k.size = strlen(k.data) + 1;

	const char *error_message = NULL;
	par_scanner sc = par_init_scanner(hd, &k, PAR_GREATER_OR_EQUAL, &error_message);
	assert(par_is_valid(sc));

	if (!check_correctness_of_size(sc, task_info.key_type, task_info.size_type)) {
		log_fatal("found a kv with size out of its category range");
		BUG_ON();
	}

	for (uint64_t i = task_info.from + 1; i < task_info.to; ++i) {
		par_get_next(sc);
		assert(par_is_valid(sc));

		if (!check_correctness_of_size(sc, task_info.key_type, task_info.size_type)) {
			log_fatal("found a kv with size out of its category range");
			BUG_ON();
		}
	}
	par_close_scanner(sc);
	free((void *)k.data);
}

/** Main retrieve-kvs logic*/
static void read_all_static_kvs(par_handle handle, struct task task_info)
{
	const char *error_message = NULL;
	struct par_key_value my_kv = { 0 };
	struct init_key_values init_info = {
		.kv_size = 0, .key_prefix = NULL, .size_type = task_info.size_type, .kv_category = task_info.key_type
	};

	init_kv(&init_info);
	/*allocate enough space for all kvs, won't use all of it*/
	char *buf = (char *)calloc(1, LARGE_KV_SIZE);

	for (uint64_t i = task_info.from; i < task_info.to; ++i) {
		memcpy(buf, init_info.key_prefix, strlen(init_info.key_prefix));
		sprintf(buf + strlen(init_info.key_prefix), "%llu", (long long unsigned)i);
		my_kv.k.size = strlen(buf) + 1;
		my_kv.k.data = buf;
		par_get(handle, &my_kv.k, &my_kv.v, &error_message);
		if (error_message) {
			log_fatal("Key %u:%s not found", my_kv.k.size, my_kv.k.data);
			BUG_ON();
		}
	}
	free(buf);
}

/**
 * Function validating the already populated kvs
 * @param hd is an initialised par_handle
 * @param v_info contains informations about the validation process like the different percetages of kc categories
 * First it scans the whole db to ensure that the number of the inserted keys are equal to the benchmark size
 * After it validates each static size kv category using scanners
 * Then it validates each random size kv category using scanners
 * Finally it retrieves all static size kvs using par_get to ensure that the kvs are correct
 * */
static void validate_kvs(par_handle hd, struct test_info v_info)
{
	uint64_t small_num_keys = (v_info.num_keys * v_info.small_kv_percentage) / 100;
	uint64_t medium_num_keys = (v_info.num_keys * v_info.medium_kv_percentage) / 100;
	uint64_t large_num_keys = (v_info.num_keys * v_info.large_kv_percentage) / 100;

	/*first stage
	 * check if num of inserted  keys == num_key using scanners
	*/
	scanner_validate_number_of_kvs(hd, v_info.num_keys);
	/* second stage
	 * validate that the sizes of keys are correctx
	*/
	log_info("Validating static size of small kvs");
	struct task task_info = { .from = 0, .to = small_num_keys / 2, .key_type = SMALL, .size_type = STATIC };
	validate_static_size_of_kvs(hd, task_info);
	log_info("Validating static size of medium kvs");
	task_info.to = medium_num_keys / 2;
	task_info.key_type = MEDIUM;
	validate_static_size_of_kvs(hd, task_info);
	log_info("Validating static size of large kvs");
	task_info.to = large_num_keys / 2;
	task_info.key_type = BIG;
	validate_static_size_of_kvs(hd, task_info);

	/* third stage
	 * validate that random kvs exist in the correct size category
	 */
	log_info("Validating random size of small kvs");
	task_info.to = small_num_keys / 2;
	task_info.size_type = RANDOM;
	task_info.key_type = SMALL;
	validate_random_size_of_kvs(hd, task_info);
	log_info("Validating random size of medium kvs");
	task_info.to = medium_num_keys / 2;
	task_info.key_type = MEDIUM;
	validate_random_size_of_kvs(hd, task_info);
	log_info("Validating random size of large kvs");
	task_info.to = large_num_keys / 2;
	task_info.key_type = BIG;
	validate_random_size_of_kvs(hd, task_info);

	/* forth stage
	 * validate that all keys exist and have the correct size with par_get
	 */
	log_info("Validating %lu medium static size keys...", medium_num_keys / 2);
	task_info.to = medium_num_keys / 2;
	task_info.size_type = STATIC;
	task_info.key_type = MEDIUM;
	read_all_static_kvs(hd, task_info);
	log_info("Validating %lu big static size keys...", large_num_keys / 2);
	task_info.to = large_num_keys / 2;
	task_info.key_type = BIG;
	read_all_static_kvs(hd, task_info);
	log_info("Validating %lu small static size keys...", small_num_keys / 2);
	task_info.to = small_num_keys / 2;
	task_info.key_type = SMALL;
	read_all_static_kvs(hd, task_info);
}

/**
 * test_mixes inserts and validates(with scans and reads), random size and static size kvs using the public api of Parallax
 * */
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
		{ { "medium_kv_percentage", required_argument, 0, 'b' },
		  "--medium_kv_percentage=number, percentage of medium category kvs out of num_of_kvs to be inserted",
		  NULL,
		  INTEGER },
		{ { "small_kv_percentage", required_argument, 0, 'b' },
		  "--small_kv_percentage=number, percentage of small category kvs out of num_of_kvs to be inserted",
		  NULL,
		  INTEGER },
		{ { "big_kv_percentage", required_argument, 0, 'b' },
		  "--big_kv_percentage=number, percentage of big category kvs out of num_of_kvs to be inserted",
		  NULL,
		  INTEGER },
		{ { 0, 0, 0, 0 }, "End of arguments", NULL, INTEGER }
	};
	unsigned options_len = (sizeof(options) / sizeof(struct wrap_option));

	arg_parse(argc, argv, options, options_len);
	arg_print_options(help_flag, options, options_len);
	const char *path = get_option(options, 1);
	const uint64_t num_of_keys = *(uint64_t *)get_option(options, 2);
	const uint32_t medium_kvs_percentage = *(int *)get_option(options, 3);
	const uint32_t small_kvs_percentage = *(int *)get_option(options, 4);
	const uint32_t big_kvs_percentage = *(int *)get_option(options, 5);

	/*sum of percentages must be equal 100*/
	assert(medium_kvs_percentage + small_kvs_percentage + big_kvs_percentage == 100);
	const char *error_message = par_format((char *)path, 128);
	if (error_message) {
		log_fatal("%s", error_message);
		return EXIT_FAILURE;
	}

	par_handle handle = open_db(path);

	random_sizes_table[SMALL].min = 5;
	random_sizes_table[SMALL].max = 100;
	random_sizes_table[MEDIUM].min = 101;
	random_sizes_table[MEDIUM].max = 1024;
	random_sizes_table[BIG].min = 1025;
	random_sizes_table[BIG].max = KV_MAX_SIZE;

	struct test_info t_info = { .small_kv_percentage = small_kvs_percentage,
				    .medium_kv_percentage = medium_kvs_percentage,
				    .large_kv_percentage = big_kvs_percentage,
				    .num_keys = num_of_keys };

	/*populate the db phase*/
	insert_keys(handle, t_info);
	/*validate the poppulated db phase*/
	validate_kvs(handle, t_info);

	error_message = par_close(handle);
	if (error_message) {
		log_fatal("%s", error_message);
		return EXIT_FAILURE;
	}
	log_info("test successfull");
	return 0;
}

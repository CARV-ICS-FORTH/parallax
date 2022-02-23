#include "arg_parser.h"
#include "parallax.h"
#include <assert.h>
#include <btree/gc.h>
#include <log.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define KV_SIZE 1500
#define KEY_PREFIX "ts"
#define NUM_KEYS num_keys
#define TOTAL_KEYS 0
uint64_t num_keys = 1000000;
int update_half = 0;

/**
 * This test checks if the garbage collection mechanism moves KVs properly at the end of the log.
 * Initially KVs are inserted to load the database with large KVs (Phase 1).
 * Next the KVs that were inserted in Phase 1 are validated to be sure no corruptions occured (Phase 2).
 * Next we update half of the KVs to trigger the GC thread to move KVs in the log tail (Phase 3).
 * Finally, we wait for the GC thread to notify the test that KVs have been moved
 * at the log tail before validating the KVs that were not updated still contain the same values (Phase 4).
 */

typedef struct key {
	uint32_t key_size;
	char key_buf[];
} key;

typedef struct value {
	uint32_t value_size;
	char value_buf[];
} value;

static uint64_t insert_counter = 0;
static uint64_t get_counter = 0;

void serially_insert_keys(par_handle hd)
{
	uint64_t i;
	key *k = (key *)malloc(KV_SIZE);

	log_info("Starting population for %lu keys...", NUM_KEYS);

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		if (update_half && i % 2 == 1)
			continue;
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		value *v = (value *)((uint64_t)k + sizeof(key) + k->key_size);
		v->value_size = KV_SIZE - ((2 * sizeof(key)) + k->key_size);
		memset(v->value_buf, 0xDD, v->value_size);
		*(uint64_t *)v->value_buf = insert_counter++;

		if (i % 10000 == 0)
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

void validate_inserted_keys(par_handle hd)
{
	uint64_t i;
	key *k = (key *)malloc(KV_SIZE);
	struct par_value v;
	log_info("Starting population for %lu keys...", NUM_KEYS);

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		if (update_half && i % 2 == 1)
			continue;
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		value *val = (value *)((uint64_t)k + sizeof(key) + k->key_size);
		val->value_size = KV_SIZE - ((2 * sizeof(key)) + k->key_size);
		memset(val->value_buf, 0xDD, val->value_size);
		*(uint64_t *)val->value_buf = get_counter++;
		if (i % 10000 == 0)
			log_info("%s", k->key_buf);

		struct par_key_value kv = { .k.data = (const char *)k->key_buf, .k.size = k->key_size };
		memset(&v, 0, sizeof(struct par_value));
		if (par_get(hd, &kv.k, &v) != PAR_SUCCESS) {
			log_fatal("Key disappeared!");
			exit(EXIT_FAILURE);
		}

		if (*(uint64_t *)val->value_buf != *(uint64_t *)v.val_buffer) {
			log_fatal("Error value does not match");
			exit(EXIT_FAILURE);
		}
		free(v.val_buffer);
	}
	free(k);
	log_info("Population ended");
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
		  "--num_of_kvs=number, parameter that specifies the number of operations the test will execute.",
		  NULL,
		  INTEGER },
		{ { 0, 0, 0, 0 }, "End of arguments", NULL, INTEGER }
	};
	unsigned options_len = (sizeof(options) / sizeof(struct wrap_option));

	arg_parse(argc, argv, options, options_len);
	arg_print_options(help_flag, options, options_len);

	char *path = get_option(options, 1);
	num_keys = *(int *)get_option(options, 2);

	par_db_options db_options;
	db_options.volume_name = path;
	db_options.volume_start = 0;
	db_options.volume_size = 0;
	db_options.create_flag = PAR_CREATE_DB;
	db_options.db_name = "testgc.db";

	par_handle handle = par_open(&db_options);

	serially_insert_keys(handle);
	validate_inserted_keys(handle);

	log_info("Inserted and Validated Keys");
	sleep(2);

	update_half = 1;
	serially_insert_keys(handle);
	sleep(15);

	while (!is_gc_executed())
		;
	validate_inserted_keys(handle);
	log_info("GCed and Validated Keys");

	return 0;
}

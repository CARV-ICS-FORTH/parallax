#include "arg_parser.h"
#include "parallax.h"
#include <assert.h>
#include <btree/gc.h>
#include <log.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PATH "/tmp/kv_store.dat"
#define KV_SIZE 1500
#define KEY_PREFIX "ts"
#define NUM_KEYS num_keys
#define TOTAL_KEYS 0
uint64_t num_keys = 1000000;
int update_half = 0;

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
	struct parallax_options *opts = arg_parser(argc, argv);
	char *path = strdup(opts->file);
	num_keys = opts->num_of_kvs;

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

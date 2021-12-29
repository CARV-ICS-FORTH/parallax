#define _LARGEFILE64_SOURCE
#include <allocator/volume_manager.h>
#include <assert.h>
#include <btree/btree.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <log.h>
#include <parallax.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PATH "/tmp/ramdisk/kv_store.dat"
#define KV_SIZE 1500
#define KEY_PREFIX "ts"
#define NUM_KEYS num_keys
#define TOTAL_KEYS 1000000
uint64_t num_keys = 100000;

typedef struct key {
	uint32_t key_size;
	char key_buf[];
} key;

typedef struct value {
	uint32_t value_size;
	char value_buf[];
} value;

void serially_insert_keys(par_handle hd)
{
	uint64_t i;
	key *k = (key *)malloc(KV_SIZE);
	struct par_key_value key_value;

	log_info("Starting population for %lu keys...", NUM_KEYS);

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		value *v = (value *)((uint64_t)k + sizeof(key) + k->key_size);
		v->value_size = KV_SIZE - ((2 * sizeof(key)) + k->key_size);
		memset(v->value_buf, 0xDD, v->value_size);
		if (i % 10000 == 0)
			log_info("%s", k->key_buf);
		key_value.k.size = k->key_size;
		key_value.k.data = k->key_buf;
		key_value.v.val_buffer = v->value_buf;
		key_value.v.val_size = v->value_size;

		par_put(hd, &key_value);
	}

	free(k);
	log_info("Population ended");
}

void get_all_keys(par_handle hd)
{
	uint64_t i;
	key *k = (key *)malloc(KV_SIZE);
	struct par_key par_key;
	struct par_value par_value;

	log_info("Search for all keys");

	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS); i++) {
		memcpy(k->key_buf + 4, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + 4 + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(&k->key_buf[4]) + 1;
		*(uint32_t *)k->key_buf = k->key_size;
		/* log_info("size %u, %u , string %*s", *(uint32_t*) k->key_buf,k->key_size,k->key_size,&k->key_buf[4]); */
		if (i % 10000 == 0)
			log_info("%s", &k->key_buf[4]);
		par_key.data = &k->key_buf[4];
		par_key.size = k->key_size;
		memset(&par_value, 0, sizeof(par_value));

		assert(par_get(hd, &par_key, &par_value) == PAR_SUCCESS);
	}
	free(k);
	log_info("Searching finished");
}

void delete_half_keys(par_handle hd)
{
	uint64_t i;
	key *k = (key *)malloc(KV_SIZE);
	struct par_key par_key;

	log_info("Delete started");
	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS / 2); i++) {
		memcpy(k->key_buf, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(k->key_buf) + 1;
		/* log_info("size %u, %u , string %*s", *(uint32_t*) k->key_buf,k->key_size,k->key_size,&k->key_buf[4]); */
		par_key.data = k->key_buf;
		par_key.size = k->key_size;

		if (i % 10000 == 0)
			log_info("%s", k->key_buf);
		assert(par_delete(hd, &par_key) == PAR_SUCCESS);
	}
	sleep(5);
	free(k);
	log_info("Delete finished");
}

void get_all_valid_keys(par_handle hd)
{
	uint64_t i;
	key *k = (key *)malloc(KV_SIZE);
	uint64_t count = 0;
	struct par_key par_key;
	struct par_value par_value;

	log_info("Search for all keys");
	for (i = TOTAL_KEYS; i < (TOTAL_KEYS + NUM_KEYS / 2); i++) {
		memcpy(k->key_buf + 4, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + 4 + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(&k->key_buf[4]) + 1;
		*(uint32_t *)k->key_buf = k->key_size;
		/* log_info("size %u, %u , string %*s", *(uint32_t*) k->key_buf,k->key_size,k->key_size,&k->key_buf[4]); */
		if (i % 10000 == 0)
			log_info("%s", &k->key_buf[4]);

		par_key.data = &k->key_buf[4];
		par_key.size = k->key_size;
		memset(&par_value, 0, sizeof(par_value));
		if (par_get(hd, &par_key, &par_value) == PAR_KEY_NOT_FOUND) {
			/* log_info("%d", get_op.tombstone); */
			/* BREAKPOINT; */
			++count;
		}
		/* assert(get_op.tombstone); */
		/* assert(get_op.found); */
	}
	for (i = ((TOTAL_KEYS + ((NUM_KEYS / 2) + 1))); i < (TOTAL_KEYS + NUM_KEYS); i++) {
		memcpy(k->key_buf + 4, KEY_PREFIX, strlen(KEY_PREFIX));
		sprintf(k->key_buf + 4 + strlen(KEY_PREFIX), "%llu", (long long unsigned)i);
		k->key_size = strlen(&k->key_buf[4]) + 1;
		*(uint32_t *)k->key_buf = k->key_size;
		/* log_info("size %u, %u , string %*s", *(uint32_t*) k->key_buf,k->key_size,k->key_size,&k->key_buf[4]); */
		if (i % 10000 == 0)
			log_info("%s", &k->key_buf[4]);

		par_key.data = &k->key_buf[4];
		par_key.size = k->key_size;
		memset(&par_value, 0, sizeof(par_value));
		if (par_get(hd, &par_key, &par_value) == PAR_SUCCESS) {
			/* log_info("%s found %d", &k->key_buf[4], get_op.found); */
			/* log_info("%d", get_op.tombstone); */
			/* exit(EXIT_FAILURE); */
			/* ++count; */

		} else {
			count++;
		}
		/* assert(get_op.tombstone); */
		/* assert(get_op.found); */
	}

	free(k);
	log_info("Searching finished %d", count);
	assert(count == NUM_KEYS / 2);
}

int main(void)
{
	par_db_options db_options;
	db_options.volume_name = PATH;
	db_options.volume_start = 0;
	db_options.volume_size = 0;
	db_options.create_flag = PAR_CREATE_DB;
	db_options.db_name = "test.db";
	par_handle handle = par_open(&db_options);
	//snapshot(handle->volume_desc);
	serially_insert_keys(handle);
	get_all_keys(handle);
	delete_half_keys(handle);
	get_all_valid_keys(handle);
	par_close(handle);
	log_info("----------------------------------CLOSE FINISH--------------------------------------");
	handle = par_open(&db_options);
	get_all_valid_keys(handle);

	//snapshot(handle->volume_desc);

	return 0;
}

#include "arg_parser.h"
#include <../lib/include/parallax/parallax.h>
#include <btree/gc.h>
#include <log.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_KV_PAIR_SIZE 4096
#define MY_MAX_KEY_SIZE 255

static void generate_random_key(unsigned char *key_buffer, uint32_t key_size)
{
	for (uint32_t i = 0; i < key_size; i++)
		key_buffer[i] = rand() % 256;
}

static void generate_random_value(char *value_buffer, uint32_t value_size, uint32_t id)
{
	*(uint32_t *)value_buffer = id;
	for (uint32_t i = sizeof(uint64_t); i < value_size; i++)
		value_buffer[i] = rand() % 256;
}

uint64_t correct_lsn = 0;
static void insert_keys(par_handle handle)
{
	int64_t i = 0;
	unsigned char key_buffer[MY_MAX_KEY_SIZE] = { 0 };
	unsigned char value_buffer[MAX_KV_PAIR_SIZE] = { 0 };
	while (i < 1000000) {
		struct par_key_value kv_pair = { 0 };
		if (i && 0 == i % 10000) {
			log_info("Progress: inserted %ld kv pairs so far", i);
		}

		kv_pair.k.size = rand() % (MY_MAX_KEY_SIZE + 1);

		if (!kv_pair.k.size)
			kv_pair.k.size++;

		kv_pair.v.val_size = rand() % (MAX_KV_PAIR_SIZE - (kv_pair.k.size + sizeof(uint32_t)));
		if (kv_pair.v.val_size < 4)
			kv_pair.v.val_size = 4;

		generate_random_key(key_buffer, kv_pair.k.size);
		kv_pair.k.data = (char *)key_buffer;
		generate_random_value((char *)value_buffer, kv_pair.v.val_size, i);
		kv_pair.v.val_buffer = (char *)value_buffer;

		const char *error_message = NULL;
		struct par_put_metadata metadata = par_put(handle, &kv_pair, &error_message);

		if (error_message) {
			log_fatal("Error message from par_close: %s", error_message);
			_Exit(EXIT_FAILURE);
		}

		/*if (metadata.lsn != correct_lsn) {
			log_fatal("Wrong lsn sequence returned from par_put, got %ld expected %ld", metadata.lsn,
				  correct_lsn);
			_Exit(EXIT_FAILURE);
		}*/
		correct_lsn += 1;
		//sleep(1);
		i++;
	}
	log_info("Population ended Successfully! :-)");
}

int main(void)
{
	//PAR_OPEN TEST
	par_db_options *db_options = malloc(sizeof(par_db_options));
	db_options->options = malloc(sizeof(struct par_options_desc));

	db_options->create_flag = PAR_CREATE_DB;
	db_options->db_name = "superdatabase";
	db_options->options->value = 90909;
	db_options->volume_name = "~/db";
	par_handle handle = par_open(db_options, NULL);
	(void)handle;

	//PAR_PUT TEST
	struct par_key_value *kv = malloc(sizeof(struct par_key_value));

	kv->k.data = "Sample put key";
	kv->k.size = 15;

	kv->v.val_buffer = "Sample put value";
	kv->v.val_buffer_size = 17;
	kv->v.val_size = 17;

	insert_keys(handle);

	//PAR_DELETE TEST
	struct par_key *k = malloc(sizeof(struct par_key));

	k->size = 15;
	k->data = "Sample put key";
	par_delete(handle, k, NULL);

	return 0;
}

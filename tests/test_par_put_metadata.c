#include "arg_parser.h"
#include <log.h>
#include <parallax/parallax.h>
#include <btree/gc.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_KV_PAIR_SIZE 4096
#define MY_MAX_KEY_SIZE 255

static par_handle open_db(const char *path)
{
	disable_gc();
	par_db_options db_options;
	const char *error_message = NULL;
	db_options.db_name = "TIRESIAS";
	db_options.create_flag = PAR_CREATE_DB;
	db_options.options = par_get_default_options();
	db_options.volume_name = (char *)path;
	par_handle hd = par_open(&db_options, &error_message);

	return hd;
}

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
static void insert_keys(par_handle handle, int64_t num_of_keys)
{
	log_info("Starting population for %lu keys...", num_of_keys);

	unsigned char key_buffer[MY_MAX_KEY_SIZE] = { 0 };
	unsigned char value_buffer[MAX_KV_PAIR_SIZE] = { 0 };
	for (int64_t i = 0; i < num_of_keys; i++) {
		struct par_key_value kv_pair = { 0 };

		kv_pair.k.size = rand() % (MY_MAX_KEY_SIZE + 1);

		// if (kv_pair.k.size <= 12) {
		// 	kv_pair.k.size = 14;
		// }

		if (!kv_pair.k.size)
			kv_pair.k.size++;
		kv_pair.v.val_size = rand() % (MAX_KV_PAIR_SIZE - (kv_pair.k.size + sizeof(uint32_t)));
		if (kv_pair.v.val_size < 4)
			kv_pair.v.val_size = 4;

		generate_random_key(key_buffer, kv_pair.k.size);
		kv_pair.k.data = (char *)key_buffer;
		generate_random_value((char *)value_buffer, kv_pair.v.val_size, i);
		kv_pair.v.val_buffer = (char *)value_buffer;

		//log_debug("Inserting in store key size %u value size %u unique keys %lu", kv_pair.k.size,
		//	  kv_pair.v.val_size, unique_keys);
		const char *error_message = NULL;
		struct par_put_metadata metadata = par_put(handle, &kv_pair, &error_message);
		if (metadata.lsn != correct_lsn) {
			log_fatal("Wrong sequenting on lsn returned from par put, got %ld expected %ld", metadata.lsn,
				  correct_lsn);
			exit(EXIT_FAILURE);
		}
		correct_lsn += 1;
	}
	log_info("Population ended Successfully! :-)");
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
		{ { 0, 0, 0, 0 }, "End of arguments", NULL, INTEGER }
	};
	unsigned options_len = (sizeof(options) / sizeof(struct wrap_option));

	arg_parse(argc, argv, options, options_len);
	arg_print_options(help_flag, options, options_len);
	const char *path = get_option(options, 1);
	const int64_t num_of_keys = *(int64_t *)get_option(options, 2);

	const char *error_message = par_format((char *)path, 128);
	if (error_message) {
		log_fatal("Error message from par_format: %s", error_message);
		exit(EXIT_FAILURE);
	}
	par_handle handle = open_db(path);

	/*populate the db phase*/
	insert_keys(handle, num_of_keys);
	error_message = par_close(handle);
	if (error_message) {
		log_fatal("Error message from par_close: %s", error_message);
		exit(EXIT_FAILURE);
	}
	log_info("test successfull");
	return 0;
}

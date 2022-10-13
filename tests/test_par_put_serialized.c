#include "arg_parser.h"
#include "log.h"
#include <btree/kv_pairs.h>
#include <parallax/parallax.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAX_REGIONS 128

int main(int argc, char *argv[])
{
	int help_flag = 0;
	struct wrap_option options[] = {
		{ { "help", no_argument, &help_flag, 1 }, "Prints valid arguments for test_medium.", NULL, INTEGER },
		{ { "file", required_argument, 0, 'a' },
		  "--file=path to file of db, parameter that specifies the target where parallax is going to run.",
		  NULL,
		  STRING },
		{ { 0, 0, 0, 0 }, "End of arguments", NULL, INTEGER }
	};
	unsigned options_len = (sizeof(options) / sizeof(struct wrap_option));
	arg_parse(argc, argv, options, options_len);
	arg_print_options(help_flag, options, options_len);

	char *path = get_option(options, 1);
	const char *error_message = par_format(path, MAX_REGIONS);
	if (error_message) {
		log_fatal("%s", error_message);
		return EXIT_FAILURE;
	}

	par_db_options db_options = { .volume_name = path,
				      .create_flag = PAR_CREATE_DB,
				      .db_name = "serialized_par_put.db",
				      .options = par_get_default_options() };
	par_handle handle = par_open(&db_options, &error_message);
	if (error_message) {
		log_fatal("%s", error_message);
		return EXIT_FAILURE;
	}

	char serialized_key_value[1024] = { 0 };
	struct splice *serialized_kv = (struct splice *)serialized_key_value;
	set_key_size(serialized_kv, 10);
	set_value_size(serialized_kv, 2);
	set_key(serialized_kv, "abcdabcda", 10);
	set_value(serialized_kv, "a", 2);

	par_put_serialized(handle, serialized_key_value, &error_message);
	if (error_message) {
		log_fatal("%s", error_message);
		return EXIT_FAILURE;
	}

	error_message = par_close(handle);

	if (error_message) {
		log_fatal("%s", error_message);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

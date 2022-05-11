#include "arg_parser.h"
#include <parallax.h>
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
	par_format(path, MAX_REGIONS);
	par_db_options db_options = { .volume_name = path,
				      .volume_start = 0,
				      .volume_size = 0,
				      .create_flag = PAR_CREATE_DB,
				      .db_name = "serialized_par_put.db" };
	par_handle handle = par_open(&db_options);
	char serialized_key_value[1024] = { 0 };
	char *serialize_kv = serialized_key_value;
	*(uint32_t *)serialize_kv = 10;
	serialize_kv += 4;
	strcpy(serialize_kv, "abcdabcda");
	serialize_kv += 10;
	*(uint32_t *)serialize_kv = 1;
	serialize_kv += 4;
	*serialize_kv = 'a';

	if (par_put_serialized(handle, serialized_key_value) != PAR_SUCCESS)
		return EXIT_FAILURE;

	par_close(handle);

	return EXIT_SUCCESS;
}

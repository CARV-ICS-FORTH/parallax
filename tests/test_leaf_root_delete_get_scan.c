#include "arg_parser.h"
#include <common/common.h>
#include <log.h>
#include <parallax/parallax.h>
#include <stdlib.h>
#include <string.h>

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

	par_db_options db_options = { .volume_name = get_option(options, 1),
				      .create_flag = PAR_CREATE_DB,
				      .db_name = "test_leaf_root_delete_get_scan.db",
				      .options = par_get_default_options() };
	const char *error_message = NULL;
	par_handle handle = par_open(&db_options, &error_message);
	if (error_message) {
		log_fatal("%s", error_message);
		free((char *)error_message);
		return EXIT_FAILURE;
	}
	struct par_key_value key_value;
	key_value.k.data = "/";
	key_value.k.size = strlen(key_value.k.data);
	key_value.v.val_buffer = "16895|0|";
	key_value.v.val_size = strlen(key_value.v.val_buffer);

	par_put(handle, &key_value, &error_message);
	if (error_message) {
		log_fatal("Par put failed %s!", error_message);
		free((char *)error_message);
		BUG_ON();
	}

	key_value.k.data = "Example";
	key_value.k.size = strlen(key_value.k.data);
	key_value.v.val_buffer = "Content";
	key_value.v.val_size = strlen(key_value.v.val_buffer);

	par_put(handle, &key_value, &error_message);
	if (error_message) {
		log_fatal("Par put failed! %s", error_message);
		free((char *)error_message);
		BUG_ON();
	}

	par_delete(handle, &key_value.k, &error_message);

	if (error_message) {
		log_fatal("Par put failed! %s", error_message);
		free((char *)error_message);
		BUG_ON();
	}

	struct par_value unused_value = { 0 };
	par_get(handle, &key_value.k, &unused_value, &error_message);
	if (!error_message) {
		log_fatal("Found key %.*s that should not exist!", key_value.k.size, key_value.k.data);
		BUG_ON();
	}
	free((char *)error_message);
	key_value.k.data = "";
	key_value.k.size = 1;

	error_message = NULL;
	par_scanner scanner = par_init_scanner(handle, &key_value.k, PAR_GREATER_OR_EQUAL, &error_message);
	if (!par_is_valid(scanner)) {
		log_fatal("Nothing found! it shouldn't!");
		BUG_ON();
	}
	struct par_key keyptr = par_get_key(scanner);
	if (strncmp(keyptr.data, "/", strlen("/"))) {
		log_fatal("Expected key not found from scanner!");
		BUG_ON();
	}

	if (par_get_next(scanner) == 1) {
		keyptr = par_get_key(scanner);
		log_fatal("Found key that should not be found in scanner! %s", keyptr.data);
		BUG_ON();
	}
	par_close_scanner(scanner);
	error_message = par_close(handle);
	if (error_message) {
		log_fatal("%s", error_message);
		free((char *)error_message);
		return EXIT_FAILURE;
	}
	return 0;
}

#include "arg_parser.h"
#include <log.h>
#include <parallax/parallax.h>
#include <stdlib.h>

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
	char *error_message = par_format(get_option(options, 1), MAX_REGIONS);
	if (error_message) {
		log_fatal("%s", error_message);
		free(error_message);
		return EXIT_FAILURE;
	}

	return 0;
}

#include "arg_parser.h"
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdio.h>

static int help_flag;

struct parallax_options *arg_parser(int argc, char *argv[])
{
	int c;
	struct parallax_options *options = (struct parallax_options *)calloc(1, sizeof(struct parallax_options));

	while (1) {
		static struct option long_options[] = { /* These option set the help flag */
							{ "help", no_argument, &help_flag, 1 },
							/* These options don’t set a flag */

							{ "file", required_argument, 0, 'a' },
							{ "num_of_kvs", required_argument, 0, 'b' },
							{ "small_kvs_percentage", required_argument, 0, 'c' },
							{ "medium_kvs_percentage", required_argument, 0, 'd' },
							{ "large_kvs_percentage", required_argument, 0, 'e' },
							{ 0, 0, 0, 0 }
		};
		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long(argc, argv, "", long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 0:
			/* If this option set a flag, do nothing else now. */
			if (long_options[option_index].flag != 0)
				break;

			break;

		case 'a':
			if (options->file != NULL)
				free(options->file);
			options->file = strdup(optarg);
			break;

		case 'b':
			options->num_of_kvs = atoi(optarg);
			break;

		case 'c':
			options->small_kvs_percentage = atoi(optarg);
			break;

		case 'd':
			options->medium_kvs_percentage = atoi(optarg);
			break;

		case 'e':
			options->large_kvs_percentage = atoi(optarg);
			break;

		case '?':
			/* getopt_long already printed an error message. */
			exit(0);
			break;

		default:
			abort();
		}
	}

	/*--help message*/
	if (help_flag) {
		printf("\033[0;32m help for test argmuments:\n\033[0;37m");
		printf("\t--path=path to file of db, parameter that specifies the target where parallax is going to run\n");
		printf("\t--num_of_kvs=number, parameter that specifies the number of operation the test will execute\n");
		printf("\t--small_kvs_percentage=number, parameter that specifies the overall percentage of small kvs out of num_of_kvs operations\n");
		printf("\t--medium_kvs_percentage=number, parameter that specifies the overall percentage of medium kvs out of num_of_kvs operations\n");
		printf("\t--large_kvs_percentage=number, parameter that specifies the overall percentage of large kvs out of num_of_kvs operations\n");
		printf("\033[0;31m Important notes:\n \033[0;37m");
		printf("\tThe sum of all percentages must be equal to 100. More notes to come..\n");
		printf("\n");
		exit(0);
	}

	// check for fewer arguments than necessery
	if (argc != 6) {
		printf("\033[0;31m Not enough arguments use --help for more\033[0;37\n");
	}
	return options;
}

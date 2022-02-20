#include "arg_parser.h"
#include <getopt.h>
#include <log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void fill_option(struct wrap_option *options, unsigned option_index)
{
	switch (options[option_index].option_type) {
	case STRING:
		options[option_index].option_value = strdup(optarg);
		break;
	case INTEGER:
		options[option_index].option_value = malloc(sizeof(int));
		*(int *)options[option_index].option_value = atoi(optarg);
		break;
	default:
		exit(EXIT_FAILURE);
	}
}

static int fail = 0;
void arg_print_options(int help_flag, struct wrap_option *options, unsigned options_len)
{
	if (help_flag) {
		for (unsigned i = 1; i < options_len - 1; i++) {
			fprintf(stderr, "%s  : value = ", options[i].description);
			if (options[i].option_value) {
				switch (options[i].option_type) {
				case STRING:
					fprintf(stderr, "%s", (char *)get_option(options, i));
					break;
				case INTEGER:
					fprintf(stderr, "%d", *(int *)get_option(options, i));
					break;
				}
			}
			fprintf(stderr, "\n");
		}
		_Exit(EXIT_FAILURE);
	}

	if (fail)
		_Exit(EXIT_FAILURE);
}

int *get_integer_option(struct wrap_option *options, unsigned option_index)
{
	return (int *)options[option_index].option_value;
}

char *get_string_option(struct wrap_option *options, unsigned option_index)
{
	return options[option_index].option_value;
}

void *get_option(struct wrap_option *options, unsigned option_index)
{
	switch (options[option_index].option_type) {
	case STRING:
		return get_string_option(options, option_index);
	case INTEGER:
		return get_integer_option(options, option_index);
	default:
		_Exit(EXIT_FAILURE);
	}
}

void arg_parse(int argc, char *argv[], struct wrap_option *options, unsigned options_len)
{
	/* getopt_long stores the option index here. */
	int option_index = 0;
	unsigned count_parsed_arguments = 0;
	struct option temp_options[options_len];
	for (unsigned i = 0; i < options_len; ++i)
		temp_options[i] = options[i].option;

	while (1) {
		int c = getopt_long(argc, argv, "", temp_options, &option_index);

		if (c == -1)
			break;
		else if (!c)
			continue;
		else {
			fill_option(options, option_index);
			++count_parsed_arguments;
		}
	}

	/** We need to ignore the help option and the final option that signals
	 * we reached the end of the options buffer thus -2 options by default. */
	if (options_len - 2 != count_parsed_arguments) {
		log_fatal("Not enough arguments provided! Expected %u provided %u !", options_len - 2,
			  count_parsed_arguments);
		fail = 1;
	}
}

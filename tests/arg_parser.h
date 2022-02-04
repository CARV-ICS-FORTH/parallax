#ifndef ARG_PARSER_H_
#define ARG_PARSER_H_
#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * This enumerator is responsible for decoding properly the data that `optarg` contains.
 * At the moment it supports STRING and INTEGER types but it is easy to extend for other types.
 * To add a new type extend the enumerator and extend the fill_option() in arg_parser.c.
 */
enum option_type { STRING, INTEGER };

/**
 * Wrap_option wraps struct option provided by getopt.h to support easier management for cmd line arguments.
 */
struct wrap_option {
	/* Default options provided by getopt.h */
	struct option option;
	/* Description printed by the help message for the current option. */
	const char *description;
	/* The data filled from the cmd line argument based on the option's type */
	void *option_value;
	/* option_type defines the contents to be expected for this option. */
	enum option_type option_type;
};

/**
 * Responsible for parsing the cmd line arguments and fillin the options array with the arguments provided.
 * It takes argc and argv from main and options should be an array filled with valid data.
 * As getopt the last option should contain the {0,0,0,0} value for getopt to detect the end of the array.
 * options_len should take into account also the slot of the {0,0,0,0} element.
 */
void arg_parse(int argc, char *argv[], struct wrap_option *options, unsigned options_len);

/**
 * Prints the description provided in each wrap_option if help_flag equals 1 and exits.
 * */
void arg_print_options(int help_flag, struct wrap_option *options, unsigned options_len);

/**
 * Returns options[option_index] data based on its option_type.
 * In case of string it returns a char *.
 * In case of integers it returns an int *.
 * */
void *get_option(struct wrap_option *options, unsigned option_index);

#endif // ARG_PARSER_H_

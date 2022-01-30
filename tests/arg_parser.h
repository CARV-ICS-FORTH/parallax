#ifndef ARG_PARSER_H_
#define ARG_PARSER_H_
#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>

enum option_type { STRING, INTEGER };

struct wrap_option {
	struct option option;
	const char *description;
	void *option_value;
	enum option_type option_type;
};

void arg_parse(int argc, char *argv[], struct wrap_option *options, unsigned options_len);
void arg_print_options(int help_flag, struct wrap_option *options, unsigned options_len);
int get_integer_option(struct wrap_option *options, unsigned option_index);
char *get_string_option(struct wrap_option *options, unsigned option_index);

#endif // ARG_PARSER_H_

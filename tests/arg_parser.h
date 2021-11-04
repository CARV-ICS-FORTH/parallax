#ifndef ARG_PARSER_H_
#define ARG_PARSER_H_
#include <stdlib.h>
#include <stdint.h>

struct parallax_options {
	char *file;
	uint64_t num_of_kvs;
	uint64_t small_kvs_percentage;
	uint64_t medium_kvs_percentage;
	uint64_t large_kvs_percentage;
};
/*returns a struct containing the values of params
 *Params get be given in any order but params must contain
 * --file=value_of_path_to_file
 * --num_of_kvs=value_of_num_ops
 * --small_kvs_percentage=value_of_small_kvs_percentage
 * --medium_kv_percentage=value_of_medium_kv_percentage
 * --large_kv_percentage=value_of_large_kv_percentage
 *
 * for more info use --help
 */
struct parallax_options *arg_parser(int argc, char *argv[]);

#endif // ARG_PARSER_H_

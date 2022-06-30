#include "../tests/arg_parser.h"
#include <log.h>
#include <parallax.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define NUM_OF_OPS 2

void execute_put_request(par_handle hd, char *line);
void execute_get_request(par_handle hd, char *line);
typedef void execute_task(par_handle hd, char *line);
execute_task *const tracer_dispatcher[NUM_OF_OPS] = { execute_put_request, execute_get_request };
enum Op { PUT = 0, GET };

void execute_get_request(par_handle hd, char *line)
{
	/*thats the operation, we dont need it*/
	strtok_r(line, " ", &line);
	uint32_t key_size = atoi(strtok_r(line, " ", &line));
	char *key = strtok_r(line, " ", &line);
	struct par_key lookup_key = { .size = (uint32_t)key_size, .data = (const char *)key };
	struct par_value lookup_value = { .val_buffer = NULL };

	if (par_get(hd, &lookup_key, &lookup_value) != PAR_SUCCESS) {
		log_fatal("Cannot find key %.*s", key_size, key);
		_exit(EXIT_FAILURE);
	}
	free(lookup_value.val_buffer);
}

void execute_put_request(par_handle hd, char *line)
{
	char _tmp[4096];
	char *key_buf = _tmp;
	/*thats the operation, we dont need it*/
	strtok_r(line, " ", &line);
	uint32_t key_size = atoi(strtok_r(line, " ", &line));
	char *key = strtok_r(line, " ", &line);
	uint32_t value_size = atoi(strtok_r(line, " ", &line));
	char *value = strtok_r(line, " ", &line);

	/*prepare the request*/
	*(uint32_t *)key_buf = key_size;
	memcpy(key_buf + sizeof(uint32_t), key, key_size);
	*(uint32_t *)(key_buf + sizeof(uint32_t) + key_size) = value_size;
	memcpy(key_buf + sizeof(uint32_t) + key_size + sizeof(uint32_t), value, value_size);

	par_put_serialized(hd, key_buf);
}

enum Op get_op(char *line)
{
	char *tmp_line = strdup(line);
	/*thats the Operation*/
	char *token = strtok_r(tmp_line, " ", &tmp_line);
	if (!strcmp(token, "PUT"))
		return PUT;

	return GET;
}

void execute_trace(par_handle hd, char *filename)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t read = 0;
	/*Open the file*/
	FILE *file = fopen(filename, "r");
	if (!file) {
		log_fatal("Cannot open tracefile:%s", filename);
		_exit(EXIT_FAILURE);
	}
	/*read file line by line*/
	while ((read = getline(&line, &len, file)) != -1) {
		enum Op operation = get_op(line);
		tracer_dispatcher[operation](hd, line);
	}

	/*close file*/
	if (line)
		free(line);
}

par_handle open_db(const char *path)
{
	par_db_options db_options;
	db_options.volume_name = (char *)path;
	db_options.volume_start = 0;
	db_options.volume_size = 0;
	db_options.create_flag = PAR_CREATE_DB;
	db_options.db_name = "tracer";

	par_handle handle = par_open(&db_options);
	return handle;
}

int main(int argc, char **argv)
{
	int help_flag = 0;

	struct wrap_option options[] = {
		{ { "help", no_argument, &help_flag, 1 }, "Prints valid arguments for tracer.", NULL, INTEGER },
		{ { "file", required_argument, 0, 'a' },
		  "--file=path ot file of db, parameter that specifies the target where parallax is going to run.",
		  NULL,
		  STRING },
		{ { "tracefile", required_argument, 0, 'b' }, "--tracefil=path to tracefile ", NULL, STRING },
		{ { 0, 0, 0, 0 }, "End of arguments", NULL, INTEGER }
	};
	unsigned options_len = (sizeof(options) / sizeof(struct wrap_option));

	arg_parse(argc, argv, options, options_len);
	arg_print_options(help_flag, options, options_len);
	const char *path = get_option(options, 1);
	par_format((char *)path, 128);
	par_handle hd = open_db(path);

	char *filename = get_option(options, 2);
	log_info("Executing trace from tracefile %s", filename);
	execute_trace(hd, filename);
	log_info("All good! tracer out..");
}

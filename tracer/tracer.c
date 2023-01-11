#include "../lib/btree/kv_pairs.h"
#include "../tests/arg_parser.h"
#include <log.h>
#include <parallax/parallax.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define NUM_OF_OPS 2

void execute_put_request(par_handle handle, char *line);
void execute_get_request(par_handle handle, char *line);
typedef void execute_task(par_handle handle, char *line);
execute_task *const tracer_dispatcher[NUM_OF_OPS] = { execute_put_request, execute_get_request };
enum Op { PUT = 0, GET };

/**
 * Execute a get request of the key specified by line
 * @param hd, the db handle that we initiated with db open
 * @param line, a str with the line contents
 * */
void execute_get_request(par_handle handle, char *line)
{
	/*thats the operation, we dont need it*/
	strtok_r(line, " ", &line);
	uint32_t key_size = atoi(strtok_r(line, " ", &line));
	char *key = strtok_r(line, " ", &line);
	struct par_key lookup_key = { .size = (uint32_t)key_size, .data = (const char *)key };
	struct par_value lookup_value = { .val_buffer = NULL };
	const char *error_message = NULL;

	par_get(handle, &lookup_key, &lookup_value, &error_message);
	if (error_message) {
		log_fatal("Cannot find key %.*s", key_size, key);
		_exit(EXIT_FAILURE);
	}
	free(lookup_value.val_buffer);
}

/**
 * Execute a put request of the key specified by line
 * @param hd, the db handle that we initiated with db open
 * @param line, a str with the line contents
 * */
void execute_put_request(par_handle handle, char *line)
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
	struct kv_splice *kv_buf = (struct kv_splice *)key_buf;
	kv_splice_set_key_size(kv_buf, key_size);
	kv_splice_set_value_size(kv_buf, key_size);
	kv_splice_set_key(kv_buf, key, key_size);
	kv_splice_set_value(kv_buf, value, value_size);
	const char *error_message = NULL;
	par_put_serialized(handle, key_buf, &error_message, true);
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

/**
 * Read the file line by line and execute its operations
 * @param hd, the db handle that we initiated with db open
 * @param filename, name of the tracefile
 * */
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

/**
 * Opens the db
 * @param path, the path to the file where the db will be initiated
 * */
par_handle open_db(const char *path)
{
	par_db_options db_options;
	db_options.volume_name = (char *)path;
	db_options.create_flag = PAR_CREATE_DB;
	db_options.db_name = "tracer";
	db_options.options = par_get_default_options();

	const char *error_message = NULL;
	par_handle handle = par_open(&db_options, &error_message);
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
	const char *error_message = par_format((char *)path, 128);
	if (error_message != NULL) {
		log_fatal("Error message from par_format: %s", error_message);
		exit(EXIT_FAILURE);
	}
	par_handle hd = open_db(path);

	char *filename = get_option(options, 2);
	log_info("Executing trace from tracefile %s", filename);
	execute_trace(hd, filename);
	log_info("All good! tracer out..");
}

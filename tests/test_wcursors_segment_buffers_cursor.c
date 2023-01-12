#include "allocator/persistent_operations.h"
#include "arg_parser.h"
#include "btree/level_write_cursor.h"
#include <assert.h>
#include <btree/kv_pairs.h>
#include <log.h>
#include <parallax/parallax.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

static par_handle test_wcursors_segment_buffers_cursor_open_parallax(struct wrap_option *options)
{
	par_db_options db_options = { 0 };
	db_options.volume_name = get_option(options, 1);
	log_debug("Volume name %s", db_options.volume_name);

	const char *error_message = par_format(db_options.volume_name, 16);
	if (error_message) {
		log_fatal("Error message from par_format: %s", error_message);
		exit(EXIT_FAILURE);
	}

	db_options.db_name = "wcursors_append_segment";
	db_options.create_flag = PAR_CREATE_DB;
	db_options.options = par_get_default_options();
	db_options.options[REPLICA_MODE].value = 1;
	db_options.options[PRIMARY_MODE].value = 0;
	par_handle parallax_db = par_open(&db_options, &error_message);
	return parallax_db;
}

static void test_wcursors_segment_buffers_cursor(par_handle handle)
{
	log_info("Initialize a level write cursor for level 4");
	uint32_t level_id = 4;
	uint32_t tree_id = 1;
	par_init_compaction_id(handle, level_id, tree_id);
	struct wcursor_level_write_cursor *write_cursor_segments =
		wcursor_init_write_cursor(level_id, handle, tree_id, true);
	wcursor_segment_buffers_iterator_t segment_buffers_cursor =
		wcursor_segment_buffers_cursor_init(write_cursor_segments);

	for (int i = 0; i < MAX_HEIGHT; ++i) {
		assert(write_cursor_segments->segment_buf[i] ==
		       wcursor_segment_buffers_cursor_get_offt(segment_buffers_cursor));
		assert(wcursor_segment_buffers_cursor_is_valid(segment_buffers_cursor));
		wcursor_segment_buffers_cursor_next(segment_buffers_cursor);
	}

	assert(!wcursor_segment_buffers_cursor_is_valid(segment_buffers_cursor));
	wcursor_segment_buffers_cursor_close(segment_buffers_cursor);
	wcursor_close_write_cursor(write_cursor_segments);
}

int main(int argc, char **argv)
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

	unsigned optional_args_len = 0;
	unsigned options_len = sizeof(options) / sizeof(struct wrap_option);
	log_debug("Options len %u", options_len);
	arg_parse(argc, argv, options, options_len - optional_args_len);
	arg_print_options(help_flag, options, options_len);

	// open parallax
	log_info("Opening Parallax at path %s", (char *)get_option(options, 1));
	par_handle handle = test_wcursors_segment_buffers_cursor_open_parallax(options);

	// test logic
	test_wcursors_segment_buffers_cursor(handle);
	log_info("Test succeeded");
}

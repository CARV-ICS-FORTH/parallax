#include <stdio.h>

struct server_handle;
struct server_options;

struct server_options *server_parse_argv_opts(int argc,
					      char *__restrict__ *__restrict__ argv) __attribute_warn_unused_result__;

struct server_handle *
portals_server_handle_init(struct server_options *server_options) __attribute_warn_unused_result__;

int server_start(struct server_handle *server_handle) __attribute_warn_unused_result__;

int server_print_config(struct server_handle *server_handle);

#ifndef PORTALS_SERVER_HANDLE_H
#define PORTALS_SERVER_HANDLE_H
#include <stdio.h>

struct server_handle;
struct server_options;

struct server_options *
prsv_server_parse_argv_opts(int argc, char *__restrict__ *__restrict__ argv) __attribute_warn_unused_result__;

struct server_handle *
prsv_portals_server_handle_init(struct server_options *server_options) __attribute_warn_unused_result__;

int prsv_server_start(struct server_handle *server_handle) __attribute_warn_unused_result__;

int prsv_server_print_config(struct server_handle *server_handle);
#endif

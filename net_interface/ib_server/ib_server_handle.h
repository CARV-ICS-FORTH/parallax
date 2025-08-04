#ifndef INFINIBAND_SERVER_HANDLE_H
#define INFINIBAND_SERVER_HANDLE_H

#include "../portals_server/portals_worker.h"
#include "../portals_server/worker_request.h"
#include <arpa/inet.h>

long ib_server_parse_number(const char *str, const char *opt);

void ib_server_check_arg(int argc, int option_id);

void ib_server_set_address(struct server_options *opts, const char *arg);

void ib_server_set_port(struct server_options *opts, const char *arg);

struct server_options *ib_server_parse_argv_opts(int argc, char **argv);

struct server_handle *ib_server_handle_init(struct server_options *opts);

int ib_server_print_config(struct server_handle *server_handle);

int ib_handle_cm_event(struct server_handle *server_handle, struct rdma_cm_event *event);

int ib_loop(struct server_handle *server_handle);

void worker_scheduler(struct server_handle *server_handle, void *buf);

size_t par_net_header_size(void);

size_t ib_par_net_get_total_bytes(char *buffer);

uint32_t par_net_header_get_opcode(char *buffer);

void *ib_put_and_reply(void *arg);

int ib_handle_event(struct ibv_wc *wc, struct server_handle *server_handle);

void *connection_manager_thread(void *arg);

int ib_server_start(struct server_handle *server_handle);

#endif

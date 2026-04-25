#ifndef INFINIBAND_SERVER_HANDLE_H
#define INFINIBAND_SERVER_HANDLE_H

#include "../par_net_worker/par_net_worker.h"
#include "../par_net_worker/par_net_worker_request.h"
#include "ccqueue.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

struct server_options;
struct server_handle;

long par_ib_server_parse_number(const char *str, const char *opt);

void par_ib_server_check_arg(int argc, int option_id);

void par_ib_server_set_address(struct server_options *opts, const char *arg);

void par_ib_server_set_port(struct server_options *opts, const char *arg);

struct server_options *par_ib_server_parse_argv_opts(int argc, char **argv);

struct root_server_handle *par_ib_server_handle_init(struct server_options *opts);

int par_ib_server_print_config(struct root_server_handle *server_handle);

uint32_t par_ib_server_get_threadno(struct root_server_handle *handle);

struct ibv_pd *par_ib_server_get_ibv_pd(struct root_server_handle *handle);

uint32_t par_net_get_threadno(struct server_options *server_options);

int par_ib_handle_cm_event(struct root_server_handle *server_handle, struct rdma_cm_event *event);

void *par_ib_worker_loop(void *arg);

size_t par_net_header_size(void);

size_t par_ib_par_net_get_total_bytes(char *buffer);

uint32_t par_net_header_get_opcode(char *buffer);

void par_ib_put_and_reply(struct server_handle *server_handle, struct par_ib_recv_slot *recv_slot);

int par_ib_handle_event(struct ibv_wc *wc, struct server_handle *server_handle);

void *connection_manager_thread(void *arg);

int par_ib_server_start(struct root_server_handle *server_handle);

#endif

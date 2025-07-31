#ifndef INFINIBAND_SERVER_HANDLE_H
#define INFINIBAND_SERVER_HANDLE_H

#include "../../lib/include/parallax/parallax.h"
#include "../../lib/include/parallax/structures.h"
#include "../portals_server/portals_server_handle.h"
#include "../portals_server/portals_worker.h"
#include <arpa/inet.h>
#include <errno.h>
#include <log.h>
#include <rdma/rdma_cma.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MATCH_ENTRY_NUM 5

struct server_options {
	uint32_t threadno;
	const char *parallax_vol_name;
	uint32_t l0_size;
	uint32_t growth_factor;
	uint8_t format;
	long port;
	struct sockaddr_storage inaddr;
};

struct server_handle {
	struct server_options *opts;

	pthread_mutex_t *mutex;
	struct portals_worker **portals_workers;

	struct rdma_event_channel *ec;
	struct rdma_cm_id *listen_id;
	struct ibv_wc *wc;
	struct ibv_comp_channel *comp_channel;
	struct ibv_cq *cq;

	par_handle par_handle;
	uint32_t thread_to_queue;

	char *recv_buffer[MATCH_ENTRY_NUM];
	uint32_t recv_buffer_size;
};

struct my_conn_metadata {
	uint32_t max_value_size;
	uint32_t client_id;
};

#define USAGE_STRING                                \
	"InfiniBand Server: no options specified\n" \
	"try './infiniband_parallax_server --help' for more information\n"

#define HELP_STRING                                                                                             \
	"Usage:\n  InfiniBand Server <-bptf>\nOptions:\n"                                                       \
	" -t, --threads <thread-num>  specify number of server threads.\n"                                      \
	" -b, --bind <if-address>     specify the interface that the server will "                              \
	"bind to.\n"                                                                                            \
	" -p, --port <port>           specify the port that the server will be "                                \
	"listening\n"                                                                                           \
	" -f, --file <path>           specify the target (file of db) where "                                   \
	"parallax will run\n\n"                                                                                 \
	" -L0, --L0_size <size in MB>           sets the L0 size in MB of each region in Parallax\n\n"          \
	" -GF, --GF <growth factor>           specify the growth factor of levels in each Parallax region\n\n " \
	" -h, --help     display this help and exit\n"                                                          \
	" -pf, --par_format           (Optional) specify whether database should be formatted\n"

#define CONFIG_STRING         \
	"[ Server Config ]\n" \
	"  - file = %s\n"     \
	"  - flags = not yet supported\n"

#define DEFAULT_PORT 7741
#define DEFAULT_ADDRESS "192.168.5.120"

#define DECIMAL_BASE 10
#define PORT_MAX 65536
#define MAX_REGIONS 128
#define PRSV_COM_BUF_SIZE (32U * KV_MAX_SIZE)
#define METADATA_SIZE 4096
#define PRSV_WORKER_BUF_SIZE (63U * 4096) // x*a +4096 = y where y is power of 2 and multiple of sizeof(void*) == 8
#define QUEUE_DEPTH 128

#define OPCODE_MAX 7
#define MAX_CLIENTS 16

long ib_server_parse_number(const char *str, const char *opt);

void ib_server_check_arg(int argc, int option_id);

void ib_server_set_address(struct server_options *opts, const char *arg);

void ib_server_set_port(struct server_options *opts, const char *arg);

struct server_options *ib_server_parse_argv_opts(int argc, char **argv);

struct server_handle *ib_server_handle_init(struct server_options *opts);

int ib_server_print_config(struct server_handle *server_handle);

int ib_handle_cm_event(struct server_handle *server_handle, struct rdma_cm_event *event);

int ib_loop(struct server_handle *server_handle);

void *ib_put_and_reply(void *arg);

void worker_scheduler(struct server_handle *server_handle);

size_t par_net_header_size(void);

int ib_handle_event(struct ibv_wc *wc);

void *connection_manager_thread(void *arg);

int ib_server_start(struct server_handle *server_handle);

#endif

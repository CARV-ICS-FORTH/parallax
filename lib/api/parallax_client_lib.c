// Copyright [2021] [FORTH-ICS]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include "../../net_interface/par_net/portals.h"
#include "../btree/conf.h"
#include "../btree/set_options.h"
#include "../include/parallax/parallax.h"
#include "../include/parallax/structures.h"
#include "../net_interface/par_net/par_net.h"
#include "../net_interface/par_net/par_net_open.h"
#include "../net_interface/par_net/par_net_put.h"
#include "../net_interface/par_net/par_net_scan.h"
#include "../net_interface/par_net/par_net_sync.h"
#ifdef USE_PAR_NET_METRICS
#include "../net_interface/par_net/par_net_metrics.h"
#endif
#include "../scanner/scanner.h"
#include <pthread.h>
#include <stdio.h>
#include <sys/time.h>
#include <x86intrin.h>

//#define PORTALS
#ifdef PORTALS
#include "portals4.h"
#include "portals4_ext.h"
char msg[PTL_EV_STR_SIZE];
#elif USE_INFINIBAND
#include <netdb.h>
#include <rdma/rdma_cma.h>
#define KV_SIZE_THRESHOLD 256
#define TIMEOUT_MS 500
#define SECTOR_SIZE 512
#define MAX_SERVERS 50
struct my_conn_metadata {
	uint32_t max_buffer_size;
	uint32_t client_id;
};
uint32_t client_id = 0;
uint32_t counter = 0;
#else
#define MAX_SERVERS 0
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#endif

#include <assert.h>
#include <inttypes.h>
#include <log.h>
#include <spin_loop.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

//#define ENABLE_METRICS

size_t par_net_header_calc_size(void)
{
	return sizeof(struct par_net_header);
}

void print_buffer_hex(const char *buffer, size_t length, char *type)
{
	if (buffer == NULL) {
		printf("%s buffer is null:\n", type);
		return;
	}
	printf("%s buffer content (hex):\n", type);
	for (size_t i = 0; i < length; i++) {
		if (buffer + i == NULL) {
			printf("%s buffer is null in index = %lu", type, i);
		} else {
			printf("%02x ", (unsigned char)buffer[i]);
		}
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("(END)\n");
}

void print_par_net_header(const struct par_net_header *h)
{
	printf("--- par_net_header ---\n");
	printf("Total Bytes: %" PRIu32 "\n", h->total_bytes);
	printf("Opcode:      %" PRIu32 "\n", h->opcode);
#ifdef USE_INFINIBAND
	printf("VAddr:       0x%016" PRIx64 "\n", h->payload_buf_vaddr);
	printf("Size:        %" PRIu64 "\n", h->payload_size);
	printf("Request ID:  %" PRIu32 "\n", h->request_id);
	printf("RKey:        0x%" PRIx32 "\n", h->payload_rkey);
	printf("Inline Flag: %u\n", h->inline_flag);
#endif
	printf("----------------------\n");
}

#ifndef PORTALS
static bool par_split_hostname_port(const char *input, char **hostname, int *port)
{
	char *colon_pos = strchr(input, ':');
	if (colon_pos == NULL) {
		// No colon found in the input string
		return -1;
	}

	// Calculate the length of the hostname
	size_t hostname_len = colon_pos - input;

	// Allocate memory for the hostname and copy it
	*hostname = (char *)calloc(1UL, hostname_len + 1);
	if (*hostname == NULL) {
		return -1;
	}
	strncpy(*hostname, input, hostname_len);

	// Convert the port part to an integer using strtol
	char *endptr = NULL;
	long port_long = strtol(colon_pos + 1, &endptr, 10);

	// Check if the conversion was successful and the entire string was valid
	if (*endptr != '\0' || port_long < 0 || port_long > 65535) {
		free(*hostname);
		return false; // Invalid port number
	}

	*port = (int)port_long;

	return true;
}
#endif

#ifdef PORTALS
struct par_handle {
	ptl_handle_ni_t nih;
	ptl_handle_eq_t eqh;
	ptl_pt_index_t ptindex;
	ptl_le_t le;
	ptl_handle_le_t leh;
	ptl_event_t event;
	ptl_md_t md;
	ptl_handle_md_t mdh;
	ptl_process_t id_server;

	pthread_mutex_t lock;
	uint64_t region_id;
	uint64_t start, end, total_cycles, total_time;
	int putfl, getfl;
	char *recv_buffer;
	char *send_buffer;

	uint32_t recv_buffer_size;
	uint32_t send_buffer_size;

	struct par_options_desc *configuration;
};

static par_handle par_net_init(const char *parallax_host)
{
	(void)parallax_host;
	struct par_handle *handle = calloc(1UL, sizeof(struct par_handle));
	handle->id_server.phys.pid = SERVER_PID;
	const char *srv_nid = getenv("SERVER_NID");
	if (srv_nid) {
		handle->id_server.phys.nid = (unsigned int)atoi(srv_nid);
	} else {
		log_warn("SERVER_NID not set. Using default nid PTL_IFACE_DEFAULT=0!");
		handle->id_server.phys.nid = PTL_IFACE_DEFAULT;
	}

	int ret = PtlInit();
	if (ret != PTL_OK) {
		log_debug("PtlInit failed");
		_exit(EXIT_FAILURE);
	}

	const char *clie_nid = getenv("CLIENT_NID");
	if (clie_nid) {
		ret = PtlNIInit((int)atoi(clie_nid), PTL_NI_MATCHING | PTL_NI_PHYSICAL, PTL_PID_ANY, NULL, NULL,
				&handle->nih);
	} else {
		log_warn("CLIENT_NID not set. Using default nid PTL_IFACE_DEFAULT=0!");
		ret = PtlNIInit(PTL_IFACE_DEFAULT, PTL_NI_MATCHING | PTL_NI_PHYSICAL, PTL_PID_ANY, NULL, NULL,
				&handle->nih);
	}
	if (ret != PTL_OK) {
		log_debug("PtlNIInit failed : %s", PtlToStr(ret, PTL_STR_ERROR));
		_exit(EXIT_FAILURE);
	}

	ret = PtlEQAlloc(handle->nih, 10, &handle->eqh);
	if (ret != PTL_OK) {
		log_debug("PtlEQAlloc failed");
		_exit(EXIT_FAILURE);
	}

	ret = PtlPTAlloc(handle->nih, 0, handle->eqh, PTL_PT_ANY, &handle->ptindex);
	if (ret != PTL_OK) {
		log_debug("PtlPTAlloc failed");
		_exit(EXIT_FAILURE);
	}

	ret = posix_memalign((void **)&handle->recv_buffer, 4096, PRSV_COM_BUF_SIZE);
	if (ret != 0) {
		log_debug("posix_memalign failed");
		_exit(EXIT_FAILURE);
	}
	ret = posix_memalign((void **)&handle->send_buffer, 4096, PRSV_COM_BUF_SIZE);
	if (ret != 0) {
		log_debug("posix_memalign failed");
		_exit(EXIT_FAILURE);
	}
	handle->recv_buffer_size = PRSV_COM_BUF_SIZE;
	handle->send_buffer_size = PRSV_COM_BUF_SIZE;

	//ok...init send buffer memmory
	handle->md.start = handle->send_buffer;
	handle->md.length = handle->send_buffer_size;
	handle->md.options = 0;
	handle->md.eq_handle = handle->eqh;
	handle->md.ct_handle = PTL_CT_NONE;

	ret = PtlMDBind(handle->nih, &handle->md, &handle->mdh);
	if (ret != PTL_OK) {
		log_debug("PtlMDBind failed");
		_exit(EXIT_FAILURE);
	}
	//send it
	log_debug("server nid: %d pid : %d", handle->id_server.phys.nid, handle->id_server.phys.pid);
	/*

  ptl_match_bits_t match = 1;
  ptl_match_bits_t ign   = 0xffffffff;

  server_handle->me.ignore_bits = ign;
  server_handle->me.match_bits = match;
  server_handle->me.match_id.phys.nid = PTL_NID_ANY;
  server_handle->me.match_id.phys.pid = PTL_PID_ANY;
  server_handle->me.min_free = 4096;
  server_handle->me.start = server_handle->recv_buffer;
  server_handle->me.length = server_handle->recv_buffer_size;
  server_handle->me.ct_handle = PTL_CT_NONE;
  server_handle->me.uid = PTL_UID_ANY;
  server_handle->me.options = CLIE_ME_OPTS;

  // Append each ME
  int ret = PtlMEAppend(server_handle->nih, server_handle->ptindex, &server_handle->me,
                        PTL_PRIORITY_LIST, NULL, &server_handle->meh);
  if (ret != PTL_OK) {
      log_debug("Error appending ME at index %d", i);
      _exit(EXIT_FAILURE);
    }
    */

	//init receive buffer memmory
	handle->le.start = handle->recv_buffer;
	handle->le.length = handle->recv_buffer_size;
	handle->le.ct_handle = PTL_CT_NONE;
	handle->le.uid = PTL_UID_ANY;
	handle->le.options = PTL_LE_OP_PUT;

	ret = PtlLEAppend(handle->nih, handle->ptindex, &handle->le, PTL_PRIORITY_LIST, NULL, &handle->leh);
	if (ret != PTL_OK) {
		log_debug("PtlLEAppend failed");
		_exit(EXIT_FAILURE);
	}

	ptl_event_t event;

	ret = PtlEQWait(handle->eqh, &event);
	if (ret != PTL_OK) {
		log_debug("PtlEQWait failed");
		_exit(EXIT_FAILURE);
	} else {
		PtlEvToStr(0, &event, msg);
		log_debug("Event client interface 1 : %s", msg);
	}

	return (par_handle)handle;
}
#elif USE_INFINIBAND

#define N_SEND_BUFFERS 4
#define N_RECV_BUFFERS 128

struct par_handle {
	char *db_name;
	struct rdma_event_channel *ec;
	struct rdma_cm_id *cm_ids[MAX_SERVERS];
	int num_servers;
	struct ibv_pd *pd;
	struct ibv_comp_channel *comp_channel;
	struct ibv_cq *cq;
	char *recv_buffer[MAX_SERVERS][N_RECV_BUFFERS];
	char *send_buffer[MAX_SERVERS][N_SEND_BUFFERS];
	struct ibv_mr *recv_mr[MAX_SERVERS][N_RECV_BUFFERS];
	struct ibv_mr *send_mr[MAX_SERVERS][N_SEND_BUFFERS];
	uint32_t recv_buffer_size;
	uint32_t send_buffer_size;
	uint64_t region_id;
	struct par_options_desc *configuration;
	int send_idx[MAX_SERVERS];
	uint32_t max_buffer_size;
};

struct address_info {
	char ip[INET_ADDRSTRLEN];
	char port[6];
};

int parse_addresses(char *parallax_host, struct address_info addresses[])
{
	int count = 0;
	char *token = strtok(parallax_host, " ,");

	while (token != NULL && count < MAX_SERVERS) {
		char *colon = strchr(token, ':');
		if (colon != NULL) {
			*colon = '\0';
			strncpy(addresses[count].ip, token, INET_ADDRSTRLEN - 1);
			addresses[count].ip[INET_ADDRSTRLEN - 1] = '\0';

			strncpy(addresses[count].port, colon + 1, 5);
			addresses[count].port[5] = '\0';

			count++;
		}
		token = strtok(NULL, " ,");
	}
	return count;
}

static struct ibv_pd *global_pd = NULL;
static struct ibv_cq *global_cq = NULL;
static struct ibv_comp_channel *global_comp_chan = NULL;
static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
static int active_par_ib_handles = 0;
static struct par_handle *global_net_handle = NULL;
static pthread_mutex_t global_net_lock = PTHREAD_MUTEX_INITIALIZER;
static int global_net_refcount = 0;

struct par_handle *par_net_init(const char *parallax_host)
{
	struct address_info addresses[MAX_SERVERS];
	char *hosts_copy = strdup(parallax_host);
	int server_count = parse_addresses(hosts_copy, addresses);
	free(hosts_copy);

	struct par_handle *handle = calloc(1, sizeof(*handle));

	handle->ec = rdma_create_event_channel();
	handle->num_servers = server_count;
	for (int i = 0; i < server_count; i++) {
		struct addrinfo *addr;
		if (getaddrinfo(addresses[i].ip, addresses[i].port, NULL, &addr)) {
			perror("getaddrinfo");
			_exit(EXIT_FAILURE);
		}

		if (rdma_create_id(handle->ec, &handle->cm_ids[i], NULL, RDMA_PS_TCP)) {
			perror("rdma_create_id");
			_exit(EXIT_FAILURE);
		}

		if (rdma_resolve_addr(handle->cm_ids[i], NULL, addr->ai_addr, TIMEOUT_MS)) {
			perror("rdma_resolve_addr");
			_exit(EXIT_FAILURE);
		}
		freeaddrinfo(addr);

		struct rdma_cm_event *event;
		rdma_get_cm_event(handle->ec, &event);
		rdma_ack_cm_event(event);

		if (rdma_resolve_route(handle->cm_ids[i], TIMEOUT_MS)) {
			perror("rdma_resolve_route");
			_exit(EXIT_FAILURE);
		}
		rdma_get_cm_event(handle->ec, &event);
		rdma_ack_cm_event(event);

		pthread_mutex_lock(&init_lock);
		if (global_pd == NULL) {
			global_pd = ibv_alloc_pd(handle->cm_ids[i]->verbs);
			global_comp_chan = ibv_create_comp_channel(handle->cm_ids[i]->verbs);
			global_cq = ibv_create_cq(handle->cm_ids[i]->verbs, 256, NULL, global_comp_chan, 0);
			ibv_req_notify_cq(global_cq, 0);
		}
		active_par_ib_handles++;
		pthread_mutex_unlock(&init_lock);

		handle->pd = global_pd;
		handle->cq = global_cq;
		handle->comp_channel = global_comp_chan;

		struct ibv_qp_init_attr qp_attr;
		memset(&qp_attr, 0, sizeof(qp_attr));
		qp_attr.send_cq = handle->cq;
		qp_attr.recv_cq = handle->cq;
		qp_attr.qp_type = IBV_QPT_RC;
		qp_attr.cap.max_send_wr = 128;
		qp_attr.cap.max_recv_wr = 128;
		qp_attr.cap.max_send_sge = 1;
		qp_attr.cap.max_recv_sge = 1;

		if (rdma_create_qp(handle->cm_ids[i], handle->pd, &qp_attr)) {
			perror("rdma_create_qp");
			_exit(EXIT_FAILURE);
		}

		handle->recv_buffer_size = KV_MAX_SIZE + par_net_header_calc_size();
		int ret;
		for (int j = 0; j < N_RECV_BUFFERS; j++) {
			ret = posix_memalign((void **)&handle->recv_buffer[i][j], SECTOR_SIZE,
					     handle->recv_buffer_size);
			if (ret != 0) {
				perror("posix_memalign recv_buffer");
				_exit(EXIT_FAILURE);
			}
			handle->recv_mr[i][j] = ibv_reg_mr(handle->pd, handle->recv_buffer[i][j],
							   handle->recv_buffer_size,
							   IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
			if (!handle->recv_mr[i][j]) {
				perror("ibv_reg_mr recv_buffer");
				_exit(EXIT_FAILURE);
			}
			struct ibv_sge recv_sge = {
				.addr = (uintptr_t)handle->recv_buffer[i][j],
				.length = handle->recv_buffer_size,
				.lkey = handle->recv_mr[i][j]->lkey,
			};
			struct ibv_recv_wr recv_wr = {
				.wr_id = j,
				.sg_list = &recv_sge,
				.num_sge = 1,
			};
			struct ibv_recv_wr *recv_bad_wr;
			if (ibv_post_recv(handle->cm_ids[i]->qp, &recv_wr, &recv_bad_wr)) {
				perror("ibv_post_recv");
				_exit(EXIT_FAILURE);
			}
		}

		handle->send_buffer_size = KV_MAX_SIZE;
		for (int j = 0; j < N_SEND_BUFFERS; j++) {
			ret = posix_memalign((void **)&handle->send_buffer[i][j], SECTOR_SIZE,
					     handle->send_buffer_size);
			if (ret != 0) {
				perror("posix_memalign send_buffer");
				_exit(EXIT_FAILURE);
			}
			handle->send_mr[i][j] =
				ibv_reg_mr(handle->pd, handle->send_buffer[i][j], handle->send_buffer_size,
					   IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
			if (!handle->send_mr[i][j]) {
				perror("ibv_reg_mr send_buffer");
				_exit(EXIT_FAILURE);
			}
		}
		handle->send_idx[i] = 0;

		struct rdma_conn_param conn_param = { 0 };
		conn_param.initiator_depth = 1;
		conn_param.responder_resources = 1;
		conn_param.retry_count = 7;
		if (rdma_connect(handle->cm_ids[i], &conn_param)) {
			perror("rdma_connect");
			_exit(EXIT_FAILURE);
		}
		rdma_get_cm_event(handle->ec, &event);
		if (i == 0) {
			struct my_conn_metadata *meta = (struct my_conn_metadata *)event->param.conn.private_data;
			client_id = meta->client_id;
			handle->max_buffer_size = meta->max_buffer_size;
		}
		rdma_ack_cm_event(event);
	}
	return handle;
}
#else
struct par_handle {
	char *recv_buffer;
	char *send_buffer;
	pthread_mutex_t lock;
	uint64_t region_id;
	int sockfd;
	uint32_t recv_buffer_size;
	uint32_t send_buffer_size;
	struct par_options_desc *configuration;
};

/**
 * @brief Initializes connections to the Parallax server.
 * @param hostname pointer to the hostname of the server
 * in the form <hostname>:<port>
 * @return a new par_handle
 */
static par_handle par_net_init(const char *parallax_host)
{
	struct par_handle *handle = calloc(1UL, sizeof(struct par_handle));
	char *hostname = NULL;
	int port = 0;

	if (false == par_split_hostname_port(parallax_host, &hostname, &port)) {
		log_fatal("Failed to parse parallax server hostname: %s must be in <hostname>:<port> notation",
			  parallax_host);
		_exit(EXIT_FAILURE);
	}
	log_debug("Connecting to Parallax server: %s:%d", hostname, port);

	struct sockaddr_in server_addr = { 0 };
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	//Resolve IP from hostname
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

	struct addrinfo hints = { 0 };
	struct addrinfo *res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; // AF_INET for IPv4

	if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
		log_fatal("Failed to resove host: %s to an IP!", hostname);
		perror("getaddrinfo failed");
		_exit(EXIT_FAILURE);
	}

	server_addr.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;

	freeaddrinfo(res);

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("TCP_CLIENT_SOCKET");
		log_error("Could not create socket");
		_exit(EXIT_FAILURE);
	}

	if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("TCP_CLIENT_CONNECT");
		log_error("Could not connect to server: %s", parallax_host);
		_exit(EXIT_FAILURE);
	}

	handle->sockfd = sockfd;
	handle->recv_buffer = calloc(1UL, KV_MAX_SIZE);
	handle->send_buffer = calloc(1UL, KV_MAX_SIZE);
	handle->recv_buffer_size = KV_MAX_SIZE;
	handle->send_buffer_size = KV_MAX_SIZE;
	free(hostname);
	return (par_handle)handle;
}
#endif

void par_net_handle_destroy(par_handle handle)
{
	if (NULL == handle) {
		log_debug("NULL handle to destroy?");
		return;
	}
	log_debug("Destroying handle");

	struct par_handle *parallax_handle = (struct par_handle *)handle;
#ifdef PORTALS
	PtlMDRelease(parallax_handle->mdh);
	PtlEQFree(parallax_handle->eqh);
	PtlPTFree(parallax_handle->nih, parallax_handle->ptindex);
	PtlNIFini(parallax_handle->nih);
	PtlFini();
#elif USE_TCP
	if (close(parallax_handle->sockfd) < 0) {
		log_fatal("Failed to close the socket");
		_exit(EXIT_FAILURE);
	}
#endif
#ifdef USE_INFINIBAND
	if (parallax_handle->db_name) {
		free(parallax_handle->db_name);
	}

	pthread_mutex_lock(&global_net_lock);
	global_net_refcount--;

	if (global_net_refcount == 0 && global_net_handle != NULL) {
		for (int i = 0; i < global_net_handle->num_servers; i++) {
			for (int j = 0; j < N_RECV_BUFFERS; j++) {
				if (global_net_handle->recv_mr[i][j])
					ibv_dereg_mr(global_net_handle->recv_mr[i][j]);
				if (global_net_handle->recv_buffer[i][j])
					free(global_net_handle->recv_buffer[i][j]);
			}
			for (int j = 0; j < N_SEND_BUFFERS; j++) {
				if (global_net_handle->send_mr[i][j])
					ibv_dereg_mr(global_net_handle->send_mr[i][j]);
				if (global_net_handle->send_buffer[i][j])
					free(global_net_handle->send_buffer[i][j]);
			}
			rdma_disconnect(global_net_handle->cm_ids[i]);
			rdma_destroy_qp(global_net_handle->cm_ids[i]);
			rdma_destroy_id(global_net_handle->cm_ids[i]);
		}

		rdma_destroy_event_channel(global_net_handle->ec);

		pthread_mutex_lock(&init_lock);
		active_par_ib_handles -= global_net_handle->num_servers;

		if (active_par_ib_handles <= 0 && global_pd != NULL) {
			ibv_destroy_cq(global_cq);
			ibv_destroy_comp_channel(global_comp_chan);
			ibv_dealloc_pd(global_pd);

			global_cq = NULL;
			global_comp_chan = NULL;
			global_pd = NULL;
			active_par_ib_handles = 0;
		}
		pthread_mutex_unlock(&init_lock);

		free(global_net_handle);
		global_net_handle = NULL;
	}
	pthread_mutex_unlock(&global_net_lock);
#elif USE_TCP
	free(parallax_handle->send_buffer);
	free(parallax_handle->recv_buffer);
#endif
	if (parallax_handle->configuration[PARALLAX_SERVER].value)
		free((void *)parallax_handle->configuration[PARALLAX_SERVER].value);
	free(parallax_handle->configuration);
	free(parallax_handle);
}

#ifdef PORTALS
static ssize_t par_portals_RPC(par_handle handle, char *send_buffer, size_t send_buffer_len, char **recv_buffer)
{
	ptl_event_t event;
	int ret;

	struct par_handle *parallax_handle = (struct par_handle *)handle;
	parallax_handle->send_buffer = send_buffer;

	ret = PtlPut(parallax_handle->mdh, 0, send_buffer_len, PTL_ACK_REQ, parallax_handle->id_server, 0, 0, 0, NULL,
		     0);

	if (ret != PTL_OK) {
		log_debug("PtlPut failed : %s", PtlToStr(ret, PTL_STR_ERROR));
		_exit(EXIT_FAILURE);
	}

	/*send message event*/
	ret = PtlEQWait(parallax_handle->eqh, &event);
	if (ret != PTL_OK) {
		log_debug("PtlEQWait failed");
		_exit(EXIT_FAILURE);
	} else {
		PtlEvToStr(0, &event, msg);
		log_debug("Event client interface 1 : %s", msg);
		//print_buffer_hex(parallax_handle->send_buffer, send_buffer_len, "Send");
	}

	/*wait for ack*/
	ret = PtlEQWait(parallax_handle->eqh, &event);
	if (ret != PTL_OK) {
		log_debug("PtlEQWait failed");
		_exit(EXIT_FAILURE);
	} else {
		PtlEvToStr(0, &event, msg);
		log_debug("Event client interface 1 : %s", msg);
	}

	/*wait for reply*/
	ret = PtlEQWait(parallax_handle->eqh, &event);
	if (ret != PTL_OK) {
		log_debug("PtlEQPoll failed");
		_exit(EXIT_FAILURE);
	} else {
		PtlEvToStr(0, &event, msg);
		log_debug("Event client interface 1 : %s", msg);
	}

	if (event.type == PTL_EVENT_PUT) {
		log_debug("client received reply from server:");
	}
	//print_buffer_hex((char *)event.start, event.mlength, "Reveive");
	//struct par_net_header *reply_header = (struct par_net_header *)*recv_buffer;

	*recv_buffer = event.start;
	ssize_t mbytes = event.mlength;
	ssize_t rbytes = event.rlength;
	//log_debug("mbytes received : %d, rbytes : %d, header total bytes : %d", mbytes,rbytes,reply_header->total_bytes);
	if (mbytes < rbytes) {
		log_debug("Warning: Received message was truncated. mlength: %ld, rlength: %ld\n", mbytes, rbytes);
		// Handle truncation, if necessary, e.g., retrieve remaining data or log an error
	}
	//maybe this is wrong need to calculate through struct par_net_header *reply_header = (struct par_net_header *)*recv_buffer;
	return mbytes;
}
#elif USE_INFINIBAND

static ssize_t par_ib_RPC(par_handle handle, char *send_buffer, size_t send_buffer_len, char **recv_buffer, int hash)
{
	struct par_handle *h = (struct par_handle *)handle;
	struct par_net_header *header = (struct par_net_header *)send_buffer;

	int s_idx = h->send_idx[hash];
	char *buf = h->send_buffer[hash][s_idx];
	struct ibv_mr *send_mr = h->send_mr[hash][s_idx];

	struct ibv_wc wc;
	struct par_net_header *hdr = NULL;
	int idx = -1;

	h->send_idx[hash] = (s_idx + 1) % N_SEND_BUFFERS;
	buf = send_buffer;

retry:
	header->request_id = client_id;

	if (send_buffer_len > KV_SIZE_THRESHOLD) {
		size_t header_size = par_net_header_calc_size();

		header->inline_flag = 0;
		header->payload_buf_vaddr = (uintptr_t)(buf);
		header->payload_rkey = send_mr->rkey;
		header->payload_size = send_buffer_len;

		struct ibv_sge sge = {
			.addr = (uintptr_t)buf,
			.length = header_size,
			.lkey = send_mr->lkey,
		};
		struct ibv_send_wr wr = {
			.wr_id = (uintptr_t)buf,
			.opcode = IBV_WR_SEND,
			.send_flags = IBV_SEND_SIGNALED,
			.sg_list = &sge,
			.num_sge = 1,
		};
		struct ibv_send_wr *bad_wr = NULL;
		int ret = ibv_post_send(h->cm_ids[hash]->qp, &wr, &bad_wr);
		if (ret) {
			log_fatal("ibv_post_send failed: %s\n", strerror(ret));
			return -1;
		}
	} else {
		struct ibv_sge sge = {
			.addr = (uintptr_t)send_buffer,
			.length = send_buffer_len,
			.lkey = send_mr->lkey,
		};
		struct ibv_send_wr wr = {
			.wr_id = (uintptr_t)send_buffer,
			.opcode = IBV_WR_SEND,
			.send_flags = IBV_SEND_SIGNALED,
			.sg_list = &sge,
			.num_sge = 1,
		};
		struct ibv_send_wr *bad_wr = NULL;
		int ret = ibv_post_send(h->cm_ids[hash]->qp, &wr, &bad_wr);
		if (ret) {
			log_fatal("ibv_post_send failed: %s\n", strerror(ret));
			return -1;
		}
	}

	while (1) {
#ifdef USE_IBV_CQ_EVENT
		void *cq_context;
		ibv_get_cq_event(h->comp_channel, &h->cq, &cq_context);
		ibv_ack_cq_events(h->cq, 1);
		ibv_req_notify_cq(h->cq, 0);
#endif
		int ne = ibv_poll_cq(h->cq, 1, &wc);
		if (ne == 0) {
			continue;
		}
		if (ne > 0 && wc.opcode == IBV_WC_SEND) {
			continue;
		}
		if (ne > 0 && wc.opcode == IBV_WC_RECV) {
			break;
		}
		log_fatal("ne: %d op:%d %s", ne, wc.opcode, ibv_wc_status_str(wc.status));
		_exit(EXIT_FAILURE);
	}
	if (wc.status != IBV_WC_SUCCESS) {
		log_fatal("Completion with error: %s\n", ibv_wc_status_str(wc.status));
		return -1;
	}

	idx = wc.wr_id;
	hdr = (struct par_net_header *)h->recv_buffer[hash][idx];

	char *recv_buf = h->recv_buffer[hash][idx];
	size_t recv_buf_size = KV_MAX_SIZE + par_net_header_calc_size();
	struct ibv_mr *recv_mr = h->recv_mr[hash][idx];

	if (hdr->request_id != header->request_id) {
		log_fatal("Received response with mismatched request_id: expected %u, got %u", header->request_id,
			  hdr->request_id);
		return -1;
	}
	if (hdr->opcode == OPCODE_GET) {
		struct par_net_get_rep *rep = (struct par_net_get_rep *)(recv_buf + par_net_header_calc_size());
		if (par_net_get_rep_error_code(rep) == 1) {
			recv_buf_size *= 2;
			if (recv_buf_size > KV_MAX_SIZE) {
				log_error("Exceeded KV_MAX_SIZE");
				return -1;
			}
			goto retry;
		}
	}

	*recv_buffer = recv_buf;

	struct ibv_sge recv_sge = {
		.addr = (uintptr_t)recv_buf,
		.length = recv_buf_size,
		.lkey = recv_mr->lkey,
	};
	struct ibv_recv_wr recv_wr = {
		.wr_id = idx,
		.sg_list = &recv_sge,
		.num_sge = 1,
	};
	struct ibv_recv_wr *recv_bad_wr;
	if (ibv_post_recv(h->cm_ids[hash]->qp, &recv_wr, &recv_bad_wr)) {
		perror("ibv_post_recv");
		return -1;
	}

	return wc.byte_len;
}
#else
static ssize_t par_net_RPC(int sockfd, char *send_buffer, size_t send_buffer_len, char **recv_buffer,
			   size_t recv_buffer_len)
{
	struct msghdr msg = { 0 };
	struct iovec iov[1];

	iov[0].iov_base = send_buffer;
	iov[0].iov_len = send_buffer_len;

	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	ssize_t bytes_sent = sendmsg(sockfd, &msg, 0);
	if (bytes_sent < 0) {
		perror("TCP_CLIENT_SENDMSG");
		log_fatal("Sendmsg failed");
		close(sockfd);
		_exit(EXIT_FAILURE);
	}

	// log_debug("Message bytes sent == %lu", bytes_sent);

	/* REPLY FROM SERVER */
	struct iovec iov_reply[1];
	struct msghdr msg_reply = { 0 };

	iov_reply[0].iov_base = *recv_buffer;
	iov_reply[0].iov_len = recv_buffer_len;

	memset(&msg_reply, 0, sizeof(msg_reply));
	msg_reply.msg_iov = iov_reply;
	msg_reply.msg_iovlen = 1;

	ssize_t bytes_received = 0;
	bytes_received = recvmsg(sockfd, &msg_reply, 0);
	if (bytes_received < 0) {
		perror("recvmsg");
		_exit(EXIT_FAILURE);
	}
	struct par_net_header *reply_header = (struct par_net_header *)*recv_buffer;
	if (bytes_received != reply_header->total_bytes) {
		log_debug(
			"Part of message received buffer was not enough to fit all shit bytes_received: %ld message is: %u going to expand it",
			bytes_received, reply_header->total_bytes);
		*recv_buffer = realloc(*recv_buffer, reply_header->total_bytes);
		iov_reply[0].iov_base = &(*recv_buffer)[bytes_received];
		iov_reply[0].iov_len = recv_buffer_len - bytes_received;

		memset(&msg_reply, 0, sizeof(msg_reply));
		msg_reply.msg_iov = iov_reply;
		msg_reply.msg_iovlen = 1;

		ssize_t extra_bytes_received = recvmsg(sockfd, &msg_reply, 0);
		assert(extra_bytes_received + bytes_received == reply_header->total_bytes);

		(void)extra_bytes_received;
	}

	// log_debug("Total Reply size == %ld", bytes_received);

	return bytes_received;
}
#endif

unsigned long djb2_hash(const char *str)
{
	unsigned long hash = 5381;
	int c;
	while ((c = *str++))
		hash = ((hash << 5) + hash) + c;
	return hash;
}

char *par_format(char *device_name, uint32_t max_regions_num)
{
	(void)device_name;
	(void)max_regions_num;

	log_warn("par format not supported for the TCP-Portals client");
	return NULL;
}

par_handle par_open(par_db_options *db_options, const char **error_message)
{
	log_info("OPEN DB with name: %s", db_options->db_name);
	struct par_options_desc *configuration = par_get_default_options();
#ifdef USE_INFINIBAND
	pthread_mutex_lock(&global_net_lock);
	if (global_net_handle == NULL) {
		global_net_handle =
			(struct par_handle *)par_net_init((const char *)configuration[PARALLAX_SERVER].value);
		global_net_refcount = 0;
	}
	global_net_refcount++;
	pthread_mutex_unlock(&global_net_lock);

	struct par_handle *parallax_handle = malloc(sizeof(struct par_handle));
	if (parallax_handle == NULL) {
		*error_message = "Failed to allocate memory for db handle";
		return NULL;
	}
	memcpy(parallax_handle, global_net_handle, sizeof(struct par_handle));
#else
	struct par_handle *parallax_handle =
		(struct par_handle *)par_net_init((const char *)configuration[PARALLAX_SERVER].value);
	parallax_handle->configuration = configuration;
#endif
#ifdef PORTALS
	parallax_handle->total_cycles = 0;
#endif
	size_t msg_len = par_net_open_req_calc_size(par_net_get_size(db_options->db_name)) + par_net_header_calc_size();
	if (msg_len > parallax_handle->send_buffer_size) {
		log_fatal("Send buffer too small has: %u B needs %lu B", parallax_handle->send_buffer_size, msg_len);
		_exit(EXIT_FAILURE);
	}

#ifdef USE_INFINIBAND
	parallax_handle->db_name = strdup(db_options->db_name);
	int hash = djb2_hash(parallax_handle->db_name) % parallax_handle->num_servers;
	struct par_net_header *request_header =
		(struct par_net_header *)(parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]]);
#elif USE_TCP
	struct par_net_header *request_header = (struct par_net_header *)(parallax_handle->send_buffer);
#endif

	request_header->total_bytes = msg_len;
	request_header->opcode = OPCODE_OPEN;
#ifdef USE_INFINIBAND
	request_header->payload_buf_vaddr = 0;
	request_header->payload_rkey = 0;
	request_header->inline_flag = 1;
	request_header->payload_size = 0;
#endif

	size_t buffer_len = parallax_handle->send_buffer_size - par_net_header_calc_size();
#ifdef USE_INFINIBAND
	struct par_net_open_req *request = par_net_open_req_create(
		db_options->create_flag, db_options->db_name,
		&parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]][par_net_header_calc_size()],
		&buffer_len);
#elif USE_TCP
	struct par_net_open_req *request =
		par_net_open_req_create(db_options->create_flag, db_options->db_name,
					&parallax_handle->send_buffer[par_net_header_calc_size()], &buffer_len);
#endif
	if (NULL == request) {
		log_fatal("Failed to create open request");
		_exit(EXIT_FAILURE);
	}

#ifdef PORTALS
	ssize_t bytes_received =
		par_portals_RPC(parallax_handle, parallax_handle->send_buffer, msg_len, &parallax_handle->recv_buffer);
#elif USE_INFINIBAND
	char *reply_buf = NULL;
	ssize_t bytes_received = par_ib_RPC(parallax_handle,
					    parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]],
					    msg_len, &reply_buf, hash);
#else
	ssize_t bytes_received = par_net_RPC(parallax_handle->sockfd, parallax_handle->send_buffer, msg_len,
					     &parallax_handle->recv_buffer, parallax_handle->recv_buffer_size);
#endif
	if (0 == bytes_received) {
		*error_message = "Communication with server failed";
		return NULL;
	}
#ifdef USE_INFINIBAND
	struct par_net_header *reply_header = (struct par_net_header *)reply_buf;
	assert(reply_header->opcode == OPCODE_OPEN);
	par_handle ret_handle = par_net_open_rep_handle_reply(&reply_buf[par_net_header_calc_size()]);
#elif USE_TCP
	struct par_net_header *reply_header = (struct par_net_header *)parallax_handle->recv_buffer;
	assert(reply_header->opcode == OPCODE_OPEN);
	par_handle ret_handle =
		par_net_open_rep_handle_reply(&parallax_handle->recv_buffer[par_net_header_calc_size()]);
	(void)reply_header;
#endif

	if (0 == ret_handle) {
		*error_message = "Operation (open) failed";
		par_net_handle_destroy(parallax_handle);
		free(parallax_handle);
		return NULL;
	}

	parallax_handle->region_id = (uint64_t)ret_handle;
	parallax_handle->configuration = configuration;

	log_info("OPEN DB with name: %s ... DONE", db_options->db_name);
	return (par_handle)parallax_handle;
}

const char *par_close(par_handle handle)
{
	log_info("CLOSE operation ...");
	struct par_handle *parallax_handle = (struct par_handle *)handle;
	size_t msg_len = par_net_close_req_calc_size() + par_net_header_calc_size();
	if (msg_len > parallax_handle->send_buffer_size) {
		log_fatal("Send buffer too small has: %u B needs %lu B", parallax_handle->send_buffer_size, msg_len);
		_exit(EXIT_FAILURE);
	}

#ifdef USE_INFINIBAND
	int hash = djb2_hash(parallax_handle->db_name) % parallax_handle->num_servers;
	struct par_net_header *header =
		(struct par_net_header *)(parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]]);
#elif USE_TCP
	struct par_net_header *header = (struct par_net_header *)(parallax_handle->send_buffer);
#endif
	header->total_bytes = msg_len;
	header->opcode = OPCODE_CLOSE;
#ifdef USE_INFINIBAND
	header->payload_buf_vaddr = 0;
	header->payload_rkey = 0;
	header->inline_flag = 1;
	header->payload_size = 0;
#endif

	size_t buffer_len = parallax_handle->send_buffer_size - par_net_header_calc_size();
#ifdef USE_INFINIBAND
	struct par_net_close_req *request = par_net_close_req_create(
		parallax_handle->region_id,
		&parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]][par_net_header_calc_size()],
		&buffer_len);
#elif USE_TCP
	struct par_net_close_req *request = par_net_close_req_create(
		parallax_handle->region_id, &parallax_handle->send_buffer[par_net_header_calc_size()], &buffer_len);
#endif
	if (NULL == request) {
		log_fatal("Failed to create close request");
		_exit(EXIT_FAILURE);
	}

#ifdef PORTALS
	ssize_t bytes_received =
		par_portals_RPC(parallax_handle, parallax_handle->send_buffer, msg_len, &parallax_handle->recv_buffer);
#elif USE_INFINIBAND
	char *reply_buf = NULL;
	ssize_t bytes_received = par_ib_RPC(parallax_handle,
					    parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]],
					    msg_len, &reply_buf, hash);
#else
	ssize_t bytes_received = par_net_RPC(parallax_handle->sockfd, parallax_handle->send_buffer, msg_len,
					     &parallax_handle->recv_buffer, parallax_handle->recv_buffer_size);
#endif
	if (0 == bytes_received) {
		return "Error with sending buffer";
	}
#ifdef USE_INFINIBAND
	struct par_net_header *reply_header = (struct par_net_header *)reply_buf;
	assert(reply_header->opcode == OPCODE_CLOSE);
	struct par_net_close_rep *reply = (struct par_net_close_rep *)&reply_buf[par_net_header_calc_size()];
#elif USE_TCP
	struct par_net_header *reply_header = (struct par_net_header *)parallax_handle->recv_buffer;
	assert(reply_header->opcode == OPCODE_CLOSE);
	struct par_net_close_rep *reply =
		(struct par_net_close_rep *)&parallax_handle->recv_buffer[par_net_header_calc_size()];
	(void)reply_header;
#endif
	const char *error_message = par_net_close_rep_handle_reply(reply);

	if (error_message) {
		return error_message;
	}

	log_info("CLOSE operation ACKed ... freeing memmory");
	par_net_handle_destroy(parallax_handle);
	log_info("CLOSE operation ... DONE");
	return NULL;
}

// cppcheck-suppress unusedFunction
char *par_get_db_name(par_handle handle, const char **error_message)
{
	(void)handle;
	(void)error_message;
	return NULL;
}

enum kv_category get_kv_category(int32_t key_size, int32_t value_size, request_type operation,
				 const char **error_message)
{
	log_fatal("Unimplemented");
	_exit(EXIT_FAILURE);
	(void)key_size;
	(void)value_size;
	(void)operation;
	(void)error_message;
	return 0;
}
#ifdef ENABLE_METRICS

#define ITERATIONS 100
#define CPU_FREQ_HZ 2300
#endif

struct par_put_metadata par_put(par_handle handle, struct par_key_value *key_value, const char **error_message)
{
	struct par_handle *parallax_handle = (struct par_handle *)handle;

	size_t msg_len =
		par_net_put_req_calc_size(key_value->k.size, key_value->v.val_size) + par_net_header_calc_size();

	if (msg_len > parallax_handle->send_buffer_size) {
		log_fatal("Send buffer too small has: %u B needs %lu B", parallax_handle->send_buffer_size, msg_len);
		_exit(EXIT_FAILURE);
	}

#ifdef USE_INFINIBAND
	int hash = djb2_hash(parallax_handle->db_name) % parallax_handle->num_servers;
	struct par_net_header *header =
		(struct par_net_header *)(parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]]);
#elif USE_TCP
	struct par_net_header *header = (struct par_net_header *)(parallax_handle->send_buffer);
#endif
	header->total_bytes = msg_len;
	header->opcode = OPCODE_PUT;
#ifdef USE_INFINIBAND
	header->payload_buf_vaddr = 0;
	header->payload_rkey = 0;
	header->inline_flag = 1;
	header->payload_size = 0;
#endif

	size_t buffer_len = parallax_handle->send_buffer_size - par_net_header_calc_size();
#ifdef USE_INFINIBAND
	struct par_net_put_req *request = par_net_put_req_create(
		parallax_handle->region_id, key_value->k.size, key_value->k.data, key_value->v.val_size,
		key_value->v.val_buffer,
		&parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]][par_net_header_calc_size()],
		&buffer_len);
#elif USE_TCP
	struct par_net_put_req *request = par_net_put_req_create(
		parallax_handle->region_id, key_value->k.size, key_value->k.data, key_value->v.val_size,
		key_value->v.val_buffer, &parallax_handle->send_buffer[par_net_header_calc_size()], &buffer_len);
#endif
	if (NULL == request) {
		log_fatal("Failed to create put request");
		_exit(EXIT_FAILURE);
	}
#ifdef PORTALS
#ifdef ENABLE_METRICS
	parallax_handle->start = __rdtsc();
	ssize_t bytes_received =
		par_portals_RPC(parallax_handle, parallax_handle->send_buffer, msg_len, &parallax_handle->recv_buffer);
	parallax_handle->end = __rdtsc();

	if (parallax_handle->putfl < ITERATIONS) {
		parallax_handle->total_time += (parallax_handle->end - parallax_handle->start) / CPU_FREQ_HZ;
		printf("PAR_PUT takes %ld usec\n", (parallax_handle->end - parallax_handle->start) / CPU_FREQ_HZ);
		printf("msg_len = %lu, bytes_received = %lu\n\n", msg_len, bytes_received);
		parallax_handle->total_cycles += (parallax_handle->end - parallax_handle->start);
		parallax_handle->putfl++;

	} else if (parallax_handle->putfl != ITERATIONS + 100) {
		printf("avrg PAR_PUT cycles after %d iterations = %lu\n", ITERATIONS,
		       parallax_handle->total_cycles / ITERATIONS);
		printf("avrg PAR_PUT time after %d iterations = %lu usec\n", ITERATIONS,
		       parallax_handle->total_time / ITERATIONS);
		parallax_handle->total_cycles = 0;
		parallax_handle->total_time = 0;
		parallax_handle->putfl = ITERATIONS + 100;
	}
#else
	ssize_t bytes_received =
		par_portals_RPC(parallax_handle, parallax_handle->send_buffer, msg_len, &parallax_handle->recv_buffer);
#endif
#elif USE_INFINIBAND
	char *reply_buf = NULL;
	ssize_t bytes_received = par_ib_RPC(parallax_handle,
					    parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]],
					    msg_len, &reply_buf, hash);
#else
	ssize_t bytes_received = par_net_RPC(parallax_handle->sockfd, parallax_handle->send_buffer, msg_len,

					     &parallax_handle->recv_buffer, parallax_handle->recv_buffer_size);
#endif
	if (0 == bytes_received) {
		*error_message = "Communication with server failed";
		struct par_put_metadata sample_return_value = { 0 };
		return sample_return_value;
	}
#ifdef USE_INFINIBAND
	struct par_net_header *reply_header = (struct par_net_header *)reply_buf;
	assert(OPCODE_PUT == reply_header->opcode);
	struct par_net_put_rep *reply = (struct par_net_put_rep *)&reply_buf[par_net_header_calc_size()];
#elif USE_TCP
	struct par_net_header *reply_header = (struct par_net_header *)parallax_handle->recv_buffer;
	assert(OPCODE_PUT == reply_header->opcode);
	struct par_net_put_rep *reply =
		(struct par_net_put_rep *)&parallax_handle->recv_buffer[par_net_header_calc_size()];
	(void)reply_header;
#endif

	struct par_put_metadata metadata = par_net_put_rep_handle_reply(reply);
	log_debug("Client lsn got from put is %lu", metadata.lsn);

	return metadata;
}

struct par_put_metadata par_put_serialized(par_handle handle, char *serialized_key_value, const char **error_message,
					   bool append_to_log, bool abort_on_compaction)
{
	log_fatal("Unimplemented");
	_exit(EXIT_FAILURE);
	struct par_put_metadata sample_return_value = { 0 };
	(void)handle;
	(void)serialized_key_value;
	(void)error_message;
	(void)append_to_log;
	(void)abort_on_compaction;
	return sample_return_value;
}

void par_get(par_handle handle, struct par_key *key, struct par_value *value, const char **error_message)
{
	if (value == NULL) {
		log_fatal("Value should not be null");
		_exit(EXIT_FAILURE);
	}

	//WHY DO WE WANT THIS ????
	/*if (value->val_buffer == NULL) {
		log_fatal("In Parallax client lib value buffer should not be null");
		_exit(EXIT_FAILURE);
	}*/

	struct par_handle *parallax_handle = (struct par_handle *)handle;
	size_t msg_len = par_net_get_req_calc_size(key->size) + par_net_header_calc_size();
	if (msg_len > parallax_handle->send_buffer_size) {
		log_fatal("Send buffer too small has: %u B needs %lu B", parallax_handle->send_buffer_size, msg_len);
		_exit(EXIT_FAILURE);
	}

#ifdef USE_INFINIBAND
	int hash = djb2_hash(parallax_handle->db_name) % parallax_handle->num_servers;
	struct par_net_header *header =
		(struct par_net_header *)(parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]]);
#elif USE_TCP
	struct par_net_header *header = (struct par_net_header *)(parallax_handle->send_buffer);
#endif
	header->total_bytes = msg_len;
	header->opcode = OPCODE_GET;
#ifdef USE_INFINIBAND
	header->payload_buf_vaddr = 0;
	header->payload_rkey = 0;
	header->inline_flag = 1;
	header->payload_size = 0;
#endif

	size_t buffer_len = parallax_handle->send_buffer_size - par_net_header_calc_size();
#ifdef USE_INFINIBAND
	struct par_net_get_req *request = par_net_get_req_create(
		parallax_handle->region_id, key->size, key->data, true,
		&parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]][par_net_header_calc_size()],
		&buffer_len);
#elif USE_TCP
	struct par_net_get_req *request =
		par_net_get_req_create(parallax_handle->region_id, key->size, key->data, true,
				       &parallax_handle->send_buffer[par_net_header_calc_size()], &buffer_len);
#endif
	if (NULL == request) {
		log_fatal("Failed to create get request");
		_exit(EXIT_FAILURE);
	}
#ifdef PORTALS
#ifdef ENABLE_METRICS

	parallax_handle->start = __rdtsc();
	ssize_t bytes_received =
		par_portals_RPC(parallax_handle, parallax_handle->send_buffer, msg_len, &parallax_handle->recv_buffer);
	parallax_handle->end = __rdtsc();

	if (parallax_handle->getfl < ITERATIONS) {
		parallax_handle->total_time += (parallax_handle->end - parallax_handle->start) / CPU_FREQ_HZ;
		printf("PAR_GET takes %ld usec\n", (parallax_handle->end - parallax_handle->start) / CPU_FREQ_HZ);
		printf("msg_len = %lu, bytes_received = %lu\n\n", msg_len, bytes_received);
		parallax_handle->total_cycles += (parallax_handle->end - parallax_handle->start);
		parallax_handle->getfl++;

	} else if (parallax_handle->getfl != ITERATIONS + 100) {
		printf("avrg PAR_GET cycles after %d iterations = %lu\n", ITERATIONS,
		       parallax_handle->total_cycles / ITERATIONS);
		printf("avrg PAR_GET time after %d iterations = %lu usec\n", ITERATIONS,
		       parallax_handle->total_time / ITERATIONS);
		parallax_handle->total_cycles = 0;
		parallax_handle->total_time = 0;
		parallax_handle->getfl = ITERATIONS + 100;
	}
#else
	ssize_t bytes_received =
		par_portals_RPC(parallax_handle, parallax_handle->send_buffer, msg_len, &parallax_handle->recv_buffer);
#endif
#elif USE_INFINIBAND
	char *reply_buf = NULL;
	ssize_t bytes_received = par_ib_RPC(parallax_handle,
					    parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]],
					    msg_len, &reply_buf, hash);
#else
	ssize_t bytes_received = par_net_RPC(parallax_handle->sockfd, parallax_handle->send_buffer, msg_len,
					     &parallax_handle->recv_buffer, parallax_handle->recv_buffer_size);
#endif
	if (0 == bytes_received) {
		*error_message = "Communication with server failed";
		return;
	}

#ifdef USE_INFINIBAND
	struct par_net_get_rep *reply = (struct par_net_get_rep *)&reply_buf[par_net_header_calc_size()];
#elif USE_TCP
	struct par_net_get_rep *reply =
		(struct par_net_get_rep *)&parallax_handle->recv_buffer[par_net_header_calc_size()];
#endif

	if (false == par_net_get_rep_handle_reply(reply, value)) {
		log_debug("Key %.*s NOT found", key->size, key->data);
		*error_message = "Key Not found";
	}
}

void par_get_serialized(par_handle handle, char *key_serialized, struct par_value *value, const char **error_message)
{
	struct key_splice *key = (struct key_splice *)key_serialized;
	struct par_key par_key = { .size = key_splice_get_key_size(key), .data = key_splice_get_key_offset(key) };
	par_get(handle, &par_key, value, error_message);

	if (*error_message) {
		log_fatal("%s", *error_message);
		_exit(EXIT_FAILURE);
	}
}

par_ret_code par_exists(par_handle handle, struct par_key *key)
{
	struct par_handle *parallax_handle = (struct par_handle *)handle;
	size_t msg_len = par_net_get_req_calc_size(key->size) + par_net_header_calc_size();
	if (msg_len > parallax_handle->send_buffer_size) {
		log_fatal("Send buffer too small has: %u B needs %lu B", parallax_handle->send_buffer_size, msg_len);
		_exit(EXIT_FAILURE);
	}

#ifdef USE_INFINIBAND
	int hash = djb2_hash(parallax_handle->db_name) % parallax_handle->num_servers;
	struct par_net_header *header =
		(struct par_net_header *)(parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]]);
#elif USE_TCP
	struct par_net_header *header = (struct par_net_header *)(parallax_handle->send_buffer);
#endif
	header->total_bytes = msg_len;
	header->opcode = OPCODE_GET;

	size_t buffer_len = parallax_handle->send_buffer_size - par_net_header_calc_size();
#ifdef USE_INFINIBAND
	struct par_net_get_req *request = par_net_get_req_create(
		parallax_handle->region_id, key->size, key->data, false,
		&parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]][par_net_header_calc_size()],
		&buffer_len);
#elif USE_TCP
	struct par_net_get_req *request =
		par_net_get_req_create(parallax_handle->region_id, key->size, key->data, false,
				       &parallax_handle->send_buffer[par_net_header_calc_size()], &buffer_len);
#endif
	if (NULL == request) {
		log_fatal("Failed to create get request");
		_exit(EXIT_FAILURE);
	}

#ifdef PORTALS
	ssize_t bytes_received =
		par_portals_RPC(parallax_handle, parallax_handle->send_buffer, msg_len, &parallax_handle->recv_buffer);
#elif USE_INFINIBAND
	char *reply_buf = NULL;
	ssize_t bytes_received = par_ib_RPC(parallax_handle,
					    parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]],
					    msg_len, &reply_buf, hash);
#else
	ssize_t bytes_received = par_net_RPC(parallax_handle->sockfd, parallax_handle->send_buffer, msg_len,
					     &parallax_handle->recv_buffer, parallax_handle->recv_buffer_size);
#endif
	if (0 == bytes_received) {
		log_warn("Communication with server failed");
		return false;
	}

#ifdef USE_INFINIBAND
	struct par_net_get_rep *reply = (struct par_net_get_rep *)&reply_buf[par_net_header_calc_size()];
#elif USE_TCP
	struct par_net_get_rep *reply =
		(struct par_net_get_rep *)&parallax_handle->recv_buffer[par_net_header_calc_size()];
#endif

	return par_net_get_rep_is_found(reply) ? PAR_SUCCESS : PAR_KEY_NOT_FOUND;
}

// cppcheck-suppress unusedFunction
uint64_t par_flush_segment_in_log(par_handle handle, char *buf, int32_t buf_size, uint32_t IO_size,
				  enum log_category log_cat)
{
	log_fatal("Unimplemented");
	_exit(EXIT_FAILURE);
	(void)handle;
	(void)buf;
	(void)buf_size;
	(void)IO_size;
	(void)log_cat;
	return 0;
}

uint64_t par_init_compaction_id(par_handle handle)
{
	(void)handle;
	return 0;
}

void par_delete(par_handle handle, struct par_key *key, const char **error_message)
{
	struct par_handle *parallax_handle = (struct par_handle *)handle;
	size_t msg_len = par_net_del_req_calc_size(key->size) + par_net_header_calc_size();
	if (msg_len > parallax_handle->send_buffer_size) {
		log_fatal("Send buffer too small has: %u B needs %lu B", parallax_handle->send_buffer_size, msg_len);
		_exit(EXIT_FAILURE);
	}

#ifdef USE_INFINIBAND
	int hash = djb2_hash(parallax_handle->db_name) % parallax_handle->num_servers;
	struct par_net_header *header =
		(struct par_net_header *)(parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]]);
#elif USE_TCP
	struct par_net_header *header = (struct par_net_header *)(parallax_handle->send_buffer);
#endif
	header->total_bytes = msg_len;
	header->opcode = OPCODE_DEL;

	size_t buffer_len = parallax_handle->recv_buffer_size - par_net_header_calc_size();
#ifdef USE_INFINIBAND
	struct par_net_del_req *request = par_net_del_req_create(
		parallax_handle->region_id, key->size, key->data,
		&parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]][par_net_header_calc_size()],
		&buffer_len);
#elif USE_TCP
	struct par_net_del_req *request =
		par_net_del_req_create(parallax_handle->region_id, key->size, key->data,
				       &parallax_handle->send_buffer[par_net_header_calc_size()], &buffer_len);
#endif
	if (NULL == request) {
		log_fatal("Failed to create delete request");
		_exit(EXIT_FAILURE);
	}

#ifdef PORTALS
	ssize_t bytes_received =
		par_portals_RPC(parallax_handle, parallax_handle->send_buffer, msg_len, &parallax_handle->recv_buffer);
#elif USE_INFINIBAND
	char *reply_buf = NULL;
	ssize_t bytes_received = par_ib_RPC(parallax_handle,
					    parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]],
					    msg_len, &reply_buf, hash);
#else
	ssize_t bytes_received = par_net_RPC(parallax_handle->sockfd, parallax_handle->send_buffer, msg_len,
					     &parallax_handle->recv_buffer, parallax_handle->recv_buffer_size);
#endif
	if (0 == bytes_received) {
		*error_message = "Communication with server failed";
		return;
	}
#ifdef USE_INFINIBAND
	struct par_net_header *reply_header = (struct par_net_header *)reply_buf;
	assert(OPCODE_DEL == reply_header->opcode);
	struct par_net_del_rep *delete_reply = (struct par_net_del_rep *)&reply_buf[par_net_header_calc_size()];
#elif USE_TCP
	struct par_net_header *reply_header = (struct par_net_header *)parallax_handle->recv_buffer;
	assert(OPCODE_DEL == reply_header->opcode);
	struct par_net_del_rep *delete_reply =
		(struct par_net_del_rep *)&parallax_handle->recv_buffer[par_net_header_calc_size()];
	(void)reply_header;
#endif
	par_net_del_rep_handle_reply(delete_reply);
}

#ifdef PORTALS
/*scanner staff*/
#define PAR_SCAN_MAX_KV_ENTRIES 50
struct parallax_scanner {
	char *send_buffer;
	char *recv_buffer;
	struct par_handle *parallax_handle;
	uint32_t max_KV_pairs;
	uint32_t send_buffer_size;
	uint32_t recv_buffer_size;
	struct par_net_scan_rep *reply;
	bool is_valid;
};
#else
/*scanner staff*/
#define PAR_SCAN_MAX_KV_ENTRIES 50
#define PAR_SCAN_SEND_BUFFER_SIZE (2 * MAX_KEY_SIZE)
#define PAR_SCAN_RECV_BUFFER_SIZE (KV_MAX_SIZE * 4UL)
struct parallax_scanner {
	char *send_buffer;
	char *recv_buffer;
	struct par_handle *parallax_handle;
	uint32_t max_KV_pairs;
	uint32_t send_buffer_size;
	uint32_t recv_buffer_size;
	struct par_net_scan_rep *reply;
	bool is_valid;
};
#endif

static struct par_net_scan_rep *par_scan_get_next_batch(par_scanner scanner, par_seek_mode mode, struct par_key *key)
{
#ifdef USE_INFINIBAND
	log_fatal("Scanner is NOT supported for the InfiniBand client");
	_exit(EXIT_FAILURE);
#endif
	struct parallax_scanner *parallax_scanner = scanner;
	size_t buffer_len = parallax_scanner->send_buffer_size - par_net_header_calc_size();

	struct par_net_scan_req *scan_req =
		par_net_scan_req_create(parallax_scanner->parallax_handle->region_id, key, PAR_SCAN_MAX_KV_ENTRIES,
					mode, &parallax_scanner->send_buffer[par_net_header_calc_size()], buffer_len);

	if (NULL == scan_req) {
		log_fatal("Failed to create scan request");
		_exit(EXIT_FAILURE);
	}

	log_debug("Sending SCAN request to fetch next batch... %s mode with key: %.*s",
		  mode == PAR_GREATER_OR_EQUAL ? "PAR_GREATER_OR_EQUAL" : "PAR_GREATER", key ? key->size : 4,
		  key ? key->data : "NULL");

	struct par_net_header *header = (struct par_net_header *)parallax_scanner->send_buffer;
	header->opcode = OPCODE_SCAN;
	header->total_bytes = par_net_scan_req_calc_size(key ? key->size : 1) + sizeof(struct par_net_header);
#ifdef PORTALS
	par_portals_RPC(parallax_scanner->parallax_handle, parallax_scanner->send_buffer, header->total_bytes,
			&parallax_scanner->recv_buffer);
#elif USE_INFINIBAND
	par_ib_RPC(parallax_scanner->parallax_handle, parallax_scanner->send_buffer, header->total_bytes,
		   &parallax_scanner->recv_buffer, 0);
#else
	par_net_RPC(parallax_scanner->parallax_handle->sockfd, parallax_scanner->send_buffer, header->total_bytes,
		    &parallax_scanner->recv_buffer, parallax_scanner->recv_buffer_size);
#endif
	log_debug("Sending SCAN request to fetch next batch ... D O N E");
	//-- reply part
	struct par_net_header *reply_header = (struct par_net_header *)parallax_scanner->recv_buffer;
	assert(reply_header->opcode == OPCODE_SCAN);
	struct par_net_scan_rep *reply =
		(struct par_net_scan_rep *)(&parallax_scanner->recv_buffer[par_net_header_calc_size()]);

	if (NULL == reply) {
		log_fatal("Got null scan reply?");
		_exit(EXIT_FAILURE);
	}
	parallax_scanner->is_valid = par_net_scan_rep_is_valid(reply);

	return reply;
}

par_scanner par_init_scanner(par_handle handle, struct par_key *key, par_seek_mode mode, const char **error_message)
{
#ifdef PORTALS
	struct par_handle *parallax_handle = (struct par_handle *)handle;
	struct parallax_scanner *scanner = calloc(1UL, sizeof(struct parallax_scanner));
	scanner->send_buffer_size = parallax_handle->send_buffer_size;
	scanner->recv_buffer_size = parallax_handle->recv_buffer_size;
	scanner->send_buffer = parallax_handle->send_buffer;
	scanner->recv_buffer = parallax_handle->recv_buffer;
	scanner->max_KV_pairs = PAR_SCAN_MAX_KV_ENTRIES;
	scanner->parallax_handle = handle;
#else
	struct parallax_scanner *scanner = calloc(1UL, sizeof(struct parallax_scanner));
	scanner->send_buffer_size = PAR_SCAN_SEND_BUFFER_SIZE;
	scanner->recv_buffer_size = PAR_SCAN_RECV_BUFFER_SIZE;
	scanner->send_buffer = calloc(1UL, scanner->send_buffer_size);
	scanner->recv_buffer = calloc(1UL, scanner->recv_buffer_size);
	scanner->parallax_handle = handle;
	scanner->max_KV_pairs = PAR_SCAN_MAX_KV_ENTRIES;
	scanner->parallax_handle = handle;
#endif
	log_debug("Requesting from server for the 1st batch of KV pairs... key is: %.*s", key == NULL ? 4 : key->size,
		  key == NULL ? "NULL" : key->data);
	scanner->reply = par_scan_get_next_batch(scanner, mode, key);
	if (NULL == scanner->reply) {
		log_fatal("Failed to fetch 1st batch of KV pairs from the server");
		*error_message = "Failed to fetch 1st batch of KV pairs from the server";
		free(scanner);
		return NULL;
	}
	par_net_scan_rep_seek2_to_first(scanner->reply);
	return scanner;
}

void par_close_scanner(par_scanner sc)
{
	struct parallax_scanner *parallax_scanner = (struct parallax_scanner *)sc;
	//free(parallax_scanner->send_buffer);
	//free(parallax_scanner->recv_buffer);
	free(parallax_scanner);
}

int par_get_next(par_scanner sc)
{
	struct parallax_scanner *parallax_scanner = (struct parallax_scanner *)sc;
	assert(parallax_scanner->reply);

	if (false == par_net_scan_rep_seek2_next_splice(parallax_scanner->reply)) {
		struct kv_splice *last_splice = par_net_scan_rep_get_last_splice(parallax_scanner->reply);
		struct par_key key = { .size = kv_splice_get_key_size(last_splice),
				       .data = kv_splice_get_key_offset_in_kv(last_splice) };
		parallax_scanner->reply = par_scan_get_next_batch(parallax_scanner, PAR_GREATER, &key);
		return par_net_scan_rep_seek2_to_first(parallax_scanner->reply);
	}
	return true;
}

int par_is_valid(par_scanner sc)
{
	struct parallax_scanner *parallax_scanner = sc;
	return NULL == parallax_scanner->reply ? false : par_net_scan_rep_has_more(parallax_scanner->reply);
}

struct par_key par_get_key(par_scanner sc)
{
	struct par_key key = { 0 };
	struct parallax_scanner *parallax_scanner = sc;
	if (NULL == parallax_scanner->reply)
		return key;
	struct kv_splice *kv_splice = par_net_scan_rep_get_curr_splice(parallax_scanner->reply);
	key.size = kv_splice_get_key_size(kv_splice);
	key.data = kv_splice_get_key_offset_in_kv(kv_splice);
	return key;
}

struct par_value par_get_value(par_scanner sc)
{
	struct par_value value = { 0 };
	struct parallax_scanner *parallax_scanner = sc;
	if (NULL == parallax_scanner->reply)
		return value;
	struct kv_splice *kv_splice = par_net_scan_rep_get_curr_splice(parallax_scanner->reply);
	value.val_size = kv_splice_get_value_size(kv_splice);
	value.val_buffer = kv_splice_get_key_offset_in_kv(kv_splice);
	return value;
	return value;
}

// cppcheck-suppress unusedFunction
par_ret_code par_sync(par_handle handle)
{
	struct par_handle *parallax_handle = (struct par_handle *)handle;

#ifdef USE_INFINIBAND
	int hash = djb2_hash(parallax_handle->db_name) % parallax_handle->num_servers;
	struct par_net_sync_req *sync_request = par_net_sync_req_create(
		parallax_handle->region_id,
		&parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]][par_net_header_calc_size()],
		parallax_handle->send_buffer_size - par_net_header_calc_size());
#elif USE_TCP
	struct par_net_sync_req *sync_request = par_net_sync_req_create(
		parallax_handle->region_id, &parallax_handle->send_buffer[par_net_header_calc_size()],
		parallax_handle->send_buffer_size - par_net_header_calc_size());
#endif
	if (NULL == sync_request) {
		log_fatal("Failed to create par_net_sync_req request");
		_exit(EXIT_FAILURE);
	}
#ifdef USE_INFINIBAND
	struct par_net_header *request =
		(struct par_net_header *)parallax_handle->send_buffer[parallax_handle->send_idx[hash]];
#elif USE_TCP
	struct par_net_header *request = (struct par_net_header *)(parallax_handle->send_buffer);
#endif
	request->opcode = OPCODE_SYNC;
	request->total_bytes = par_net_header_calc_size() + par_net_sync_req_calc_size();

#ifdef PORTALS
	ssize_t bytes_received = par_portals_RPC(parallax_handle, parallax_handle->send_buffer, request->total_bytes,
						 &parallax_handle->recv_buffer);
#elif USE_INFINIBAND
	char *reply_buf = NULL;
	ssize_t bytes_received = par_ib_RPC(parallax_handle,
					    parallax_handle->send_buffer[hash][parallax_handle->send_idx[hash]],
					    request->total_bytes, &reply_buf, hash);
#else
	ssize_t bytes_received = par_net_RPC(parallax_handle->sockfd, parallax_handle->send_buffer,
					     request->total_bytes, &parallax_handle->recv_buffer,
					     parallax_handle->recv_buffer_size);
#endif
	struct par_net_header *reply = (struct par_net_header *)parallax_handle->recv_buffer;
	assert(reply->total_bytes == bytes_received);
	struct par_net_sync_rep *sync_reply = (struct par_net_sync_rep *)&reply_buf[par_net_header_calc_size()];
	par_ret_code ret_val = PAR_SUCCESS;
	if (par_net_sync_rep_get_status(sync_reply)) {
		log_warn("Sync failed");
		ret_val = PAR_FAILURE;
	}
	return ret_val;
}

void par_metrics(par_handle handle, uint8_t flags)
{
#ifdef USE_PAR_NET_METRICS
	struct par_handle *parallax_handle = (struct par_handle *)handle;
	size_t msg_len = par_net_metrics_req_calc_size() + par_net_header_calc_size();

	if (msg_len > parallax_handle->send_buffer_size) {
		log_fatal("Send buffer too small has: %u B needs %lu B", parallax_handle->send_buffer_size, msg_len);
		_exit(EXIT_FAILURE);
	}

	struct par_net_header *header = (struct par_net_header *)(parallax_handle->send_buffer);
	header->total_bytes = msg_len;
	header->opcode = OPCODE_METRICS;

	size_t buffer_len = parallax_handle->recv_buffer_size - par_net_header_calc_size();
	struct par_net_metrics_req *request = par_net_metrics_req_create(
		flags, &parallax_handle->send_buffer[par_net_header_calc_size()], &buffer_len);

	if (NULL == request) {
		log_fatal("Failed to create Metrics request");
		_exit(EXIT_FAILURE);
	}

	ssize_t bytes_received = par_net_RPC(parallax_handle->sockfd, parallax_handle->send_buffer, msg_len,
					     &parallax_handle->recv_buffer, parallax_handle->recv_buffer_size);

	if (0 == bytes_received) {
		return;
	}

	struct par_net_header *reply_header = (struct par_net_header *)parallax_handle->recv_buffer;
	assert(OPCODE_METRICS == reply_header->opcode);
	struct par_net_metrics_rep *metrics_reply =
		(struct par_net_metrics_rep *)&parallax_handle->recv_buffer[par_net_header_calc_size()];

	(void)reply_header;
	par_net_metrics_rep_handle_reply(metrics_reply);

#endif
}

struct par_options_desc *par_get_default_options(void)
{
	// parse the options from options.yml config file
	struct lib_option *db_options = NULL;
	parse_options(&db_options);

	struct lib_option *option = NULL;
	/*get the default db option values */
	check_option(db_options, "level0_size", &option);
	uint64_t level0_size = MB(option->value.count);

	check_option(db_options, "growth_factor", &option);
	uint64_t growth_factor = option->value.count;

	check_option(db_options, "level_medium_inplace", &option);
	uint64_t level_medium_inplace = option->value.count;

	check_option(db_options, "medium_log_LRU_cache_size", &option);
	uint64_t LRU_cache_size = MB(option->value.count);

	check_option(db_options, "gc_interval", &option);
	uint64_t gc_interval = option->value.count;

	check_option(db_options, "primary_mode", &option);
	uint64_t primary_mode = option->value.count;

	check_option(db_options, "replica_mode", &option);
	uint64_t replica_mode = 0;

	check_option(db_options, "replica_build_index", &option);
	uint64_t replica_build_index = option->value.count;

	check_option(db_options, "replica_send_index", &option);
	uint64_t replica_send_index = option->value.count;

	check_option(db_options, "enable_bloom_filters", &option);
	uint64_t enable_bloom_filters = option->value.count;

	check_option(db_options, "enable_compaction_double_buffering", &option);
	uint64_t enable_compaction_double_buffering = option->value.count;

	check_option(db_options, "number_of_replicas", &option);
	uint64_t number_of_replicas = option->value.count;

	check_option(db_options, "parallax_server", &option);
	const char *parallax_server = strdup(option->value.name);

	struct par_options_desc *default_db_options =
		(struct par_options_desc *)calloc(NUM_OF_CONFIGURATION_OPTIONS, sizeof(struct par_options_desc));
	//fill default_db_options based on the default values
	default_db_options[LEVEL0_SIZE].value = level0_size;
	default_db_options[GROWTH_FACTOR].value = growth_factor;
	default_db_options[LEVEL_MEDIUM_INPLACE].value = level_medium_inplace;
	default_db_options[MEDIUM_LOG_LRU_CACHE_SIZE].value = LRU_cache_size;
	default_db_options[GC_INTERVAL].value = gc_interval;
	default_db_options[PRIMARY_MODE].value = primary_mode;
	default_db_options[REPLICA_MODE].value = replica_mode;
	default_db_options[ENABLE_BLOOM_FILTERS].value = enable_bloom_filters;
	default_db_options[ENABLE_COMPACTION_DOUBLE_BUFFERING].value = enable_compaction_double_buffering;
	default_db_options[NUMBER_OF_REPLICAS].value = number_of_replicas;
	default_db_options[REPLICA_BUILD_INDEX].value = replica_build_index;
	default_db_options[REPLICA_SEND_INDEX].value = replica_send_index;
	default_db_options[WCURSOR_SPIN_FOR_FLUSH_REPLIES].value = 0;
	default_db_options[PARALLAX_SERVER].value = (uint64_t)parallax_server;
#ifdef PORTALS
	log_debug("PARALLAX_SERVER_HOSTNAME is: %s", parallax_server);
#endif
	destroy_options(db_options);
	return default_db_options;
}

void par_flush_superblock(par_handle handle)
{
	log_fatal("Unimplemented");
	_exit(EXIT_FAILURE);
	(void)handle;
}

int par_get_num_of_servers(void)
{
	int count = 0;
	char *token = strtok((char *)par_get_default_options()[PARALLAX_SERVER].value, " ,");

	while (token != NULL && count < MAX_SERVERS) {
		if (strchr(token, ':') != NULL) {
			count++;
		}
		token = strtok(NULL, " ,");
	}
	return count;
}

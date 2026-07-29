#define _GNU_SOURCE
#include "ib_server_handle.h"

#define PAR_IB_USAGE_STRING                         \
	"InfiniBand Server: no options specified\n" \
	"try './infiniband_parallax_server --help' for more information\n"

#define PAR_IB_HELP_STRING                                                                                      \
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
	" -bd, --blob_dir <path>      specify the directory to store large KV blobs\n\n"                        \
	" -h, --help     display this help and exit\n"                                                          \
	" -pf, --par_format           (Optional) specify whether database should be formatted\n"

#define PAR_IB_CONFIG_STRING  \
	"[ Server Config ]\n" \
	"  - file = %s\n"     \
	"  - flags = not yet supported\n"

#define PAR_IB_DEFAULT_PORT 7471
#define PAR_IB_DEFAULT_ADDRESS "192.168.5.122"

#define PAR_IB_DECIMAL_BASE 10
#define PAR_IB_PORT_MAX 65536
#define PAR_IB_MAX_REGIONS 128
#define PAR_IB_METADATA_SIZE 4096
#define PAR_IB_CLOSE_OP_BUF_SIZE 100
#define PAR_IB_MAX_CLIENTS 256
#define PAR_IB_MSG_SIZE 1024
#define PAR_IB_NUM_ENTRIES 16
#define PAR_IB_SECTOR_SIZE 4096
#define PAR_IB_MAX_SRQ_BUFFERS 128
#define PAR_IB_DEFAULT_BLOB_DIR "/tmp"
#define PAR_IB_RDMA_READ_BUF_SIZE (4 * 1024 * 1024)

struct server_options {
	uint32_t threadno;
	const char *parallax_vol_name;
	uint32_t l0_size;
	uint32_t growth_factor;
	uint8_t format;
	long port;
	struct sockaddr_storage inaddr;
	const char *blob_dir;
};

struct root_server_handle {
	struct server_options *opts;
	struct rdma_event_channel *ec;
	struct ibv_pd *pd;
	struct server_handle *workers;
	uint32_t num_workers;
	pthread_t cm_thread;
	uint32_t rr_counter;
};

struct server_handle {
	uint32_t worker_id;
	struct ibv_comp_channel *comp_channel;
	struct ibv_cq *cq;
	struct ibv_srq *srq;
	struct par_ib_send_buf *send_slots;
	struct par_ib_recv_slot *recv_slots;
	struct rdma_read_slot *read_pool;
	pthread_t thread;
	struct root_server_handle *global;
};

struct my_conn_metadata {
	uint32_t max_buffer_size;
	uint32_t client_id;
};

struct rdma_read_ctx {
	size_t size;
	struct par_net_header *hdr;
	struct par_ib_client_ctx *client;
	struct rdma_read_slot *slot;
	struct par_ib_recv_slot *recv_slot;
};

struct rdma_read_slot {
	void *buf;
	struct ibv_mr *mr;
	size_t size;
};

struct par_ib_send_buf;

struct par_ib_recv_slot {
	void *buf;
	struct ibv_mr *mr;
	int buf_idx;
	struct par_ib_send_buf *send_buf_ptr;
	struct rdma_read_slot *read_slot_ptr;
};

struct par_ib_send_buf {
	void *buf;
	struct ibv_mr *mr;
	int buf_idx;
	struct par_ib_recv_slot *recv_slot_ptr;
};

struct par_ib_client_ctx {
	struct ibv_pd *pd;
	struct ibv_qp *qp;

	int write_fd;
	int read_fd;
	char safe_key[256];
};

struct par_ib_client_ctx *clients[PAR_IB_MAX_CLIENTS];
static uint32_t client_id_counter = 1;

long par_ib_server_parse_number(const char *str, const char *opt)
{
	errno = 0;
	long num = strtol(str, NULL, PAR_IB_DECIMAL_BASE);
	if (0 == errno)
		return num;
	if (errno == EINVAL) {
		log_fatal("InfiniBand Server: Invalid number in option '%s'\n", opt);
		_exit(EXIT_FAILURE);
	}
	log_fatal("InfiniBand Server: Number out-of-range in option '%s'\n", opt);
	_exit(EXIT_FAILURE);
}

void par_ib_server_check_arg(int argc, int option_id)
{
	if (option_id < argc)
		return;
	log_fatal("InfiniBand Server: Option requires an argument");
	_exit(EXIT_FAILURE);
}

void par_ib_server_set_address(struct server_options *opts, const char *arg)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)&opts->inaddr;
	memset(addr, 0, sizeof(struct sockaddr_in));
	addr->sin_family = AF_INET;

	if (inet_pton(AF_INET, arg, &addr->sin_addr) != 1) {
		log_fatal("InfiniBand Server: Invalid IPv4 address '%s'\n", arg);
		_exit(EXIT_FAILURE);
	}
}

void par_ib_server_set_port(struct server_options *opts, const char *arg)
{
	long port = par_ib_server_parse_number(arg, "-p/--port");
	if (port < 0 || port > PAR_IB_PORT_MAX) {
		log_fatal("InfiniBand Server: Invalid port number '%ld'\n", port);
	}
	opts->port = port;
}

struct server_options *par_ib_server_parse_argv_opts(int argc, char **argv)
{
	if (argc <= 1) {
		log_fatal("%s", PAR_IB_USAGE_STRING);
		_exit(EXIT_FAILURE);
	}

	struct server_options *server_options = calloc(1UL, sizeof(*server_options));
	if (!server_options) {
		log_fatal("InfiniBand Server: Memory Allocation Failed");
		_exit(EXIT_FAILURE);
	}

	int port_set = 0;
	int address_set = 0;

	for (int i = 1; i < argc; ++i) {
		if (argv[i][0] != '-') {
			log_fatal("InfiniBand Server: Unknown Option '%s'\n", argv[i]);
		}

		if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--threads")) {
			par_ib_server_check_arg(argc, ++i);
			long thrnum = par_ib_server_parse_number(argv[i], "-t/--threads");
			if (thrnum < 0) {
				log_fatal("InfiniBand Server: invalid thread number '%ld'\n", thrnum);
			}
			server_options->threadno = (unsigned int)thrnum;
		} else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) {
			par_ib_server_check_arg(argc, ++i);
			par_ib_server_set_port(server_options, argv[i]);
			port_set = 1;
		} else if (!strcmp(argv[i], "-b") || !strcmp(argv[i], "--bind")) {
			par_ib_server_check_arg(argc, ++i);
			par_ib_server_set_address(server_options, argv[i]);
			address_set = 1;
		} else if (!strcmp(argv[i], "-L0") || !strcmp(argv[i], "--L0_size")) {
			par_ib_server_check_arg(argc, ++i);
			server_options->l0_size = strtoul(argv[i], NULL, 10) * (1 << 20);
		} else if (!strcmp(argv[i], "-GF") || !strcmp(argv[i], "--GF")) {
			par_ib_server_check_arg(argc, ++i);
			server_options->growth_factor = strtoul(argv[i], NULL, 10);
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			log_fatal("%s\n", PAR_IB_HELP_STRING);
		} else if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--file")) {
			par_ib_server_check_arg(argc, ++i);
			server_options->parallax_vol_name = strdup(argv[i]);
		} else if (!strcmp(argv[i], "-pf") || !strcmp(argv[i], "--par_format")) {
			server_options->format = 1;
		} else if (!strcmp(argv[i], "-bd") || !strcmp(argv[i], "--blob_dir")) {
			par_ib_server_check_arg(argc, ++i);
			server_options->blob_dir = strdup(argv[i]);
		} else {
			log_fatal("InfiniBand Server: unknown option '%s'\n", argv[i]);
		}
	}

	if (port_set == 0) {
		server_options->port = PAR_IB_DEFAULT_PORT;
	}
	if (address_set == 0) {
		par_ib_server_set_address(server_options, PAR_IB_DEFAULT_ADDRESS);
	}
	if (server_options->blob_dir == NULL) {
		server_options->blob_dir = strdup(PAR_IB_DEFAULT_BLOB_DIR);
	}

	return server_options;
}

struct root_server_handle *par_ib_server_handle_init(struct server_options *opts)
{
	if (!opts) {
		log_debug("InfiniBand Server: options is NULL");
		_exit(EXIT_FAILURE);
	}

	struct root_server_handle *handle = calloc(1, sizeof(struct root_server_handle));
	if (handle == NULL) {
		log_debug("InfiniBand Server: calloc failed");
		_exit(EXIT_FAILURE);
	}

	handle->opts = opts;
	handle->num_workers = opts->threadno;
	handle->workers = calloc(handle->num_workers, sizeof(struct server_handle));

	handle->ec = rdma_create_event_channel();
	if (!handle->ec) {
		perror("rdma_create_event_channel");
		_exit(EXIT_FAILURE);
	}

	struct rdma_cm_id *listen_id;

	if (rdma_create_id(handle->ec, &listen_id, NULL, RDMA_PS_TCP)) {
		perror("rdma_create_id");
		_exit(EXIT_FAILURE);
	}

	struct sockaddr_in *inaddr = (struct sockaddr_in *)&opts->inaddr;
	inaddr->sin_port = htons(opts->port);

	if (rdma_bind_addr(listen_id, (struct sockaddr *)inaddr)) {
		perror("rdma_bind_addr");
		_exit(EXIT_FAILURE);
	}

	if (rdma_listen(listen_id, 10)) {
		perror("rdma_listen");
		_exit(EXIT_FAILURE);
	}

	handle->pd = ibv_alloc_pd(listen_id->verbs);
	if (!handle->pd) {
		perror("ibv_alloc_pd");
		_exit(EXIT_FAILURE);
	}

	for (uint32_t i = 0; i < handle->num_workers; ++i) {
		struct server_handle *worker = &handle->workers[i];
		worker->worker_id = i;
		worker->global = handle;

		worker->comp_channel = ibv_create_comp_channel(listen_id->verbs);
		if (!worker->comp_channel) {
			perror("ibv_create_comp_channel");
			_exit(EXIT_FAILURE);
		}

		worker->cq = ibv_create_cq(listen_id->verbs, 256, worker, worker->comp_channel, 0);
		if (!worker->cq) {
			perror("ibv_create_cq");
			_exit(EXIT_FAILURE);
		}
		ibv_req_notify_cq(worker->cq, 0);

		struct ibv_srq_init_attr srq_attr = { .attr = { .max_wr = PAR_IB_MAX_SRQ_BUFFERS, .max_sge = 1 } };
		worker->srq = ibv_create_srq(handle->pd, &srq_attr);
		if (!worker->srq) {
			perror("ibv_create_srq");
			_exit(EXIT_FAILURE);
		}

		size_t single_buf_size = PAR_IB_METADATA_SIZE + PAR_IB_MSG_SIZE;
		size_t total_chunk_size = single_buf_size * PAR_IB_MAX_SRQ_BUFFERS;

		worker->recv_slots = calloc(PAR_IB_MAX_SRQ_BUFFERS, sizeof(struct par_ib_recv_slot));
		if (!worker->recv_slots) {
			log_debug("InfiniBand Server: calloc global_recv_slots failed");
			_exit(EXIT_FAILURE);
		}

		void *srq_memory_chunk = NULL;
		int ret = posix_memalign(&srq_memory_chunk, PAR_IB_SECTOR_SIZE, total_chunk_size);
		if (ret) {
			perror("posix_memalign chunk");
			_exit(EXIT_FAILURE);
		}

		struct ibv_mr *srq_mr = ibv_reg_mr(handle->pd, srq_memory_chunk, total_chunk_size,
						   IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
		if (!srq_mr) {
			free(srq_memory_chunk);
			perror("ibv_reg_mr chunk");
			_exit(EXIT_FAILURE);
		}

		for (int j = 0; j < PAR_IB_MAX_SRQ_BUFFERS; j++) {
			worker->recv_slots[j].buf = (char *)srq_memory_chunk + (j * single_buf_size);
			worker->recv_slots[j].mr = srq_mr;
			worker->recv_slots[j].buf_idx = j;

			struct ibv_sge sge = {
				.addr = (uintptr_t)worker->recv_slots[j].buf,
				.length = single_buf_size,
				.lkey = worker->recv_slots[j].mr->lkey,
			};
			struct ibv_recv_wr wr = {
				.wr_id = (uintptr_t)&worker->recv_slots[j],
				.sg_list = &sge,
				.num_sge = 1,
			};
			struct ibv_recv_wr *bad_wr;
			if (ibv_post_srq_recv(worker->srq, &wr, &bad_wr)) {
				perror("ibv_post_srq_recv init");
				_exit(EXIT_FAILURE);
			}
		}

		worker->send_slots = calloc(PAR_IB_MAX_SRQ_BUFFERS, sizeof(struct par_ib_send_buf));
		if (!worker->send_slots) {
			log_debug("InfiniBand Server: calloc global_send_slots failed");
			_exit(EXIT_FAILURE);
		}

		size_t single_send_size = KV_MAX_SIZE + PAR_IB_METADATA_SIZE;
		size_t total_send_chunk = single_send_size * PAR_IB_MAX_SRQ_BUFFERS;

		void *send_memory_chunk = NULL;
		int ret_send = posix_memalign(&send_memory_chunk, PAR_IB_SECTOR_SIZE, total_send_chunk);
		if (ret_send) {
			perror("posix_memalign send chunk");
			_exit(EXIT_FAILURE);
		}

		struct ibv_mr *send_mr =
			ibv_reg_mr(handle->pd, send_memory_chunk, total_send_chunk, IBV_ACCESS_LOCAL_WRITE);
		if (!send_mr) {
			free(send_memory_chunk);
			perror("ibv_reg_mr send chunk");
			_exit(EXIT_FAILURE);
		}

		for (int j = 0; j < PAR_IB_MAX_SRQ_BUFFERS; j++) {
			worker->send_slots[j].buf = (char *)send_memory_chunk + (j * single_send_size);
			worker->send_slots[j].mr = send_mr;
			worker->send_slots[j].buf_idx = j;

			worker->recv_slots[j].send_buf_ptr = &worker->send_slots[j];
			worker->send_slots[j].recv_slot_ptr = &worker->recv_slots[j];
		}

		worker->read_pool = calloc(PAR_IB_MAX_SRQ_BUFFERS, sizeof(struct rdma_read_slot));
		if (!worker->read_pool) {
			log_debug("InfiniBand Server: calloc read_pool failed");
			_exit(EXIT_FAILURE);
		}

		size_t total_read_chunk_size = (size_t)PAR_IB_RDMA_READ_BUF_SIZE * PAR_IB_MAX_SRQ_BUFFERS;
		void *read_memory_chunk = NULL;
		ret = posix_memalign(&read_memory_chunk, PAR_IB_SECTOR_SIZE, total_read_chunk_size);
		if (ret) {
			perror("posix_memalign read chunk");
			_exit(EXIT_FAILURE);
		}

		struct ibv_mr *read_mr =
			ibv_reg_mr(handle->pd, read_memory_chunk, total_read_chunk_size, IBV_ACCESS_LOCAL_WRITE);
		if (!read_mr) {
			free(read_memory_chunk);
			perror("ibv_reg_mr read chunk");
			_exit(EXIT_FAILURE);
		}

		for (int j = 0; j < PAR_IB_MAX_SRQ_BUFFERS; j++) {
			worker->read_pool[j].buf = (char *)read_memory_chunk + (j * PAR_IB_RDMA_READ_BUF_SIZE);
			worker->read_pool[j].mr = read_mr;
			worker->read_pool[j].size = PAR_IB_RDMA_READ_BUF_SIZE;

			worker->recv_slots[j].read_slot_ptr = &worker->read_pool[j];
		}
	}

	log_info("InfiniBand server listening on %s:%ld", inet_ntoa(inaddr->sin_addr), opts->port);

	const char *error_message = NULL;
	/** initialize parallax **/
	if (opts->format) {
		log_info("Format option enabled");
		error_message = par_format((char *)(opts->parallax_vol_name), PAR_IB_MAX_REGIONS);

		if (error_message) {
			log_fatal("%s", error_message);
			_exit(EXIT_FAILURE);
		}

		if (strcmp(opts->blob_dir, PAR_IB_DEFAULT_BLOB_DIR) != 0) {
			char cmd[1024];
			snprintf(cmd, sizeof(cmd), "rm -f %s/*", opts->blob_dir);
			int ret = system(cmd);
			if (ret != 0) {
				log_warn("Failed to clear blob directory, or directory was already empty");
			}
		} else {
			log_info("Using default blob directory, not clearing it");
		}

	} else {
		log_info("Format option not enabled");
	}

	return handle;
}

int par_ib_server_print_config(struct root_server_handle *server_handle)
{
	if (!server_handle || !server_handle->opts) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}

	struct sockaddr_in *addr = (struct sockaddr_in *)&server_handle->opts->inaddr;

	char ip_str[INET_ADDRSTRLEN];
	if (!inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str))) {
		perror("inet_ntop failed");
		return -(EXIT_FAILURE);
	}

	log_info(PAR_IB_CONFIG_STRING, server_handle->opts->parallax_vol_name);

	return EXIT_SUCCESS;
}

uint32_t par_ib_server_get_threadno(struct root_server_handle *handle)
{
	return handle->opts->threadno;
}

struct ibv_pd *par_ib_server_get_ibv_pd(struct root_server_handle *handle)
{
	return handle->pd;
}

uint32_t par_net_get_threadno(struct server_options *server_options)
{
	return server_options->threadno;
}

int par_ib_handle_cm_event(struct root_server_handle *server_handle, struct rdma_cm_event *event)
{
	switch (event->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:;
		struct rdma_cm_id *client_id = event->id;
		uint32_t worker_idx = __sync_fetch_and_add(&server_handle->rr_counter, 1) % server_handle->num_workers;
		struct server_handle *assigned_worker = &server_handle->workers[worker_idx];
		struct ibv_qp_init_attr qp_attr = {
            .send_cq = assigned_worker->cq,
            .recv_cq = assigned_worker->cq,
            .srq = assigned_worker->srq,
            .qp_type = IBV_QPT_RC,
            .cap = {
                .max_send_wr = 128,
                .max_recv_wr = 128,
                .max_send_sge = 1,
                .max_recv_sge = 1,
            },
        };
		if (rdma_create_qp(client_id, server_handle->pd, &qp_attr)) {
			perror("rdma_create_qp");
			return -1;
		}
		struct my_conn_metadata server_caps = {
			.max_buffer_size = KV_MAX_SIZE,
			.client_id = __sync_fetch_and_add(&client_id_counter, 1),
		};
		if (server_caps.client_id > PAR_IB_MAX_CLIENTS) {
			log_fatal("Server capacity reached! Rejecting client %u", server_caps.client_id);
			rdma_reject(client_id, NULL, 0);
			return 0;
		}
		struct rdma_conn_param conn_param = {
			.private_data = &server_caps,
			.private_data_len = sizeof(server_caps),
			.responder_resources = 8,
			.initiator_depth = 8,
			.retry_count = 7,
			.rnr_retry_count = 7,
		};
		if (rdma_accept(client_id, &conn_param)) {
			perror("rdma_accept");
			return -1;
		}

		struct par_ib_client_ctx *ctx = calloc(1, sizeof(*ctx));
		if (!ctx) {
			perror("calloc");
			return -1;
		}
		ctx->pd = server_handle->pd;
		ctx->qp = client_id->qp;
		ctx->write_fd = -1;
		ctx->read_fd = -1;
		ctx->safe_key[0] = '\0';

		clients[server_caps.client_id - 1] = ctx;
		client_id->context = (void *)(uintptr_t)server_caps.client_id;
		break;
	case RDMA_CM_EVENT_ESTABLISHED:;
		log_info("RDMA_CM_EVENT_ESTABLISHED");
		break;
	case RDMA_CM_EVENT_DISCONNECTED:;
		uint32_t cid = (uint32_t)(uintptr_t)event->id->context;
		log_info("RDMA_CM_EVENT_DISCONNECTED for client %u", cid);

		if (cid > 0 && cid <= PAR_IB_MAX_CLIENTS) {
			struct par_ib_client_ctx *disconnect_ctx = clients[cid - 1];
			if (disconnect_ctx != NULL) {
				if (disconnect_ctx->write_fd >= 0) {
					close(disconnect_ctx->write_fd);
					disconnect_ctx->write_fd = -1;
				}
				if (disconnect_ctx->read_fd >= 0) {
					close(disconnect_ctx->read_fd);
					disconnect_ctx->read_fd = -1;
				}
			}
		}
		break;
	default:
		log_info("Unhandled event: %s", rdma_event_str(event->event));
		return -1;
	}
	return 0;
}

void *par_ib_worker_loop(void *arg)
{
	struct server_handle *server_handle = (struct server_handle *)arg;

	while (1) {
		struct ibv_wc wc[PAR_IB_NUM_ENTRIES];
		int num_events;
		struct ibv_cq *ev_cq;
		void *ev_ctx;
		if (ibv_get_cq_event(server_handle->comp_channel, &ev_cq, &ev_ctx) != 0) {
			log_debug("ibv_get_cq_event failed");
			_exit(EXIT_FAILURE);
		}
		ibv_ack_cq_events(ev_cq, 1);
		if (ibv_req_notify_cq(ev_cq, 0) != 0) {
			log_debug("ibv_req_notify_cq failed");
			_exit(EXIT_FAILURE);
		}
		while ((num_events = ibv_poll_cq(server_handle->cq, PAR_IB_NUM_ENTRIES, wc)) > 0) {
			for (int i = 0; i < num_events; i++) {
				if (par_ib_handle_event(&wc[i], server_handle) < 0) {
					log_debug("Worker %u: par_ib_handle_event failed", server_handle->worker_id);
					_exit(EXIT_FAILURE);
				}
			}
		}
		if (num_events < 0) {
			log_debug("ibv_poll_cq failed");
			_exit(EXIT_FAILURE);
		}
	}
	return EXIT_SUCCESS;
}

inline size_t par_net_header_size(void)
{
	return sizeof(struct par_net_header);
}

void par_ib_par_net_call_open(struct server_handle *server_handle, void *args, struct par_net_header *reply_header)
{
	void *start = (void *)args;
	struct par_net_header *hdr = (struct par_net_header *)start;
	struct par_net_open_req *request = (struct par_net_open_req *)((char *)start + par_net_header_size());

	par_db_options db_options = { 0 };
	db_options.options = par_get_default_options();
	db_options.db_name = par_net_open_get_dbname(request);
	db_options.create_flag = par_net_open_get_flag(request);

	struct server_options *opts = server_handle->global->opts;

	db_options.volume_name = (char *)opts->parallax_vol_name;
	log_debug("Setting L0 size to %u B", opts->l0_size);
	db_options.options[LEVEL0_SIZE].value = opts->l0_size;
	log_debug("Setting growth factor to %u", opts->growth_factor);
	db_options.options[GROWTH_FACTOR].value = opts->growth_factor;

	const char *error_message = NULL;
	log_debug("Opening db with name == %s", db_options.db_name);
	par_handle handle = par_open(&db_options, &error_message);
	uint32_t total_bytes = par_net_open_rep_calc_size() + par_net_header_size();
	struct par_net_open_rep *reply = par_net_open_rep_create(error_message != NULL, handle,
								 (char *)reply_header + par_net_header_size(),
								 total_bytes - par_net_header_size());
	if (NULL == reply) {
		log_warn("Failed to create reply");
	}
	reply_header->opcode = OPCODE_OPEN;
	reply_header->total_bytes = total_bytes;
	reply_header->request_id = hdr->request_id;
	log_debug("Ok with open reply");
}

void par_ib_par_net_call_put(struct server_handle *server_handle, void *args, struct par_net_header *reply_header)
{
	(void)server_handle;
	void *start = (void *)args;
	struct par_net_header *hdr = (struct par_net_header *)start;
	struct par_net_put_req *request = (struct par_net_put_req *)((char *)start + par_net_header_size());
	struct par_ib_client_ctx *ctx = clients[hdr->request_id - 1];

	struct par_key_value kv_pair = { 0 };
	uint64_t region_id = par_net_put_get_region_id(request);
	kv_pair.k.size = par_net_put_get_key_size(request);
	kv_pair.v.val_size = par_net_put_get_value_size(request);
	kv_pair.k.data = par_net_put_get_key(request);
	kv_pair.v.val_buffer = par_net_put_get_value(request);
	kv_pair.v.val_buffer_size = par_net_put_get_value_size(request);

	log_debug("Key size =  %lu", (unsigned long)kv_pair.k.size);
	log_debug("Value size = %lu", (unsigned long)kv_pair.v.val_buffer_size);

	const char *error_message = NULL;

	struct par_put_metadata metadata;
	metadata = par_put((par_handle)region_id, &kv_pair, &error_message);
	log_debug("LSN is %lu", metadata.lsn);
	if (ctx->safe_key[0] == '\0') {
		if (kv_pair.k.size >= 3 && kv_pair.k.data[0] == 'i' && kv_pair.k.data[1] == 'd') {
			char *underscore = memchr(kv_pair.k.data, '_', kv_pair.k.size);
			if (underscore != NULL) {
				size_t len = underscore - (char *)kv_pair.k.data;
				memcpy(ctx->safe_key, kv_pair.k.data, len);
				ctx->safe_key[len] = '\0';
				log_debug("Locked in physical file name prefix: %s", ctx->safe_key);
			}
		}
	}
	uint32_t total_bytes = par_net_header_size() + par_net_put_rep_calc_size();
	struct par_net_put_rep *reply = par_net_put_rep_create(
		error_message == NULL, metadata, (char *)reply_header + par_net_header_size(), total_bytes);
	if (NULL == reply) {
		log_warn("Failed to create put reply");
	}
	reply_header->opcode = OPCODE_PUT;
	reply_header->total_bytes = total_bytes;
	reply_header->request_id = hdr->request_id;
}

void par_ib_par_net_call_del(struct server_handle *server_handle, void *args, struct par_net_header *reply_header)
{
	(void)server_handle;
	(void)args;
	(void)reply_header;
	log_warn("DELETE NOT IMPLEMENTED");
}

void par_ib_par_net_call_get(struct server_handle *server_handle, void *args, struct par_net_header *reply_header)
{
	(void)server_handle;
	void *start = (void *)args;
	struct par_net_header *hdr = (struct par_net_header *)start;
	struct par_net_get_req *request = (struct par_net_get_req *)((char *)start + par_net_header_size());

	uint64_t region_id = par_net_get_get_region_id(request);
	struct par_key par_key;
	par_key.size = par_net_get_get_key_size(request);
	par_key.data = par_net_get_get_key(request);
	struct par_value par_value = { 0 };
	struct par_ib_client_ctx *ctx = clients[hdr->request_id - 1];

	const char *error_message = NULL;
	uint32_t total_bytes = KV_MAX_SIZE + par_net_header_size() + par_net_get_rep_header_size();
	bool found = false;
	if (par_net_get_req_fetch_value(request)) {
		log_debug("Region id: %lu Calling par_get for key: %.*s", region_id, par_key.size, par_key.data);
		par_value.val_buffer = (char *)reply_header + par_net_header_size() + par_net_get_rep_header_size();
		par_value.val_buffer_size = total_bytes - (par_net_header_size() + par_net_get_rep_header_size());
		log_debug("Available buffer for gets is %u", par_value.val_buffer_size);
		par_get((par_handle)region_id, &par_key, &par_value, &error_message);
		found = error_message == NULL;
		if (ctx->safe_key[0] == '\0') {
			if (par_key.size >= 3 && par_key.data[0] == 'i' && par_key.data[1] == 'd') {
				char *underscore = memchr(par_key.data, '_', par_key.size);
				if (underscore != NULL) {
					size_t len = underscore - (char *)par_key.data;
					memcpy(ctx->safe_key, par_key.data, len);
					ctx->safe_key[len] = '\0';
				}
			}
		}
	} else {
		log_debug("Region id: %lu Calling par_exists for key: %.*s", region_id, par_key.size, par_key.data);
		par_ret_code ret_code = par_exists((par_handle)region_id, &par_key);
		found = ret_code == PAR_SUCCESS;
		par_value.val_size = 0;
	}
	size_t buffer_len = total_bytes - par_net_header_size();
	struct par_net_get_rep *reply =
		par_net_get_rep_set_header(found, &par_value, (char *)reply_header + par_net_header_size(), buffer_len);
	if (reply == NULL) {
		log_warn("Failed to create reply");
	}
	reply_header->opcode = OPCODE_GET;
	reply_header->total_bytes =
		par_net_header_size() + par_net_get_rep_calc_size(error_message == NULL ? par_value.val_size : 0);
	reply_header->request_id = hdr->request_id;
}

void par_ib_par_net_call_close(struct server_handle *server_handle, void *args, struct par_net_header *reply_header)
{
	(void)server_handle;
	void *start = (void *)args;
	struct par_net_header *hdr = (struct par_net_header *)start;
	struct par_net_close_req *request = (struct par_net_close_req *)((char *)start + par_net_header_size());

	uint64_t region_id = par_net_close_get_region_id(request);

	par_handle handle = (par_handle)region_id;

	const char *error_message = par_close(handle);
	log_debug("Close DB message is %s ", error_message ? error_message : " OK !");
	uint32_t error_message_size =
		par_net_header_size() + (error_message ? strlen(error_message) + 1 : 0) + PAR_IB_CLOSE_OP_BUF_SIZE;
	size_t buffer_len = error_message_size - par_net_header_size() + PAR_IB_CLOSE_OP_BUF_SIZE;

	struct par_net_close_rep *reply =
		par_net_close_rep_create(error_message, (char *)reply_header + par_net_header_size(), buffer_len);

	if (NULL == reply) {
		log_warn("Failed to create get reply");
	}
	reply_header->opcode = OPCODE_CLOSE;
	reply_header->total_bytes = error_message_size;
	reply_header->request_id = hdr->request_id;
}

void par_ib_par_net_call_scan(struct server_handle *server_handle, void *args, struct par_net_header *reply_header)
{
	(void)server_handle;
	(void)args;
	(void)reply_header;
	log_warn("SCAN NOT IMPLEMENTED");
}

void par_ib_par_net_call_sync(struct server_handle *server_handle, void *args, struct par_net_header *reply_header)
{
	(void)server_handle;
	(void)args;
	(void)reply_header;
	log_warn("SYNC NOT IMPLEMENTED");
}

void par_ib_par_net_call_put_blob(struct server_handle *server_handle, void *args, struct par_net_header *reply_header)
{
	(void)server_handle;
	void *start = (void *)args;
	struct par_net_header *hdr = (struct par_net_header *)start;
	struct par_net_put_req *request = (struct par_net_put_req *)((char *)start + par_net_header_size());

	uint32_t payload_size = par_net_put_get_value_size(request);
	const char *payload_data = (hdr->inline_flag == 0) ? (const char *)hdr->payload_buf_vaddr :
							     par_net_put_get_value(request);
	const char *error_message = NULL;
	uint32_t client_idx = hdr->request_id - 1;
	struct par_put_metadata metadata = { 0 };

	struct par_ib_client_ctx *ctx = clients[client_idx];
	if (ctx->safe_key[0] == '\0') {
		log_warn("put_blob called but no dataset mapped for client %u!", hdr->request_id);
		error_message = "No dataset mapped";
	} else {
		if (ctx->write_fd < 0) {
			char filepath[512];
			snprintf(filepath, sizeof(filepath), "%s/dataset_%s.grib",
				 server_handle->global->opts->blob_dir, ctx->safe_key);

			ctx->write_fd = open(filepath, O_RDWR | O_CREAT | O_APPEND, 0644);
		}
		if (ctx->write_fd >= 0) {
			off_t current_offset = lseek(ctx->write_fd, 0, SEEK_END);
			ssize_t written = write(ctx->write_fd, payload_data, payload_size);

			if (written != payload_size) {
				error_message = "Failed to write complete payload";
			} else {
				metadata.lsn = (uint64_t)current_offset;
			}
		} else {
			error_message = "Failed to open dataset file";
		}
	}

	uint32_t total_bytes = par_net_header_size() + par_net_put_rep_calc_size();
	struct par_net_put_rep *reply = par_net_put_rep_create(
		error_message == NULL, metadata, (char *)reply_header + par_net_header_size(), total_bytes);

	reply_header->opcode = OPCODE_PUT_BLOB;
	reply_header->total_bytes = total_bytes;
	reply_header->request_id = hdr->request_id;
	(void)reply;
}

void par_ib_par_net_call_get_blob(struct server_handle *server_handle, void *args, struct par_net_header *reply_header)
{
	(void)server_handle;
	void *start = (void *)args;
	struct par_net_header *hdr = (struct par_net_header *)start;
	struct par_blob_req *blob_req = (struct par_blob_req *)((char *)start + par_net_header_size());

	bool found = false;
	struct par_value par_value = { 0 };
	uint32_t client_idx = hdr->request_id - 1;

	struct par_ib_client_ctx *ctx = clients[client_idx];

	if (ctx->safe_key[0] == '\0') {
		log_warn("get_blob called but no dataset mapped for client %u!", hdr->request_id);
	} else {
		off_t real_offset = (off_t)blob_req->offset;

		if (ctx->read_fd < 0) {
			char filepath[512];
			snprintf(filepath, sizeof(filepath), "%s/dataset_%s.grib",
				 server_handle->global->opts->blob_dir, ctx->safe_key);

			ctx->read_fd = open(filepath, O_RDONLY);
		}

		if (ctx->read_fd >= 0) {
			par_value.val_buffer =
				(char *)reply_header + par_net_header_size() + par_net_get_rep_header_size();
			ssize_t bytes_read = pread(ctx->read_fd, par_value.val_buffer, blob_req->size, real_offset);

			if (bytes_read > 0) {
				found = true;
				par_value.val_size = bytes_read;
			}
		} else {
			log_warn("Failed to open file %s", ctx->safe_key);
		}
	}

	uint32_t total_bytes = par_net_header_size() + par_net_get_rep_header_size() + (found ? par_value.val_size : 0);
	size_t buffer_len = total_bytes - par_net_header_size();

	struct par_net_get_rep *reply =
		par_net_get_rep_set_header(found, &par_value, (char *)reply_header + par_net_header_size(), buffer_len);

	reply_header->opcode = OPCODE_GET_BLOB;
	reply_header->total_bytes = total_bytes;
	reply_header->request_id = hdr->request_id;
	(void)reply;
}

void par_ib_par_net_call_put_batch(struct server_handle *server_handle, void *args, struct par_net_header *reply_header)
{
	(void)server_handle;
	void *start = (void *)args;
	struct par_net_header *hdr = (struct par_net_header *)start;
	struct par_net_put_batch_req *request = (struct par_net_put_batch_req *)((char *)start + par_net_header_size());

	uint64_t region_id = par_net_put_batch_get_region_id(request);
	uint32_t count = par_net_put_batch_get_num_kvs(request);
	char *ptr = par_net_put_batch_get_data_ptr(request);

	const char *error_message = NULL;
	struct par_put_metadata metadata = { 0 };

	for (uint32_t i = 0; i < count; i++) {
		uint32_t k_size = *((uint32_t *)ptr);
		ptr += sizeof(uint32_t);

		uint32_t v_size = *((uint32_t *)ptr);
		ptr += sizeof(uint32_t);

		struct par_key_value kv_pair;

		kv_pair.k.size = k_size;
		kv_pair.k.data = ptr;
		ptr += k_size;

		kv_pair.v.val_size = v_size;
		kv_pair.v.val_buffer_size = v_size;
		kv_pair.v.val_buffer = ptr;
		ptr += v_size;

		metadata = par_put((par_handle)region_id, &kv_pair, &error_message);

		if (error_message) {
			log_warn("Batch put failed at index %u: %s", i, error_message);
			break;
		}
	}

	uint32_t total_bytes = par_net_header_size() + par_net_put_rep_calc_size();
	struct par_net_put_rep *reply = par_net_put_rep_create(
		error_message == NULL, metadata, (char *)reply_header + par_net_header_size(), total_bytes);

	if (NULL == reply) {
		log_warn("Failed to create put batch reply");
	}

	reply_header->opcode = OPCODE_PUT_BATCH;
	reply_header->total_bytes = total_bytes;
	reply_header->request_id = hdr->request_id;
}

const par_ib_call par_net_call[OPCODE_MAX] = { NULL,
					       par_ib_par_net_call_open,
					       par_ib_par_net_call_put,
					       par_ib_par_net_call_del,
					       par_ib_par_net_call_get,
					       par_ib_par_net_call_close,
					       par_ib_par_net_call_scan,
					       par_ib_par_net_call_sync,
					       par_ib_par_net_call_put_blob,
					       par_ib_par_net_call_get_blob,
					       par_ib_par_net_call_put_batch };

size_t par_ib_par_net_get_total_bytes(char *buffer)
{
	struct par_net_header *header = (struct par_net_header *)buffer;
	return header->total_bytes;
}

uint32_t par_net_header_get_opcode(char *buffer)
{
	struct par_net_header *header = (struct par_net_header *)buffer;

	if (header->opcode >= OPCODE_MAX)
		return 0;

	return header->opcode;
}

void par_ib_put_and_reply(struct server_handle *server_handle, struct par_ib_recv_slot *recv_slot)
{
	struct par_net_header *hdr = recv_slot->buf;
	struct par_ib_client_ctx *ctx = clients[hdr->request_id - 1];

	size_t total_bytes = hdr->total_bytes;
	if (total_bytes > KV_MAX_SIZE + par_net_header_size()) {
		log_fatal("Error Larger message recv buffer size is: %lu B total_bytes are: %lu B",
			  KV_MAX_SIZE + par_net_header_size(), total_bytes);
		_exit(EXIT_FAILURE);
	}

	uint32_t opcode = hdr->opcode;
	log_debug("message opcode : %u", opcode);
	if (opcode == 0) {
		log_fatal("invalid opcode");
		_exit(EXIT_FAILURE);
	}

	if (hdr->request_id == 0 || hdr->request_id > PAR_IB_MAX_CLIENTS) {
		log_fatal("Received message with invalid request_id: %u", hdr->request_id);
		_exit(EXIT_FAILURE);
	}

	struct par_ib_send_buf *send_buf = recv_slot->send_buf_ptr;
	struct par_net_header *reply_header = (struct par_net_header *)send_buf->buf;
	par_net_call[opcode](server_handle, hdr, reply_header);

	struct ibv_sge send_sge = { .addr = (uintptr_t)reply_header,
				    .length = reply_header->total_bytes,
				    .lkey = send_buf->mr->lkey };
	struct ibv_send_wr send_wr = { .wr_id = (uintptr_t)recv_slot,
				       .sg_list = &send_sge,
				       .num_sge = 1,
				       .opcode = IBV_WR_SEND,
				       .send_flags = IBV_SEND_SIGNALED };
	struct ibv_send_wr *bad_send_wr;
	if (ibv_post_send(ctx->qp, &send_wr, &bad_send_wr)) {
		perror("ibv_post_send reply");
		_exit(EXIT_FAILURE);
	}
}

int par_ib_handle_event(struct ibv_wc *wc, struct server_handle *server_handle)
{
	if (wc->status != IBV_WC_SUCCESS) {
		log_debug("Work Completion error: %s", ibv_wc_status_str(wc->status));
		return -1;
	}

	switch (wc->opcode) {
	case IBV_WC_RECV:;
		void *buf = (void *)(uintptr_t)wc->wr_id;
		struct par_ib_recv_slot *recv_slot = (struct par_ib_recv_slot *)buf;
		struct par_net_header *hdr = recv_slot->buf;
		if (hdr->inline_flag == 0) {
			struct par_ib_client_ctx *client_ctx = clients[hdr->request_id - 1];
			struct rdma_read_slot *slot = recv_slot->read_slot_ptr;
			struct rdma_read_ctx *ctx = malloc(sizeof(*ctx));
			ctx->client = client_ctx;
			ctx->size = hdr->payload_size;
			ctx->slot = slot;
			ctx->hdr = hdr;
			ctx->recv_slot = recv_slot;

			struct ibv_sge sge = { .addr = (uintptr_t)slot->buf,
					       .length = ctx->size,
					       .lkey = slot->mr->lkey };
			struct ibv_send_wr rdma_wr = {
				.wr_id = (uintptr_t)ctx,
				.opcode = IBV_WR_RDMA_READ,
				.sg_list = &sge,
				.num_sge = 1,
				.send_flags = IBV_SEND_SIGNALED,
				.wr.rdma.remote_addr = hdr->payload_buf_vaddr,
				.wr.rdma.rkey = hdr->payload_rkey,
			};
			struct ibv_send_wr *bad_wr = NULL;
			if (ibv_post_send(client_ctx->qp, &rdma_wr, &bad_wr)) {
				perror("ibv_post_send RDMA_READ");
				free(ctx);
			}
			break;
		}

		par_ib_put_and_reply(server_handle, buf);
		break;
	case IBV_WC_SEND:;
		struct par_ib_recv_slot *completed_recv = (struct par_ib_recv_slot *)(uintptr_t)wc->wr_id;
		struct par_net_header *completed_hdr = completed_recv->buf;

		struct ibv_sge srq_sge = {
			.addr = (uintptr_t)server_handle->recv_slots[completed_recv->buf_idx].buf,
			.length = PAR_IB_METADATA_SIZE + PAR_IB_MSG_SIZE,
			.lkey = server_handle->recv_slots[completed_recv->buf_idx].mr->lkey,
		};
		struct ibv_recv_wr srq_wr = {
			.wr_id = (uintptr_t)&server_handle->recv_slots[completed_recv->buf_idx],
			.sg_list = &srq_sge,
			.num_sge = 1,
		};
		struct ibv_recv_wr *bad_srq_wr;
		if (ibv_post_srq_recv(server_handle->srq, &srq_wr, &bad_srq_wr)) {
			perror("ibv_post_srq_recv repost");
			_exit(EXIT_FAILURE);
		}

		if (completed_hdr->inline_flag == 0) {
			free(completed_recv);
		}
		break;
	case IBV_WC_RDMA_READ:;
		struct rdma_read_ctx *ctx = (struct rdma_read_ctx *)(uintptr_t)wc->wr_id;
		ctx->hdr->payload_buf_vaddr = (uint64_t)ctx->slot->buf;
		recv_slot = (struct par_ib_recv_slot *)malloc(sizeof(*recv_slot));
		if (ctx->hdr->opcode == OPCODE_PUT_BLOB) {
			recv_slot->buf = ctx->recv_slot->buf;
			recv_slot->mr = ctx->recv_slot->mr;
			ctx->hdr->payload_buf_vaddr = (uint64_t)ctx->slot->buf;
		} else {
			recv_slot->buf = ctx->slot->buf;
			recv_slot->mr = ctx->slot->mr;
		}
		recv_slot->buf_idx = ctx->recv_slot->buf_idx;
		recv_slot->read_slot_ptr = ctx->slot;

		recv_slot->send_buf_ptr = ctx->recv_slot->send_buf_ptr;

		if (ctx->hdr->opcode != OPCODE_PUT && ctx->hdr->opcode != OPCODE_PUT_BLOB &&
		    ctx->hdr->opcode != OPCODE_PUT_BATCH) {
			log_fatal("Unhandled RDMA READ opcode");
		}

		free(ctx);

		par_ib_put_and_reply(server_handle, recv_slot);
		break;
	default:
		log_debug("Unhandled RDMA opcode: %d", wc->opcode);
		break;
	}
	return 0;
}

void *connection_manager_thread(void *arg)
{
	struct root_server_handle *server_handle = arg;
	struct rdma_cm_event *event;

	while (1) {
		if (rdma_get_cm_event(server_handle->ec, &event)) {
			perror("rdma_get_cm_event");
			_exit(EXIT_FAILURE);
		}
		struct rdma_cm_event event_copy;
		memcpy(&event_copy, event, sizeof(*event));
		rdma_ack_cm_event(event);

		if (par_ib_handle_cm_event(server_handle, &event_copy) < 0) {
			log_debug("par_ib_handle_cm_event failed");
			_exit(EXIT_FAILURE);
		}
	}
	return NULL;
}

int par_ib_server_start(struct root_server_handle *server_handle)
{
	if (!server_handle) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}
	uint32_t threads = server_handle->opts->threadno;

	if (pthread_create(&server_handle->cm_thread, NULL, connection_manager_thread, server_handle)) {
		perror("pthread_create for cm_thread");
		_exit(EXIT_FAILURE);
	}

	log_info("InfiniBand server is ready");

	for (uint32_t i = 0; i < threads; i++) {
		if (pthread_create(&server_handle->workers[i].thread, NULL, par_ib_worker_loop,
				   &server_handle->workers[i])) {
			perror("pthread_create for worker thread failed");
			_exit(EXIT_FAILURE);
		}
	}

	if (pthread_join(server_handle->cm_thread, NULL) != 0) {
		perror("pthread_join for cm_thread failed");
	}

	return EXIT_SUCCESS;
}

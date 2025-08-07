#include "ib_server_handle.h"

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
#define QUEUE_DEPTH 128
#define CLOSE_OP_BUF_SIZE 100
#define MATCH_ENTRY_NUM 5
#define MAX_CLIENTS 16
#define MSG_SIZE 1024

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

static uint32_t client_id_counter = 1;
struct ib_client_ctx *clients[MAX_CLIENTS];

// TODO: Move to a header file
struct par_net_header {
	uint32_t total_bytes;
	uint32_t opcode;
#ifdef USE_INFINIBAND
	uint64_t payload_buf_vaddr;
	uint64_t payload_size;
	uint64_t recv_buf_vaddr;
	uint64_t recv_buf_size;
	uint32_t request_id;
	uint32_t payload_rkey;
	uint32_t recv_buf_rkey;
	uint8_t inline_flag;
#endif
} __attribute__((packed));

struct rdma_read_ctx {
	void *buf;
	size_t size;
	struct ibv_mr *mr;
	struct par_net_header hdr;
};

long ib_server_parse_number(const char *str, const char *opt)
{
	errno = 0;
	long num = strtol(str, NULL, DECIMAL_BASE);
	if (0 == errno)
		return num;
	if (errno == EINVAL) {
		log_fatal("InfiniBand Server: Invalid number in option '%s'\n", opt);
		_exit(EXIT_FAILURE);
	}
	log_fatal("InfiniBand Server: Number out-of-range in option '%s'\n", opt);
	_exit(EXIT_FAILURE);
}

void ib_server_check_arg(int argc, int option_id)
{
	if (option_id < argc)
		return;
	log_fatal("InfiniBand Server: Option requires an argument");
	_exit(EXIT_FAILURE);
}

void ib_server_set_address(struct server_options *opts, const char *arg)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)&opts->inaddr;
	memset(addr, 0, sizeof(struct sockaddr_in));
	addr->sin_family = AF_INET;

	if (inet_pton(AF_INET, arg, &addr->sin_addr) != 1) {
		log_fatal("InfiniBand Server: Invalid IPv4 address '%s'\n", arg);
		_exit(EXIT_FAILURE);
	}
}

void ib_server_set_port(struct server_options *opts, const char *arg)
{
	long port = ib_server_parse_number(arg, "-p/--port");
	if (port < 0 || port > PORT_MAX) {
		log_fatal("InfiniBand Server: Invalid port number '%ld'\n", port);
	}
	opts->port = port;
}

struct server_options *ib_server_parse_argv_opts(int argc, char **argv)
{
	if (argc <= 1) {
		log_fatal("%s", USAGE_STRING);
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
			ib_server_check_arg(argc, ++i);
			long thrnum = ib_server_parse_number(argv[i], "-t/--threads");
			if (thrnum < 0) {
				log_fatal("InfiniBand Server: invalid thread number '%ld'\n", thrnum);
			}
			server_options->threadno = (unsigned int)thrnum;
		} else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) {
			ib_server_check_arg(argc, ++i);
			ib_server_set_port(server_options, argv[i]);
			port_set = 1;
		} else if (!strcmp(argv[i], "-b") || !strcmp(argv[i], "--bind")) {
			ib_server_check_arg(argc, ++i);
			ib_server_set_address(server_options, argv[i]);
			address_set = 1;
		} else if (!strcmp(argv[i], "-L0") || !strcmp(argv[i], "--L0_size")) {
			ib_server_check_arg(argc, ++i);
			server_options->l0_size = strtoul(argv[i], NULL, 10) * (1 << 20);
		} else if (!strcmp(argv[i], "-GF") || !strcmp(argv[i], "--GF")) {
			ib_server_check_arg(argc, ++i);
			server_options->growth_factor = strtoul(argv[i], NULL, 10);
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			log_fatal("%s\n", HELP_STRING);
		} else if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--file")) {
			ib_server_check_arg(argc, ++i);
			server_options->parallax_vol_name = strdup(argv[i]);
		} else if (!strcmp(argv[i], "-pf") || !strcmp(argv[i], "--par_format")) {
			server_options->format = 1;
		} else {
			log_fatal("InfiniBand Server: unknown option '%s'\n", argv[i]);
		}
	}

	if (port_set == 0) {
		server_options->port = DEFAULT_PORT;
	}
	if (address_set == 0) {
		ib_server_set_address(server_options, DEFAULT_ADDRESS);
	}

	return server_options;
}

struct server_handle *ib_server_handle_init(struct server_options *opts)
{
	if (!opts) {
		log_debug("InfiniBand Server: options is NULL");
		_exit(EXIT_FAILURE);
	}

	struct server_handle *handle = calloc(1UL, sizeof(struct server_handle));
	if (handle == NULL)
		_exit(EXIT_FAILURE);

	handle->opts = opts;

	handle->portals_workers = calloc(opts->threadno, sizeof(struct portals_worker *));
	if (!handle->portals_workers)
		_exit(EXIT_FAILURE);

	handle->mutex = calloc(opts->threadno, sizeof(pthread_mutex_t));
	if (!handle->mutex)
		_exit(EXIT_FAILURE);

	for (uint32_t i = 0; i < opts->threadno; ++i) {
		handle->portals_workers[i] = calloc(1UL, portals_worker_size());
		if (!handle->portals_workers[i])
			_exit(EXIT_FAILURE);
		pthread_mutex_init(&handle->mutex[i], NULL);
	}

	handle->ec = rdma_create_event_channel();
	if (!handle->ec) {
		perror("rdma_create_event_channel");
		_exit(EXIT_FAILURE);
	}

	if (rdma_create_id(handle->ec, &handle->listen_id, NULL, RDMA_PS_TCP)) {
		perror("rdma_create_id");
		_exit(EXIT_FAILURE);
	}

	struct sockaddr_in *inaddr = (struct sockaddr_in *)&opts->inaddr;
	inaddr->sin_port = htons(opts->port);

	if (rdma_bind_addr(handle->listen_id, (struct sockaddr *)inaddr)) {
		perror("rdma_bind_addr");
		_exit(EXIT_FAILURE);
	}

	if (rdma_listen(handle->listen_id, 10)) {
		perror("rdma_listen");
		_exit(EXIT_FAILURE);
	}

	handle->comp_channel = ibv_create_comp_channel(handle->listen_id->verbs);
	if (!handle->comp_channel) {
		perror("ibv_create_comp_channel");
		_exit(EXIT_FAILURE);
	}
	handle->cq = ibv_create_cq(handle->listen_id->verbs, 10, NULL, handle->comp_channel, 0);
	if (!handle->cq) {
		perror("ibv_create_cq");
		_exit(EXIT_FAILURE);
	}
	if (ibv_req_notify_cq(handle->cq, 0)) {
		perror("ibv_req_notify_cq");
		_exit(EXIT_FAILURE);
	}

	int ret;

	for (int i = 0; i < MATCH_ENTRY_NUM; i++) {
		void *raw_memory;
		ret = posix_memalign(&raw_memory, 4096, PRSV_COM_BUF_SIZE + METADATA_SIZE);

		if (ret != 0) {
			perror("posix_memalign failed");
			_exit(EXIT_FAILURE);
		}

		handle->recv_buffer[i] = (char *)raw_memory + METADATA_SIZE;

		uint32_t *pollercounter = (uint32_t *)((uintptr_t)raw_memory);
		__atomic_store_n(pollercounter, 0, __ATOMIC_RELAXED);

		uint32_t *workercounter = (uint32_t *)((uintptr_t)raw_memory + sizeof(uint32_t));
		__atomic_store_n(workercounter, 0, __ATOMIC_RELAXED);

		uint16_t *buffer_id = (uint16_t *)((uintptr_t)raw_memory + 2 * sizeof(uint32_t));
		*buffer_id = i;
	}
	if (ret != 0) {
		log_debug("posix_memalign failed");
		_exit(EXIT_FAILURE);
	}

	handle->recv_buffer_size = PRSV_COM_BUF_SIZE;

	log_info("InfiniBand server listening on %s:%ld", inet_ntoa(inaddr->sin_addr), opts->port);

	const char *error_message = NULL;
	/** initialize parallax **/
	if (opts->format) {
		log_info("Format option enabled");
		error_message = par_format((char *)(opts->parallax_vol_name), MAX_REGIONS);

		if (error_message) {
			log_fatal("%s", error_message);
			_exit(EXIT_FAILURE);
		}

	} else {
		log_info("Format option not enabled");
	}

	return handle;
}

int ib_server_print_config(struct server_handle *server_handle)
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

	printf(CONFIG_STRING, server_handle->opts->parallax_vol_name);

	return EXIT_SUCCESS;
}

int ib_handle_cm_event(struct server_handle *server_handle, struct rdma_cm_event *event)
{
	switch (event->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST: {
		struct rdma_cm_id *client_id = event->id;
		struct ibv_pd *pd = ibv_alloc_pd(client_id->verbs);
		if (!pd) {
			perror("ibv_alloc_pd");
			return -1;
		}
		struct ibv_qp_init_attr qp_attr = {
            .send_cq = server_handle->cq,
            .recv_cq = server_handle->cq,
            .qp_type = IBV_QPT_RC,
            .cap = {
                .max_send_wr = 10,
                .max_recv_wr = 10,
                .max_send_sge = 1,
                .max_recv_sge = 1,
            },
        };
		if (rdma_create_qp(client_id, pd, &qp_attr)) {
			perror("rdma_create_qp");
			return -1;
		}
		struct my_conn_metadata server_caps = {
			.max_value_size = 1024 * 512,
			.client_id = __sync_fetch_and_add(&client_id_counter, 1),
		};
		struct rdma_conn_param conn_param = {
			.private_data = &server_caps,
			.private_data_len = sizeof(server_caps),
			.responder_resources = 8,
			.initiator_depth = 8,
			.retry_count = 7,
		};
		if (rdma_accept(client_id, &conn_param)) {
			perror("rdma_accept");
			return -1;
		}
		size_t total_size = METADATA_SIZE + MSG_SIZE;
		void *buf;
		int ret = posix_memalign(&buf, sysconf(_SC_PAGESIZE), total_size);
		if (ret) {
			perror("posix_memalign");
			return -1;
		}
		struct ibv_mr *mr = ibv_reg_mr(pd, buf, total_size, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

		struct ib_client_ctx *ctx = calloc(1, sizeof(*ctx));
		if (!ctx) {
			perror("calloc");
			return -1;
		}
		ctx->id = client_id;
		ctx->pd = pd;
		ctx->cq = server_handle->cq;
		ctx->mr = mr;
		ctx->comp_channel = server_handle->comp_channel;
		ctx->buf = buf;
		ctx->qp = client_id->qp;
		ctx->server_handle = server_handle;
		client_id->context = ctx;

		clients[server_caps.client_id - 1] = ctx;

		struct ibv_sge sge = {
			.addr = (uintptr_t)ctx->buf,
			.length = total_size,
			.lkey = mr->lkey,
		};
		struct ibv_recv_wr wr = {
			.wr_id = (uintptr_t)ctx->buf,
			.sg_list = &sge,
			.num_sge = 1,
		};
		struct ibv_recv_wr *bad_wr;
		if (ibv_post_recv(client_id->qp, &wr, &bad_wr)) {
			perror("ibv_post_recv");
			return -1;
		}
		break;
	}
	case RDMA_CM_EVENT_ESTABLISHED: {
		log_debug("RDMA_CM_EVENT_ESTABLISHED");
		break;
	}
	case RDMA_CM_EVENT_DISCONNECTED: {
		log_debug("RDMA_CM_EVENT_DISCONNECTED");
		break;
	}
	default:
		log_debug("Unhandled event: %s", rdma_event_str(event->event));
		return -1;
	}
	return 0;
}

int ib_loop(struct server_handle *server_handle)
{
	struct ibv_cq *cq;
	void *cq_ctx;
	struct ibv_wc wc;

	while (1) {
		if (ibv_get_cq_event(server_handle->comp_channel, &cq, &cq_ctx)) {
			perror("ibv_get_cq_event");
			continue;
		}
		ibv_ack_cq_events(cq, 1);
		if (ibv_req_notify_cq(cq, 0)) {
			perror("ibv_req_notify_cq");
			continue;
		}
		while (ibv_poll_cq(cq, 1, &wc) > 0) {
			if (ib_handle_event(&wc, server_handle) < 0) {
				log_debug("ib_handle_event failed");
				_exit(EXIT_FAILURE);
			}
		}
	}
	return EXIT_SUCCESS;
}

void worker_scheduler(struct server_handle *server_handle, void *buf)
{
	if (server_handle->thread_to_queue == server_handle->opts->threadno)
		server_handle->thread_to_queue = 0;

	while (portals_worker_get_reqs(server_handle->portals_workers[server_handle->thread_to_queue]) >= QUEUE_DEPTH) {
		log_debug("Thread %d: REACHED MAX QUEUE_DEPTH Current", server_handle->thread_to_queue);
		server_handle->thread_to_queue++;
		if (server_handle->thread_to_queue == server_handle->opts->threadno)
			server_handle->thread_to_queue = 0;
	}
	struct portals_worker *worker = server_handle->portals_workers[server_handle->thread_to_queue];
	portals_worker_put(worker, portals_worker_create_req(buf));
	portals_worker_notify(worker);

	server_handle->thread_to_queue++;
	return;
}

inline size_t par_net_header_size(void)
{
	return sizeof(struct par_net_header);
}

static struct par_net_header *ib_par_net_call_open(struct portals_worker *portals_worker, void *args)
{
	void *start = (void *)args;
	struct par_net_header *hdr = (struct par_net_header *)start;
	struct par_net_open_req *request = (struct par_net_open_req *)((char *)start + par_net_header_size());

	par_db_options db_options = { 0 };
	db_options.options = par_get_default_options();
	db_options.db_name = par_net_open_get_dbname(request);
	db_options.create_flag = par_net_open_get_flag(request);

	db_options.volume_name = (char *)portals_worker_get_server_handle(portals_worker)->opts->parallax_vol_name;
	log_debug("Setting L0 size to %u B", portals_worker_get_server_handle(portals_worker)->opts->l0_size);
	db_options.options[LEVEL0_SIZE].value = portals_worker_get_server_handle(portals_worker)->opts->l0_size;
	log_debug("Setting growth factor to %u", portals_worker_get_server_handle(portals_worker)->opts->growth_factor);
	db_options.options[GROWTH_FACTOR].value = portals_worker_get_server_handle(portals_worker)->opts->growth_factor;

	const char *error_message = NULL;
	log_debug("Opening db with name == %s", db_options.db_name);
	par_handle handle = par_open(&db_options, &error_message);
	uint32_t total_bytes = par_net_open_rep_calc_size() + par_net_header_size();
	portals_worker_lock(portals_worker);
	char *buffer = (char *)portals_worker_get_buffer(total_bytes);
	portals_worker_unlock(portals_worker);
	struct par_net_open_rep *reply = par_net_open_rep_create(
		error_message != NULL, handle, &buffer[par_net_header_size()], total_bytes - par_net_header_size());
	if (NULL == reply) {
		log_warn("Failed to create reply");
		return NULL;
	}
	struct par_net_header *reply_header = (struct par_net_header *)buffer;
	reply_header->opcode = OPCODE_OPEN;
	reply_header->total_bytes = total_bytes;
	reply_header->request_id = hdr->request_id;
	log_debug("Ok with open reply");
	return reply_header;
}

static struct par_net_header *ib_par_net_call_put(struct portals_worker *portals_worker, void *args)
{
	void *start = (void *)args;
	struct par_net_header *hdr = (struct par_net_header *)start;
	struct par_net_put_req *request = (struct par_net_put_req *)((char *)start + par_net_header_size());

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
	struct par_put_metadata metadata = par_put((par_handle)region_id, &kv_pair, &error_message);
	log_debug("LSN is %lu", metadata.lsn);
	uint32_t total_bytes = par_net_header_size() + par_net_put_rep_calc_size();
	portals_worker_lock(portals_worker);
	char *buffer = (char *)portals_worker_get_buffer(total_bytes);
	portals_worker_unlock(portals_worker);
	struct par_net_put_rep *reply =
		par_net_put_rep_create(error_message == NULL, metadata, &buffer[par_net_header_size()], total_bytes);
	if (NULL == reply) {
		log_warn("Failed to create put reply");
		return NULL;
	}
	struct par_net_header *reply_header = (struct par_net_header *)buffer;
	reply_header->opcode = OPCODE_PUT;
	reply_header->total_bytes = total_bytes;
	reply_header->request_id = hdr->request_id;
	return reply_header;
}

static struct par_net_header *ib_par_net_call_del(struct portals_worker *portals_worker, void *args)
{
	(void)portals_worker;
	(void)args;
	log_warn("DELETE NOT IMPLEMENTED");
	return NULL;
}

static struct par_net_header *ib_par_net_call_get(struct portals_worker *portals_worker, void *args)
{
	void *start = (void *)args;
	struct par_net_header *hdr = (struct par_net_header *)start;
	struct par_net_get_req *request = (struct par_net_get_req *)((char *)start + par_net_header_size());

	uint64_t region_id = par_net_get_get_region_id(request);
	struct par_key par_key;
	par_key.size = par_net_get_get_key_size(request);
	par_key.data = par_net_get_get_key(request);
	struct par_value par_value = { 0 };

	//log_debug("key size == %lu", (unsigned long)par_key.size);

	const char *error_message = NULL;
	uint32_t total_bytes = KV_MAX_SIZE + par_net_header_size() + par_net_get_rep_header_size();
	portals_worker_lock(portals_worker);
	char *buffer = (char *)portals_worker_get_buffer(total_bytes);
	portals_worker_unlock(portals_worker);
	bool found = false;
	if (par_net_get_req_fetch_value(request)) {
		log_debug("Region id: %lu Calling par_get for key: %.*s", region_id, par_key.size, par_key.data);
		par_value.val_buffer = &buffer[par_net_header_size() + par_net_get_rep_header_size()];
		par_value.val_buffer_size = total_bytes - (par_net_header_size() + par_net_get_rep_header_size());
		log_debug("Available buffer for gets is %u", par_value.val_buffer_size);
		par_get((par_handle)region_id, &par_key, &par_value, &error_message);
		found = error_message == NULL;
	} else {
		log_debug("Region id: %lu Calling par_exists for key: %.*s", region_id, par_key.size, par_key.data);
		par_ret_code ret_code = par_exists((par_handle)region_id, &par_key);
		found = ret_code == PAR_SUCCESS;
		par_value.val_size = 0;
	}
	// log_debug("Key: %.*s --> %s", par_key.size, par_key.data, found ? "FOUND" : "NOT FOUND");
	//unsigned int hash = djb2_hash((const unsigned char *)par_value.val_buffer, par_value.val_size);
	//log_debug("got hash from get = %u", hash);
	size_t buffer_len = total_bytes - par_net_header_size();
	struct par_net_get_rep *reply =
		par_net_get_rep_set_header(found, &par_value, &buffer[par_net_header_size()], buffer_len);
	if (reply == NULL) {
		log_warn("Failed to create reply");
		return NULL;
	}
	struct par_net_header *reply_header = (struct par_net_header *)buffer;
	reply_header->opcode = OPCODE_GET;
	reply_header->total_bytes =
		par_net_header_size() + par_net_get_rep_calc_size(error_message == NULL ? par_value.val_size : 0);
	reply_header->request_id = hdr->request_id;
	return reply_header;
}

static struct par_net_header *ib_par_net_call_close(struct portals_worker *portals_worker, void *args)
{
	void *start = (void *)args;
	struct par_net_header *hdr = (struct par_net_header *)start;
	struct par_net_close_req *request = (struct par_net_close_req *)((char *)start + par_net_header_size());

	uint64_t region_id = par_net_close_get_region_id(request);

	par_handle handle = (par_handle)region_id;

	const char *error_message = par_close(handle);
	log_debug("Close DB message is %s ", error_message ? error_message : " OK !");
	uint32_t error_message_size =
		par_net_header_size() + (error_message ? strlen(error_message) + 1 : 0) + CLOSE_OP_BUF_SIZE;
	size_t buffer_len = error_message_size - par_net_header_size() + CLOSE_OP_BUF_SIZE;
	portals_worker_lock(portals_worker);
	char *buffer = (char *)portals_worker_get_buffer(error_message_size);
	portals_worker_unlock(portals_worker);

	struct par_net_close_rep *reply =
		par_net_close_rep_create(error_message, &buffer[par_net_header_size()], buffer_len);

	if (NULL == reply) {
		log_warn("Failed to create get reply");
		return NULL;
	}
	struct par_net_header *reply_header = (struct par_net_header *)buffer;
	reply_header->opcode = OPCODE_CLOSE;
	reply_header->total_bytes = error_message_size;
	reply_header->request_id = hdr->request_id;
	return reply_header;
}

static struct par_net_header *ib_par_net_call_scan(struct portals_worker *portals_worker, void *args)
{
	(void)portals_worker;
	(void)args;
	log_warn("SCAN NOT IMPLEMENTED");
	return NULL;
}

static struct par_net_header *ib_par_net_call_sync(struct portals_worker *portals_worker, void *args)
{
	(void)portals_worker;
	(void)args;
	log_warn("SYNC NOT IMPLEMENTED");
	return NULL;
}

const par_ib_call par_net_call[OPCODE_MAX] = { NULL,
					       ib_par_net_call_open,
					       ib_par_net_call_put,
					       ib_par_net_call_del,
					       ib_par_net_call_get,
					       ib_par_net_call_close,
					       ib_par_net_call_scan,
					       ib_par_net_call_sync };

size_t ib_par_net_get_total_bytes(char *buffer)
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

void *ib_put_and_reply(void *arg)
{
	struct portals_worker *portals_worker = arg;
	void *aligned_buffer_start;
	uint32_t *workercounter;
	struct server_handle *server_handle = portals_worker_get_server_handle(portals_worker);
	struct portals_worker_request *req = NULL;

	while (1) {
		req = portals_worker_poll(portals_worker);
		if (req == NULL) {
			continue;
			log_fatal("NOTHING IN THREAD QUEUE");
		}
		struct par_net_header *hdr = (struct par_net_header *)portals_worker_get_start(req);
		struct ib_client_ctx *ctx = clients[hdr->request_id - 1];

		size_t total_bytes = ib_par_net_get_total_bytes(portals_worker_get_start(req));
		if (total_bytes > server_handle->recv_buffer_size) {
			log_debug("Error Larger message recv buffer size is: %u B total_bytes are: %lu B",
				  server_handle->recv_buffer_size, total_bytes);
			break;
		}

		uint32_t opcode = par_net_header_get_opcode(portals_worker_get_start(req));
		log_debug("message opcode : %u", opcode);
		if (opcode == 0) {
			log_debug("invalid opcode");
			break;
		}

		struct par_net_header *reply_header =
			par_net_call[opcode](portals_worker, portals_worker_get_start(req));

		aligned_buffer_start = (void *)((uintptr_t)portals_worker_get_user_ptr(req));
		workercounter = (uint32_t *)((uintptr_t)aligned_buffer_start - METADATA_SIZE + sizeof(uint32_t));
		__atomic_fetch_add(workercounter, 1, __ATOMIC_RELAXED);

		portals_worker_send_reply_buff(reply_header, reply_header->total_bytes, ctx);

		struct ibv_sge sge = {
			.addr = (uintptr_t)ctx->buf,
			.length = MSG_SIZE,
			.lkey = ctx->mr->lkey,
		};
		struct ibv_recv_wr wr = {
			.wr_id = (uintptr_t)ctx->buf,
			.sg_list = &sge,
			.num_sge = 1,
		};
		struct ibv_recv_wr *bad_wr;
		if (ibv_post_recv(ctx->qp, &wr, &bad_wr)) {
			perror("ibv_post_recv");
			exit(EXIT_FAILURE);
		}
	}
	log_debug("FINISHED");
	return EXIT_SUCCESS;
}

int ib_handle_event(struct ibv_wc *wc, struct server_handle *server_handle)
{
	if (wc->status != IBV_WC_SUCCESS) {
		log_debug("Work Completion error: %s", ibv_wc_status_str(wc->status));
		return -1;
	}

	switch (wc->opcode) {
	case IBV_WC_RECV: {
		void *buf = (void *)(uintptr_t)wc->wr_id;
		struct par_net_header *hdr = (struct par_net_header *)buf;
		if (hdr->inline_flag == 0) {
			struct ib_client_ctx *client_ctx = clients[hdr->request_id - 1];
			struct rdma_read_ctx *ctx = malloc(sizeof(*ctx));
			ctx->buf = malloc(hdr->payload_size);
			ctx->size = hdr->payload_size;
			ctx->mr = ibv_reg_mr(client_ctx->pd, ctx->buf, hdr->payload_size,
					     IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
			if (!ctx->mr) {
				perror("ibv_reg_mr");
				free(ctx->buf);
				free(ctx);
				break;
			}
			ctx->hdr = *hdr;

			struct ibv_sge sge = { .addr = (uintptr_t)ctx->buf,
					       .length = ctx->size,
					       .lkey = ctx->mr->lkey };
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
			}
			break;
		}
		uint32_t *pollercounter = (uint32_t *)((uintptr_t)buf - METADATA_SIZE);
		worker_scheduler(server_handle, buf);
		__atomic_fetch_add(pollercounter, 1, __ATOMIC_RELAXED);
		break;
	}
	case IBV_WC_SEND: {
		break;
	}
	case IBV_WC_RDMA_READ: {
		struct rdma_read_ctx *ctx = (struct rdma_read_ctx *)(uintptr_t)wc->wr_id;
		struct par_net_header *hdr = &ctx->hdr;
		char *combined = NULL;
		if (hdr->opcode == OPCODE_PUT) {
			struct par_net_put_req *req = (struct par_net_put_req *)ctx->buf;
			size_t total_size = sizeof(struct par_net_header) +
					    par_net_put_req_calc_size(par_net_put_get_key_size(req),
								      par_net_put_get_value_size(req));
			combined = malloc(total_size);

			memcpy(combined, &ctx->hdr, sizeof(struct par_net_header));
			memcpy(combined + sizeof(struct par_net_header), req,
			       par_net_put_req_calc_size(par_net_put_get_key_size(req),
							 par_net_put_get_value_size(req)));
		} else {
			log_fatal("Unhandled RDMA READ opcode %d", hdr->opcode);
		}

		uint32_t *pollercounter = (uint32_t *)((uintptr_t)hdr - METADATA_SIZE);
		worker_scheduler(server_handle, combined);
		__atomic_fetch_add(pollercounter, 1, __ATOMIC_RELAXED);
		break;
	}
	default:
		log_debug("Unhandled RDMA opcode: %d", wc->opcode);
		break;
	}
	return 0;
}

void *connection_manager_thread(void *arg)
{
	struct server_handle *server_handle = arg;
	struct rdma_cm_event *event;

	while (1) {
		if (rdma_get_cm_event(server_handle->ec, &event)) {
			perror("rdma_get_cm_event");
			_exit(EXIT_FAILURE);
		}
		struct rdma_cm_event event_copy;
		memcpy(&event_copy, event, sizeof(*event));
		rdma_ack_cm_event(event);

		if (ib_handle_cm_event(server_handle, &event_copy) < 0) {
			log_debug("ib_handle_cm_event failed");
			_exit(EXIT_FAILURE);
		}
	}
	return NULL;
}

int ib_server_start(struct server_handle *server_handle)
{
	if (!server_handle) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}
	uint32_t threads = server_handle->opts->threadno;
	server_handle->thread_to_queue = 0;

	for (uint32_t i = 0; i < threads; i++) {
		server_handle->portals_workers[i] =
			portals_worker_create(server_handle, i, threads, &server_handle->mutex[i]);

		if (pthread_create(portals_worker_get_tid(server_handle->portals_workers[i]), NULL, ib_put_and_reply,
				   server_handle->portals_workers[i])) {
			for (uint32_t tmp = 0; tmp < i; ++tmp)
				pthread_cancel(*portals_worker_get_tid(server_handle->portals_workers[tmp]));
			for (uint32_t tmp = 0; tmp < i; ++tmp)
				pthread_join(*portals_worker_get_tid(server_handle->portals_workers[tmp]), NULL);
			return -(EXIT_FAILURE);
		}
	}

	pthread_t cm_thread;
	pthread_create(&cm_thread, NULL, connection_manager_thread, server_handle);

	log_debug("InfiniBand server is ready");

	if (ib_loop(server_handle) < 0) {
		log_debug("ib_loop failed");
		_exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

#include "ib_server_handle.h"

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
		} else if (!strcmp(argv[i], "-b") || !strcmp(argv[i], "--bind")) {
			ib_server_check_arg(argc, ++i);
			ib_server_set_address(server_options, argv[i]);
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
	printf("InfiniBand Server is bound to %s:%ld\n", ip_str, server_handle->opts->port);

	return EXIT_SUCCESS;
}

int ib_handle_cm_event(struct server_handle *server_handle, struct rdma_cm_event *event)
{
	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		log_debug("RDMA_CM_EVENT_ADDR_RESOLVED");
		if (rdma_resolve_route(server_handle->listen_id, 2000)) {
			perror("rdma_resolve_route");
			return -(EXIT_FAILURE);
		}
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		log_debug("RDMA_CM_EVENT_ROUTE_RESOLVED");
		if (rdma_accept(server_handle->listen_id, NULL)) {
			perror("rdma_accept");
			return -(EXIT_FAILURE);
		}
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		log_debug("RDMA_CM_EVENT_ESTABLISHED");
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
		log_debug("RDMA_CM_EVENT_DISCONNECTED");
		break;
	default:
		log_debug("Unhandled event: %s", rdma_event_str(event->event));
		return -(EXIT_FAILURE);
	}
	return EXIT_SUCCESS;
}

int ib_loop(struct server_handle *server_handle)
{
	while (1) {
		struct rdma_cm_event *event;
		if (rdma_get_cm_event(server_handle->ec, &event)) {
			perror("rdma_get_cm_event");
			return -(EXIT_FAILURE);
		}

		struct rdma_cm_event event_copy;
		memcpy(&event_copy, event, sizeof(*event));
		rdma_ack_cm_event(event);

		if (ib_handle_cm_event(server_handle, &event_copy) < 0) {
			log_debug("ib_handle_cm_event failed");
			return -(EXIT_FAILURE);
		}
	}
	return EXIT_SUCCESS;
}

void *ib_put_and_reply(void *arg)
{
}

void worker_scheduler(struct server_handle *server_handle)
{
	if (server_handle->thread_to_queue == server_handle->opts->threadno)
		server_handle->thread_to_queue = 0;

	while (portals_worker_get_reqs(server_handle->portals_workers[server_handle->thread_to_queue]) >= QUEUE_DEPTH) {
		log_debug("Thread %d: REACHED MAX QUEUE_DEPTH Current", server_handle->thread_to_queue);
		server_handle->thread_to_queue++;
		if (server_handle->thread_to_queue == server_handle->opts->threadno)
			server_handle->thread_to_queue = 0;
		//TODO: At this point if all threads are full instead of iterating over and over again,
		// we can just choose one random thread or choose the one with the least requests.
	}
	struct portals_worker *worker = server_handle->portals_workers[server_handle->thread_to_queue];
	portals_worker_put(worker, ib_worker_create_req(server_handle->wc));
	portals_worker_notify(worker);

	server_handle->thread_to_queue++;
	return;
}

int ib_handle_event(struct ibv_wc *wc, struct server_handle *handle)
{
	if (wc->status != IBV_WC_SUCCESS) {
		log_debug("RDMA Work Completion error: %s", ibv_wc_status_str(wc->status));
		return -1;
	}

	switch (wc->opcode) {
	case IBV_WC_RECV: {
		void *buf = (void *)(uintptr_t)wc->wr_id;
		uint32_t *pollercounter = (uint32_t *)((uintptr_t)buf - METADATA_SIZE);

		worker_scheduler(handle);
		__atomic_fetch_add(pollercounter, 1, __ATOMIC_RELAXED);

		break;
	}

	case IBV_WC_SEND: {
		void *user_ptr = (void *)(uintptr_t)wc->wr_id;
		uintptr_t index_start =
			(uintptr_t)user_ptr - ((uintptr_t)user_ptr % (PRSV_WORKER_BUF_SIZE + METADATA_SIZE));
		uint32_t *worker_index = (uint32_t *)(index_start);

		pthread_mutex_lock(&handle->mutex[*worker_index]);
		portals_worker_free_buf(handle->portals_workers[*worker_index], user_ptr);
		pthread_mutex_unlock(&handle->mutex[*worker_index]);

		break;
	}

	default:
		log_debug("Unhandled RDMA opcode: %d", wc->opcode);
		break;
	}

	return 0;
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

	log_debug("InfiniBand server is ready");

	if (ib_loop(server_handle) < 0) {
		log_debug("ib_loop failed");
		_exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

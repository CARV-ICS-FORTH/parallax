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
	if (handle == NULL) {
		log_debug("InfiniBand Server: handle allocation failed");
		_exit(EXIT_FAILURE);
	}

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

	log_info("InfiniBand server listening on %s:%ld", inet_ntoa(inaddr->sin_addr), opts->port);

	// const char *err = NULL;
	// if (opts->format) {
	// 	log_info("Format option enabled");
	// 	err = par_format((char *)opts->parallax_vol_name, MAX_REGIONS);
	// 	if (err) {
	// 		log_debug("par_format failed: %s", err);
	// 		_exit(EXIT_FAILURE);
	// 	}
	// } else {
	// 	log_debug("Format option not enabled");
	// }

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

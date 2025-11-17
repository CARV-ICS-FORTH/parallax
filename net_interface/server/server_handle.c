#define _GNU_SOURCE
#include "server_handle.h"
#include "../allocator/djb2.h"
#include "../par_net/par_net.h"
#include "../par_net/par_net_scan.h"
#include "../par_net/par_net_sync.h"
#include "btree/btree.h"
#include "btree/conf.h"
#include "btree/kv_pairs.h"
#include "parallax/parallax.h"
#include "parallax/structures.h"
#include "tcp_errors.h"
#include <arpa/inet.h>
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <log.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef SSL
#include "../common/common_ssl/mbedtls_utility.h"
#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#ifdef SGX
#include <openenclave/enclave.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <uthash.h>
#endif
/*** defaults ***/

#define MAGIC_INIT_NUM (0xCAFEu)
#define EPOLL_MAX_EVENTS 64

#define PORT_MAX 65536

/*** server options ***/
#define DECIMAL_BASE 10

#define USAGE_STRING                         \
	"tcp-server: no options specified\n" \
	"try 'tcp-server --help' for more information\n"

#define HELP_STRING                                                                                             \
	"Usage:\n  tcp-server <-bptf>\nOptions:\n"                                                              \
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
	" -v, --version  display version information and exit\n"                                                \
	" -pf, --par_format           (Optional) specify whether database should be formatted\n"

#define NECESSARY_OPTIONS 6

#define VERSION_STRING "tcp-server 0.1\n"

#define CONFIG_STRING           \
	"[ Server Config ]\n"   \
	"  - threads = %u\n"    \
	"  - address = %s:%u\n" \
	"  - file = %s\n"       \
	"  - flags = not yet supported\n"

#define INITIAL_NET_BUF_SIZE (KV_MAX_SIZE * 4UL)

/** server argv[] options **/

struct server_options {
	uint32_t magic_init_num;
	uint32_t threadno;
	const char *paddr; // printable ip address
	long port;
	const char *parallax_vol_name;
	struct sockaddr_storage inaddr; // ip address + port
	uint32_t l0_size;
	uint32_t growth_factor;
	uint8_t format;
};

/** server worker **/

struct worker {
	struct server_handle *server_handle;
	pthread_t tid;

	int32_t epfd;
	int32_t sock;
	uint64_t core;

	struct buffer buf;
	struct par_value pval;

	char *recv_buffer;
	size_t recv_buffer_size;
	char *send_buffer;
	size_t send_buffer_size;

#ifdef USE_PAR_NET_METRICS
  uint32_t op_count[OPCODE_MAX];
  uint32_t get_avg_key_size;
  uint32_t get_avg_value_size;
  uint32_t put_avg_key_size;
  uint32_t put_avg_value_size;
  uint32_t total_ops_count;
#endif 

};

#ifdef SSL
struct conn_info {
	int32_t fd;
	mbedtls_ssl_context *ssl_session;
	mbedtls_net_context *client_fd;
	UT_hash_handle hh;
};
#endif

/** server handle **/
struct server_handle {
	uint16_t magic_init_num;
	uint32_t flags;
	int32_t sock;
	int32_t epfd;

	par_handle par_handle;

	struct server_options *opts;
	struct worker *workers;
#ifdef SSL
	mbedtls_net_context listen_fd;
	struct conn_info *conn_ht;
	pthread_rwlock_t lock;
#endif
};

/** server request/reply **/

struct tcp_req {
	req_t type;
	kv_t kv;
	struct kv_splice_base kv_splice_base;
};

struct tcp_rep {
	retcode_t retc;
	struct par_value val;
};

_Thread_local const char *par_error_message_tl;

#define infinite_loop_start() for (;;) {
#define infinite_loop_end() }
#define event_loop_start(index, limit) for (int index = 0; index < limit; ++index) {
#define event_loop_end() }

//#define reqbuf_hdr_read_type(req, buf) req->type = *((uint8_t *)(buf))

#define MAX_REGIONS 128

/***** private functions (decl) *****/
#ifdef SSL
static void my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
	((void)level);

	mbedtls_fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
	fflush((FILE *)ctx);
}
#endif

/**
 * @brief
 *
 * @param this
 * @return int
 */
static int __handle_new_connection(struct worker *this) __attribute__((nonnull));

/**
 * @brief
 *
 * @param arg
 * @return void*
 */
static void *__handle_events(void *arg) __attribute__((nonnull));

static int __par_handle_req(struct worker *restrict worker, int client_sock, struct tcp_req *restrict req)
	__attribute__((nonnull));

/**
 * @brief
 *
 */
#ifndef SSL
static int __pin_thread_to_core(int core);
#endif

/*refactor start*/
static void server_check_arg(int argc, int option_id)
{
	if (option_id < argc)
		return;
	log_fatal("tcp-server: option requires an argument");
	_exit(EXIT_FAILURE);
}

static long server_parse_number(const char *str, const char *opt)
{
	errno = 0;
	long num = strtol(str, NULL, DECIMAL_BASE);
	if (0 == errno)
		return num;
	if (errno == EINVAL) {
		log_fatal("tcp-server: invalid number in option '%s'\n", opt);
		_exit(EXIT_FAILURE);
	}
	log_fatal("tcp-server: number out-of-range in option '%s'\n", opt);
	_exit(EXIT_FAILURE);
}

static void server_set_port(struct server_options *opts, const char *arg)
{
	long port = server_parse_number(arg, "-p/--port");
	if (port < 0 || port > PORT_MAX) {
		log_fatal("tcp-server: invalid port number '%ld'\n", port);
	}
	opts->port = port;
	((struct sockaddr_in *)(&opts->inaddr))->sin_port = htons((unsigned short)port);
}

static void server_set_address(struct server_options *opts, const char *arg)
{
	int is_v6 = strchr(arg, ':') != NULL;
	opts->inaddr.ss_family = is_v6 ? AF_INET6 : AF_INET;
	size_t off = is_v6 ? offsetof(struct sockaddr_in6, sin6_addr) : offsetof(struct sockaddr_in, sin_addr);
	if (!inet_pton(opts->inaddr.ss_family, arg, (char *)(&opts->inaddr) + off)) {
		log_fatal("tcp-server: invalid address '%s'\n", arg);
	}
	opts->paddr = arg;
}

struct server_options *server_parse_argv_opts(int argc, char *restrict *restrict argv)
{
	if (argc <= 1) {
		log_fatal("%s", USAGE_STRING);
		_exit(EXIT_FAILURE);
	}

	struct server_options *server_options = calloc(1UL, sizeof(*server_options));
	if (!server_options) {
		log_fatal("tcp-server: memory allocation failed");
		_exit(EXIT_FAILURE);
	}
	server_options->magic_init_num = MAGIC_INIT_NUM;

	int opt_num = 0;

	for (int i = 1; i < argc; ++i) {
		if (argv[i][0] != '-') {
			log_fatal("tcp-server: unknown option '%s'\n", argv[i]);
		}

		if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--threads")) {
			server_check_arg(argc, ++i);
			long thrnum = server_parse_number(argv[i], "-t/--threads");
			if (thrnum < 0) {
				log_fatal("tcp-server: invalid thread number '%ld'\n", thrnum);
			}
			server_options->threadno = (unsigned int)thrnum;
			++opt_num;
		} else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) {
			server_check_arg(argc, ++i);
			server_set_port(server_options, argv[i]);
			++opt_num;
		} else if (!strcmp(argv[i], "-b") || !strcmp(argv[i], "--bind")) {
			server_check_arg(argc, ++i);
			server_set_address(server_options, argv[i]);
			++opt_num;
		} else if (!strcmp(argv[i], "-L0") || !strcmp(argv[i], "--L0_size")) {
			server_check_arg(argc, ++i);
			server_options->l0_size = strtoul(argv[i], NULL, 10) * (1 << 20);
			++opt_num;
		} else if (!strcmp(argv[i], "-GF") || !strcmp(argv[i], "--GF")) {
			server_check_arg(argc, ++i);
			server_options->growth_factor = strtoul(argv[i], NULL, 10);
			++opt_num;
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			log_fatal("%s\n", HELP_STRING);
		} else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
			log_fatal("%s\n", VERSION_STRING);
		} else if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--file")) {
			server_check_arg(argc, ++i);
			server_options->parallax_vol_name = strdup(argv[i]);
			++opt_num;
		} else if (!strcmp(argv[i], "-pf") || !strcmp(argv[i], "--par_format")) {
			server_options->format = 1;
		} else {
			log_fatal("tcp-server: unknown option '%s'\n", argv[i]);
		}
	}

	if (opt_num != NECESSARY_OPTIONS) {
		log_fatal("%s\n", HELP_STRING);
		_exit(EXIT_FAILURE);
	}
	return server_options;
}

/*refactor end*/

int server_print_config(struct server_handle *server_handle)
{
	if (!server_handle) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}

	if (server_handle->magic_init_num != MAGIC_INIT_NUM) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}

	printf(CONFIG_STRING, server_handle->opts->threadno, server_handle->opts->paddr,
	       ntohs(((struct sockaddr_in *)(&server_handle->opts->inaddr))->sin_port),
	       server_handle->opts->parallax_vol_name);

	return EXIT_SUCCESS;
}

#ifdef SSL
int configure_server_ssl(mbedtls_ssl_config *conf, mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_x509_crt *server_cert,
			 mbedtls_pk_context *pkey)
{
	int ret = 1;

	ret = generate_certificate_and_pkey(server_cert, pkey);
	if (ret != 0) {
		log_fatal("generate_certificate_and_pkey failed with %d\n", ret);
		goto exit;
	}

	if ((ret = mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
					       MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		log_fatal("mbedtls_ssl_config_defaults returned %d\n", ret);
		goto exit;
	}

	mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);
	mbedtls_ssl_conf_dbg(conf, my_debug, stdout);

	mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
	mbedtls_ssl_conf_ca_chain(conf, server_cert->next, NULL);

	if ((ret = mbedtls_ssl_conf_own_cert(conf, server_cert, pkey)) != 0) {
		log_fatal("mbedtls_ssl_conf_own_cert returned %d\n", ret);
		goto exit;
	}

	ret = 0;
exit:
	fflush(stdout);
	return ret;
}
#endif

#ifdef SSL
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_config conf;
mbedtls_x509_crt server_cert;
mbedtls_pk_context pkey;
const char *pers = "tls_server";
#endif

struct server_handle *server_handle_init(struct server_options *server_options)
{
	if (!server_options) {
		log_fatal("server options is NULL");
		_exit(EXIT_FAILURE);
	}

	if (server_options->magic_init_num != MAGIC_INIT_NUM) {
		errno = EINVAL;
		log_fatal("This is NOT a server_options object!");
		_exit(EXIT_FAILURE);
	}

	struct server_handle *server_handle =
		calloc(1UL, sizeof(struct server_handle) + (server_options->threadno * sizeof(struct worker)));
	if (server_handle == NULL)
		_exit(EXIT_FAILURE);

	server_handle->opts = server_options;
	server_handle->workers = (struct worker *)((char *)(server_handle) + sizeof(struct server_handle));
	server_handle->sock = -1;
	server_handle->epfd = -1;
	log_debug("Net buffer initialized");
#ifdef SSL
	if (pthread_rwlock_init(&server_handle->lock, NULL) != 0) {
		return -(EXIT_FAILURE);
	}

	/* Load host resolver and socket interface modules explicitly */
#ifdef SGX
	if (load_oe_modules() != OE_OK) {
		log_fatal("loading required Open Enclave modules failed\n");
		goto cleanup;
	}
#endif

	server_handle->conn_ht = NULL;
	// init mbedtls objects
	int ret = 0;
	char port_str[10];
	sprintf(port_str, "%ld", sconf->port);
	mbedtls_net_init(&server_handle->listen_fd);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&server_cert);
	mbedtls_pk_init(&pkey);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
#ifdef SGX
	oe_verifier_initialize();
#endif

	if ((ret = mbedtls_net_bind(&server_handle->listen_fd, sconf->paddr, port_str, MBEDTLS_NET_PROTO_TCP)) != 0) {
		log_fatal("mbedtls_net_bind returned %d\n", ret);
		goto cleanup;
	}
	server_handle->sock = server_handle->listen_fd.fd;
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers,
					 strlen(pers))) != 0) {
		log_fatal("mbedtls_ctr_drbg_seed returned %d\n", ret);
		goto cleanup;
	}
	// Configure server SSL settings
	ret = configure_server_ssl(&conf, &ctr_drbg, &server_cert, &pkey);
	if (ret != 0) {
		log_fatal("configure_server_ssl returned %d\n", ret);
		goto cleanup;
	}
#else
	sa_family_t fam = server_options->inaddr.ss_family;

	if ((server_handle->sock = socket(fam, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)) < 0) {
		log_fatal("Failed to create socket");
		goto cleanup;
	}

	int opt = 1;
	setsockopt(server_handle->sock, SOL_SOCKET, SO_REUSEADDR, &opt,
		   sizeof(opt)); /** TODO: remove, only for debug purposes! */

	if (bind(server_handle->sock, (struct sockaddr *)(&server_options->inaddr),
		 (fam == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) < 0) {
		log_fatal("Failed to bind socket");
		perror("Reason:");
		goto cleanup;
	}

	if (listen(server_handle->sock, TT_MAX_LISTEN) < 0)
		goto cleanup;
#endif
	if ((server_handle->epfd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
		log_fatal("epoll failed");
		perror("Reason:");
		goto cleanup;
	}

	struct epoll_event epev = { .events = EPOLLIN | EPOLLRDHUP | EPOLLONESHOT, .data.fd = server_handle->sock };

	if (epoll_ctl(server_handle->epfd, EPOLL_CTL_ADD, server_handle->sock, &epev) < 0) {
		log_fatal("epoll_ctl failed");
		goto cleanup;
	}

	const char *error_message = NULL;
	/** initialize parallax **/
	if (server_handle->opts->format) {
		log_info("Format option enabled");
		error_message = par_format((char *)(server_options->parallax_vol_name), MAX_REGIONS);

		if (error_message) {
			log_fatal("%s", error_message);
			_exit(EXIT_FAILURE);
		}

	} else {
		log_info("Format option not enabled");
	}

	/*
  par_db_options db_options = { .volume_name = (char *)(sconf->dbpath), // fuck clang_format!
				      .create_flag = PAR_CREATE_DB,
				      .db_name = "tcp_server_par.db",
				      .options = par_get_default_options() };
	db_options.options[LEVEL0_SIZE].value = level0_size;
	db_options.options[GROWTH_FACTOR].value = GF;
	log_info("Initializing Parallax DBs with L0 %u and GF %u", level0_size, GF);
	char actual_db_name[128] = { 0 };
	for (int i = 0; i < MAX_PARALLAX_DBS; i++) {
		if (snprintf(actual_db_name, sizeof(actual_db_name), "tcp_server_par_%d", i) < 0) {
			log_fatal("Failed to construct db name");
			return -(EXIT_FAILURE);
		}
		db_options.db_name = actual_db_name;
		server_handle->par_handle[i] = par_open(&db_options, &error_message);
	}
*/

	server_handle->magic_init_num = MAGIC_INIT_NUM;

	return server_handle;

cleanup:
#ifdef SSL
	mbedtls_net_free(&server_handle->listen_fd);
	mbedtls_x509_crt_free(&server_cert);
	mbedtls_pk_free(&pkey);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
#ifdef SGX
	oe_verifier_shutdown();
#endif
#endif
	close(server_handle->sock);
	close(server_handle->epfd);
	free(server_handle);
	return NULL;
}

int server_handle_destroy(struct server_handle *server_handle)
{
	if (!server_handle || server_handle->magic_init_num != MAGIC_INIT_NUM) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}

	/** END OF ERROR HANDLING **/

	// signal all threads to cancel
#ifdef SSL
	mbedtls_net_free(&server_handle->listen_fd);
	mbedtls_x509_crt_free(&server_cert);
	mbedtls_pk_free(&pkey);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
#ifdef SGX
	oe_verifier_shutdown();
#endif
#endif

	close(server_handle->sock);
	close(server_handle->epfd);
	munmap(server_handle->workers[0].buf.mem, server_handle->opts->threadno * DEF_BUF_SIZE);
	free(server_handle->opts);

	const char *error_message = par_close(server_handle->par_handle);

	if (error_message) {
		log_fatal("%s", error_message);
		return -(EXIT_FAILURE);
	}

	free(server_handle);

	return EXIT_SUCCESS;
}

int server_spawn_threads(struct server_handle *server_handle)
{
	if (!server_handle) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}

	if (server_handle->magic_init_num != MAGIC_INIT_NUM) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}

	/** END OF ERROR HANDLING **/

	uint32_t threads = server_handle->opts->threadno;

	if ((server_handle->workers[0].buf.mem = mmap(NULL, threads * DEF_BUF_SIZE, PROT_READ | PROT_WRITE,
						      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0UL)) == MAP_FAILED)
		return -(EXIT_FAILURE);

	uint32_t index;

	for (index = 0U, --threads; index < threads; ++index) {
		server_handle->workers[index].core = index;
		server_handle->workers[index].sock = server_handle->sock;
		server_handle->workers[index].epfd = server_handle->epfd;
		// server_handle->workers[index].par_handle = server_handle->par_handle;
		server_handle->workers[index].server_handle = server_handle;
		server_handle->workers[index].buf.bytes = DEF_BUF_SIZE;
		server_handle->workers[index].buf.mem = server_handle->workers[0].buf.mem + (index * DEF_BUF_SIZE);
		server_handle->workers[index].pval.val_size = 0U;
		server_handle->workers[index].pval.val_buffer_size = KV_MAX_SIZE;
		server_handle->workers[index].pval.val_buffer =
			server_handle->workers[index].buf.mem + TT_REPHDR_SIZE; // [!] one shared buffer per thread!

		if (pthread_create(&server_handle->workers[index].tid, NULL, __handle_events,
				   server_handle->workers + index)) { // one of the server threads failed!
			uint32_t tmp;

			/* kill all threads that have been created by now */
			for (tmp = 0; tmp < index; ++tmp)
				pthread_cancel(server_handle->workers[tmp].tid);

			for (tmp = 0; tmp < index; ++tmp)
				pthread_join(server_handle->workers[tmp].tid, NULL);

			munmap(server_handle->workers[0].buf.mem, threads * DEF_BUF_SIZE);

			return -(EXIT_FAILURE);
		}
	}

	// convert 'main()-thread' to 'server-thread'

	server_handle->workers[index].core = index;
	server_handle->workers[index].tid = pthread_self();
	server_handle->workers[index].sock = server_handle->sock;
	server_handle->workers[index].epfd = server_handle->epfd;
	// server_handle->workers[index].par_handle = server_handle->par_handle;
	server_handle->workers[index].server_handle = server_handle;
	server_handle->workers[index].buf.bytes = DEF_BUF_SIZE;
	server_handle->workers[index].buf.mem = server_handle->workers[0].buf.mem + (index * DEF_BUF_SIZE);
	server_handle->workers[index].pval.val_size = 0U;
	server_handle->workers[index].pval.val_buffer_size = KV_MAX_SIZE;
	server_handle->workers[index].pval.val_buffer = server_handle->workers[index].buf.mem + TT_REPHDR_SIZE;

	__handle_events(server_handle->workers + index);

	return EXIT_SUCCESS;
}

/***** private functions *****/

static int __handle_new_connection(struct worker *this)
{
	// struct sockaddr_storage caddr = { 0 };
	struct epoll_event epev = { 0 };

	// socklen_t socklen = { 0 };
	int tmpfd = 0;

	if (fcntl(this->sock, F_SETFL, O_NONBLOCK) == -1) {
		perror("fcntl nonblock failure");
		return -(EXIT_FAILURE);
	}

	if (fcntl(this->sock, F_SETFD, FD_CLOEXEC) == -1) {
		perror("fcntl cloexec failure");
		return -(EXIT_FAILURE);
	}
#ifdef SSL
	int ret;
	mbedtls_ssl_context *ssl_session = malloc(sizeof(mbedtls_ssl_context));
	if (ssl_session == NULL) {
		return -(EXIT_FAILURE);
	}
	mbedtls_ssl_init(ssl_session);
	if ((ret = mbedtls_ssl_setup(ssl_session, &conf)) != 0) {
		log_fatal("mbedtls_ssl_setup returned %d\n", ret);
		free(ssl_session);
		return -(EXIT_FAILURE);
	}
	mbedtls_net_context *client_fd = malloc(sizeof(mbedtls_net_context));
	if (client_fd == NULL) {
		log_fatal("malloc of mbedtls_net_context failed");
		return -(EXIT_FAILURE);
	}
	if ((tmpfd = mbedtls_net_accept(&this->server_handle->listen_fd, client_fd, NULL, 0, NULL)) < 0) {
		log_fatal("mbedtls_net_accept failed with %s", strerror(errno));
		free(ssl_session);
		free(client_fd);
		return -(EXIT_FAILURE);
	}
	tmpfd = client_fd->fd;
	mbedtls_net_set_nonblock(client_fd);
	mbedtls_ssl_set_bio(ssl_session, client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
	while ((ret = mbedtls_ssl_handshake(ssl_session)) != 0) {
		if (ret == MBEDTLS_ERR_SSL_CONN_EOF) {
			free(ssl_session);
			free(client_fd);
			return -(EXIT_FAILURE);
		}
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			log_fatal("mbedtls_ssl_handshake returned -0x%x\n", -ret);
			free(ssl_session);
			free(client_fd);
			return -(EXIT_FAILURE);
		}
	}

	/*Add (fd, ssl_session) pair to ht*/
	struct conn_info *conn_info = malloc(sizeof(struct conn_info));
	if (conn_info == NULL)
		exit(EXIT_FAILURE);
	conn_info->fd = client_fd->fd;
	conn_info->ssl_session = ssl_session;
	conn_info->client_fd = client_fd;
	if (pthread_rwlock_wrlock(&this->server_handle->lock) != 0)
		exit(EXIT_FAILURE);
	HASH_ADD_INT(this->server_handle->conn_ht, fd, conn_info);
	pthread_rwlock_unlock(&this->server_handle->lock);

#else
	if ((tmpfd = accept(this->sock, NULL, NULL)) < 0) {
		log_fatal("%s", strerror(errno));
		perror("Error is ");
		return -(EXIT_FAILURE);
	}
#endif

	epev.data.fd = tmpfd;
	epev.events = EPOLLIN | EPOLLONESHOT;

	if (epoll_ctl(this->epfd, EPOLL_CTL_ADD, tmpfd, &epev) < 0) {
		perror("__handle_new_connection::epoll_ctl(ADD)");
		close(tmpfd);
#ifdef SSL
		free(ssl_session);
		free(client_fd);
#endif
		return -(EXIT_FAILURE);
	}

	epev.events = EPOLLIN | EPOLLONESHOT;
	epev.data.fd = this->sock;
	/** rearm server socket **/

	if (epoll_ctl(this->epfd, EPOLL_CTL_MOD, this->sock, &epev) < 0) {
		log_fatal("epoll_ctl(): %s ---> terminating server!!!", strerror(errno));

		epoll_ctl(this->epfd, EPOLL_CTL_DEL, tmpfd, NULL);
		close(this->sock);
		close(tmpfd);
#ifdef SSL
		free(ssl_session);
		free(client_fd);
#endif
		exit(EXIT_FAILURE);
	}
	return EXIT_SUCCESS;
}

static void *__handle_events(void *arg)
{
	struct worker *worker = arg;
#ifndef SSL
	if (__pin_thread_to_core(worker->core) < 0) {
		log_fatal("__pin_thread_to_core(): %s", strerror(errno));
		_exit(EXIT_FAILURE);
	}
#endif

	/*
          uint32_t key_size = *(uint32_t *)(&this->buf.mem[1]);
          uint32_t value_size = *(uint32_t *)(&this->buf.mem[5]);
          struct tcp_req req = { .kv_splice_base.kv_cat =
     calculate_KV_category(key_size, value_size, insertOp),
                                 .kv_splice_base.kv_splice = (void
     *)(this->buf.mem + 1UL) };
  */
	struct tcp_req req = { 0 };

	int events;
	int client_sock;
	int event_bits;

	struct epoll_event rearm_event = { .events = EPOLLIN | EPOLLRDHUP | EPOLLONESHOT };
	struct epoll_event epoll_events[EPOLL_MAX_EVENTS];
	worker->recv_buffer = calloc(1UL, INITIAL_NET_BUF_SIZE);
	worker->recv_buffer_size = INITIAL_NET_BUF_SIZE;
	worker->send_buffer = calloc(1UL, INITIAL_NET_BUF_SIZE);
	worker->send_buffer_size = INITIAL_NET_BUF_SIZE;

#ifdef USE_PAR_NET_METRICS
  memset(worker->op_count, 0, sizeof(worker->op_count));
  worker->get_avg_key_size = 0;
  worker->get_avg_value_size = 0;
  worker->put_avg_key_size = 0;
  worker->put_avg_value_size = 0;
  worker->total_ops_count = 0;
#endif


	infinite_loop_start();

	events = epoll_wait(worker->epfd, epoll_events, EPOLL_MAX_EVENTS, -1);

	if (unlikely(events < 0)) {
		// log_fatal("epoll(): %s", strerror(errno));
		continue;
	}

	event_loop_start(evindex, events);

	client_sock = epoll_events[evindex].data.fd;
	event_bits = epoll_events[evindex].events;

	if (event_bits & EPOLLRDHUP) {
		/** received FIN from client **/

		log_info("client (%d) wants to terminate the connection", client_sock);

		// the server can send some more packets here. If so, client code needs some
		// changes

		shutdown(client_sock, SHUT_WR);
		log_info("terminating connection with client(%d)", client_sock);

		epoll_ctl(worker->epfd, EPOLL_CTL_DEL, client_sock, NULL); // kernel 2.6+
		close(client_sock);
#ifdef SSL
		struct conn_info *conn_info;
		if (pthread_rwlock_wrlock(&this->server_handle->lock) != 0) {
			continue;
		}
		HASH_FIND_INT(this->server_handle->conn_ht, &client_sock, conn_info);
		free(conn_info->ssl_session);
		free(conn_info->client_fd);
		HASH_DEL(this->server_handle->conn_ht, conn_info);
		pthread_rwlock_unlock(&this->server_handle->lock);
#endif
	} else if (likely(event_bits & EPOLLIN)) /** read event **/
	{
		/** new connection **/
		if (client_sock == worker->sock) {
			log_debug("new connection");

			if (__handle_new_connection(worker) < 0)
				log_fatal("__handle_new_connection() failed: %s\n", strerror(errno));

			continue;
		}

		/** end **/

		/** request **/
		if (unlikely(__par_handle_req(worker, client_sock, &req) < 0L)) {
			log_fatal("__par_handle_req(): %s", strerror(errno));
			goto client_error;
		}

		/* re-enable getting INPUT-events from the coresponding client */

		rearm_event.data.fd = client_sock;
		epoll_ctl(worker->epfd, EPOLL_CTL_MOD, client_sock, &rearm_event);

		continue;

	client_error:
		epoll_ctl(worker->epfd, EPOLL_CTL_DEL, client_sock, NULL); // kernel 2.6+
		close(client_sock);
#ifdef SSL
		struct conn_info *conn_info;
		if (pthread_rwlock_wrlock(&this->server_handle->lock) != 0) {
			continue;
		}
		HASH_FIND_INT(this->server_handle->conn_ht, &client_sock, conn_info);
		free(conn_info->ssl_session);
		free(conn_info->client_fd);
		HASH_DEL(this->server_handle->conn_ht, conn_info);
		pthread_rwlock_unlock(&this->server_handle->lock);
#endif
	} else if (unlikely(event_bits & EPOLLERR)) /** error **/
	{
		log_fatal("events[%d] = EPOLLER, fd = %d\n", evindex, client_sock);
		/** TODO: error handling */
		continue;
	}

	event_loop_end();
	infinite_loop_end();

	__builtin_unreachable();
}

inline size_t par_net_header_calc_size(void)
{
	return sizeof(struct par_net_header);
}

uint32_t par_net_header_get_opcode(char *buffer)
{
	struct par_net_header *header = (struct par_net_header *)buffer;

	if (header->opcode >= OPCODE_MAX)
		return 0;

	return header->opcode;
}

static size_t par_net_get_total_bytes(char *buffer)
{
	struct par_net_header *header = (struct par_net_header *)buffer;
	return header->total_bytes;
}

static struct par_net_header *par_net_call_open(struct worker *worker, void *args)
{
	(void)args;
	struct par_net_open_req *request = (struct par_net_open_req *)&worker->recv_buffer[par_net_header_calc_size()];

	par_db_options db_options = { 0 };
	db_options.options = par_get_default_options(); 
	db_options.db_name = par_net_open_get_dbname(request);
	db_options.create_flag = par_net_open_get_flag(request);

	db_options.volume_name = (char *)worker->server_handle->opts->parallax_vol_name;
	log_debug("Setting L0 size to %u B", worker->server_handle->opts->l0_size);
	db_options.options[LEVEL0_SIZE].value = worker->server_handle->opts->l0_size;
	log_debug("Setting growth factor to %u", worker->server_handle->opts->growth_factor);
	db_options.options[GROWTH_FACTOR].value = worker->server_handle->opts->growth_factor;

	const char *error_message = NULL;
	log_debug("Opening db with name == %s", db_options.db_name);
	par_handle handle = par_open(&db_options, &error_message);

	struct par_net_open_rep *reply = par_net_open_rep_create(error_message != NULL, handle,
								 &worker->send_buffer[par_net_header_calc_size()],
								 worker->send_buffer_size - par_net_header_calc_size());
	if (NULL == reply) {
		log_warn("Failed to create reply");
		return NULL;
	}
	struct par_net_header *reply_header = (struct par_net_header *)worker->send_buffer;
	reply_header->opcode = OPCODE_OPEN;
	reply_header->total_bytes = par_net_open_rep_calc_size() + par_net_header_calc_size();
	log_debug("Ok with open reply");
	return reply_header;
}

static struct par_net_header *par_net_call_put(struct worker *worker, void *args)
{
	(void)args;
	struct par_net_put_req *request = (struct par_net_put_req *)&worker->recv_buffer[par_net_header_calc_size()];

	struct par_key_value kv_pair = { 0 };
	uint64_t region_id = par_net_put_get_region_id(request);
	kv_pair.k.size = par_net_put_get_key_size(request);
	kv_pair.v.val_size = par_net_put_get_value_size(request);
	kv_pair.k.data = par_net_put_get_key(request);
	kv_pair.v.val_buffer = par_net_put_get_value(request);
	kv_pair.v.val_buffer_size = par_net_put_get_value_size(request);

	// log_debug("Key size =  %lu", (unsigned long)kv_pair.k.size);
	// log_debug("Value size = %lu", (unsigned long)kv_pair.v.val_buffer_size);

#ifdef USE_PAR_NET_METRICS
  worker->put_avg_key_size += kv_pair.k.size;
  worker->put_avg_value_size += kv_pair.v.val_size;
#endif


	const char *error_message = NULL;
	struct par_put_metadata metadata = par_put((par_handle)region_id, &kv_pair, &error_message);
	log_debug("LSN is %lu", metadata.lsn);
	size_t buffer_len = worker->send_buffer_size - par_net_header_calc_size();
	struct par_net_put_rep *reply = par_net_put_rep_create(
		error_message == NULL, metadata, &worker->send_buffer[par_net_header_calc_size()], buffer_len);
	if (NULL == reply) {
		log_warn("Failed to create put reply");
		return NULL;
	}
	struct par_net_header *reply_header = (struct par_net_header *)worker->send_buffer;
	reply_header->opcode = OPCODE_PUT;
	reply_header->total_bytes = par_net_header_calc_size() + par_net_put_rep_calc_size();
	return reply_header;
}

static struct par_net_header *par_net_call_del(struct worker *worker, void *args)
{
	(void)args;

	struct par_net_del_req *request = (struct par_net_del_req *)(&worker->recv_buffer[par_net_header_calc_size()]);

	struct par_key key = { 0 };
	uint64_t region_id = par_net_del_get_region_id(request);
	key.size = par_net_del_get_key_size(request);
	key.data = par_net_del_get_key(request);

	const char *error_message = NULL;
	par_delete((par_handle)region_id, &key, &error_message);

	size_t buffer_len = worker->recv_buffer_size - par_net_header_calc_size();
	struct par_net_del_rep *reply = par_net_del_rep_create(
		error_message != NULL, &worker->recv_buffer[par_net_del_rep_calc_size()], buffer_len);
	if (NULL == reply) {
		log_fatal("Failed to create reply for delete operation");
		_exit(EXIT_FAILURE);
	}
	struct par_net_header *reply_header = (struct par_net_header *)worker->recv_buffer;
	reply_header->opcode = OPCODE_DEL;
	reply_header->total_bytes = par_net_header_calc_size() + par_net_del_rep_calc_size();
	return reply_header;
}

static struct par_net_header *par_net_call_get(struct worker *worker, void *args)
{
	(void)args;
	struct par_net_get_req *request = (struct par_net_get_req *)&worker->recv_buffer[par_net_header_calc_size()];

	uint64_t region_id = par_net_get_get_region_id(request);
	struct par_key par_key;
	par_key.size = par_net_get_get_key_size(request);
	par_key.data = par_net_get_get_key(request);

	struct par_value par_value = { 0 };

	// log_debug("key size == %lu", (unsigned long)par_key.size);
	const char *error_message = NULL;

	bool found = false;
	if (par_net_get_req_fetch_value(request)) {
		// log_debug("Region id: %lu Calling par_get for key: %.*s", region_id, par_key.size, par_key.data);
		par_value.val_buffer = &worker->send_buffer[par_net_header_calc_size() + par_net_get_rep_header_size()];
		par_value.val_buffer_size =
			worker->send_buffer_size - (par_net_header_calc_size() + par_net_get_rep_header_size());
		// log_debug("Available buffer for gets is %u", par_value.val_buffer_size);
		par_get((par_handle)region_id, &par_key, &par_value, &error_message);
		found = error_message == NULL;
	} else {
		log_debug("Region id: %lu Calling par_exists for key: %.*s", region_id, par_key.size, par_key.data);
		par_ret_code ret_code = par_exists((par_handle)region_id, &par_key);
		found = ret_code == PAR_SUCCESS;
		par_value.val_size = 0;
	}
	// log_debug("Key: %.*s --> %s", par_key.size, par_key.data, found ? "FOUND" : "NOT FOUND");
  
#ifdef USE_PAR_NET_METRICS
  worker->get_avg_key_size += par_key.size;

  if(found)
    worker->get_avg_value_size += par_value.val_size;
#endif

	size_t buffer_len = worker->send_buffer_size - par_net_header_calc_size();
	struct par_net_get_rep *reply = par_net_get_rep_set_header(
		found, &par_value, &worker->send_buffer[par_net_header_calc_size()], buffer_len);
	if (reply == NULL) {
		log_warn("Failed to create reply");
		return NULL;
	}
	struct par_net_header *reply_header = (struct par_net_header *)worker->send_buffer;
	reply_header->opcode = OPCODE_GET;
	reply_header->total_bytes =
		par_net_header_calc_size() + par_net_get_rep_calc_size(error_message == NULL ? par_value.val_size : 0);
	return reply_header;
}

static struct par_net_header *par_net_call_sync(struct worker *worker, void *args)
{
	(void)args;
	struct par_net_sync_req *sync_request =
		(struct par_net_sync_req *)&worker->recv_buffer[par_net_header_calc_size()];
	uint64_t region_id = par_net_sync_req_get_region_id(sync_request);
	par_ret_code ret = par_sync((par_handle)region_id);
	struct par_net_sync_rep *sync_reply =
		par_net_sync_rep_create(ret, region_id, &worker->send_buffer[par_net_header_calc_size()],
					worker->send_buffer_size - par_net_header_calc_size());
	if (NULL == sync_reply) {
		log_fatal("Failed to create sync reply");
		_exit(EXIT_FAILURE);
	}
	struct par_net_header *reply = (struct par_net_header *)worker->send_buffer;
	reply->opcode = OPCODE_SYNC;
	reply->total_bytes = par_net_header_calc_size() + par_net_sync_rep_calc_size();
	return reply;
}

static struct par_net_header *par_net_call_scan(struct worker *worker, void *args)
{
	(void)args;
	struct par_net_scan_req *request = (struct par_net_scan_req *)&worker->recv_buffer[par_net_header_calc_size()];
	uint64_t region_id = par_net_scan_req_get_region_id(request);

	const char *error_message = NULL;
	struct par_key key = { .size = par_net_scan_req_get_key_size(request),
			       .data = par_net_scan_req_get_key(request) };

	// log_debug("Scan for DB: %s seek key size:%u payload: %.*s mode is: %s",
	// 	  par_get_db_name((par_handle)region_id, &error), key.size, key.size, key.data,
	// 	  par_net_scan_req_get_seek_mode(request) == PAR_GREATER_OR_EQUAL ? "PAR_GREATER_OR_EQUAL" :
	// 									    "PAR_GREATER");

	struct par_net_scan_rep *reply = par_net_scan_rep_create(par_net_scan_req_get_max_entries(request),
								 &worker->send_buffer[par_net_header_calc_size()],
								 worker->send_buffer_size - par_net_header_calc_size());

	par_scanner dev_scanner =
		par_init_scanner((par_handle)region_id, &key, par_net_scan_req_get_seek_mode(request), &error_message);
	if (error_message) {
		log_fatal("Error: %s", error_message);
		_exit(EXIT_FAILURE);
	}

	while (par_is_valid(dev_scanner)) {
		struct par_key scan_key = par_get_key(dev_scanner);
		struct par_value scan_value = par_get_value(dev_scanner);
		if (false == par_net_scan_rep_append_splice(reply, scan_key.size, scan_key.data, scan_value.val_size,
							    scan_value.val_buffer))
			break;
		par_get_next(dev_scanner);
	}
	par_net_scan_rep_set_valid(reply, par_is_valid(dev_scanner));
	par_close_scanner(dev_scanner);

	struct par_net_header *header = (struct par_net_header *)worker->send_buffer;
	header->opcode = OPCODE_SCAN;
	header->total_bytes = par_net_header_calc_size() + par_net_scan_rep_get_size(reply);
	// log_debug("Scan DONE entries retrieved = %u total reply size: %u max send buffer size: %lu",
	// 	  par_net_scan_rep_get_num_entries(reply), header->total_bytes, worker->send_buffer_size);
	return header;
}

static struct par_net_header *par_net_call_close(struct worker *worker, void *args)
{
	(void)args;
	struct par_net_close_req *request =
		(struct par_net_close_req *)&worker->recv_buffer[par_net_header_calc_size()];

	uint64_t region_id = par_net_close_get_region_id(request);

	par_handle handle = (par_handle)region_id;

	const char *error_mesage = par_close(handle);
	log_debug("Close DB message is %s ", error_mesage ? error_mesage : " OK !");
	uint32_t error_message_size = error_mesage ? strlen(error_mesage) + 1 : 0;
	size_t buffer_len = worker->send_buffer_size - par_net_header_calc_size();
	struct par_net_close_rep *reply =
		par_net_close_rep_create(error_mesage, &worker->send_buffer[par_net_header_calc_size()], buffer_len);
	if (NULL == reply) {
		log_warn("Failed to create get reply");
		return NULL;
	}
	struct par_net_header *reply_header = (struct par_net_header *)worker->send_buffer;
	reply_header->opcode = OPCODE_CLOSE;
	reply_header->total_bytes = par_net_header_calc_size() + par_net_close_rep_calc_size(error_message_size);
	return reply_header;
}

static struct par_net_header *par_net_call_metrics(struct worker *worker, void *args){
  (void)args;

#ifdef USE_PAR_NET_METRICS

  struct par_net_metrics_req *request =
		(struct par_net_metrics_req *)&worker->recv_buffer[par_net_header_calc_size()];

  uint8_t flags = par_net_metrics_req_get_flags(request);
  (void)flags; // Will implement RESET

	uint32_t num_workers = worker->server_handle->opts->threadno;
  
  uint32_t get_ops = 0;
  uint32_t put_ops = 0; 
  uint32_t get_avg_key_size = 0;
  uint32_t get_avg_value_size = 0;
  uint32_t put_avg_key_size = 0;
  uint32_t put_avg_value_size = 0;
  uint32_t total_ops = 0;

  for (uint32_t i = 0; i < num_workers; i++) {
    struct worker *w = &worker->server_handle->workers[i];
    get_ops += w->op_count[OPCODE_GET];
    put_ops += w->op_count[OPCODE_PUT];
    get_avg_key_size  += w->get_avg_key_size; 
    get_avg_value_size += w->get_avg_value_size;
    put_avg_key_size += w->put_avg_key_size;
    put_avg_value_size += w->put_avg_value_size;
    total_ops += w->total_ops_count;
  }
  
  get_avg_key_size = (get_ops > 0) ? (uint32_t)(get_avg_key_size / get_ops) : 0;
  get_avg_value_size = (get_ops > 0) ? (uint32_t)(get_avg_value_size / get_ops) : 0;

  put_avg_key_size = (put_ops > 0) ? (uint32_t)(put_avg_key_size / put_ops) : 0;
  put_avg_value_size = (put_ops > 0) ? (uint32_t)(put_avg_value_size / put_ops) : 0;

  size_t buffer_len = worker->send_buffer_size - par_net_header_calc_size();
	struct par_net_metrics_rep *reply =
		par_net_metrics_rep_create(get_ops, put_ops, get_avg_key_size, get_avg_value_size, put_avg_key_size, put_avg_value_size,total_ops, &worker->send_buffer[par_net_header_calc_size()], buffer_len);
	if (NULL == reply) {
		log_warn("Failed to create get reply");
		return NULL;
	}

  struct par_net_header *reply_header = (struct par_net_header *)worker->send_buffer;
	reply_header->opcode = OPCODE_METRICS;
  reply_header->total_bytes = par_net_header_calc_size() + par_net_metrics_rep_calc_size();
  return reply_header;

#endif

  return NULL;
}

const par_call par_net_call[OPCODE_MAX] = { NULL,
					    par_net_call_open,
					    par_net_call_put,
					    par_net_call_del,
					    par_net_call_get,
					    par_net_call_close,
					    par_net_call_scan,
					    par_net_call_sync,
              par_net_call_metrics};

static int __par_handle_req(struct worker *restrict worker, int client_sock, struct tcp_req *restrict req)
{
	(void)req;

	struct iovec iov[1];
	struct msghdr msg;

	iov[0].iov_base = worker->recv_buffer;
	iov[0].iov_len = worker->recv_buffer_size;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	ssize_t bytes_received = recvmsg(client_sock, &msg, 0);
	if (bytes_received < 0) {
		perror("recvmsg");
		_exit(EXIT_FAILURE);
	}

	size_t total_bytes = par_net_get_total_bytes(worker->recv_buffer);
	// log_debug("Total bytes of  received message = %lu", total_bytes);

	if (total_bytes > worker->recv_buffer_size) {
		log_debug("Handling Larger message recv buffer size is: %lu B total_bytes are: %lu B",
			  worker->recv_buffer_size, total_bytes);
		worker->recv_buffer_size = total_bytes;
		worker->recv_buffer = (char *)realloc(worker->recv_buffer, worker->recv_buffer_size);
		assert(worker->recv_buffer != NULL);
		worker->recv_buffer_size = worker->recv_buffer_size;

		iov[0].iov_base = &worker->recv_buffer[bytes_received];
		iov[0].iov_len = worker->recv_buffer_size - bytes_received;

		ssize_t extra_bytes_received = recvmsg(client_sock, &msg, 0);
		if (extra_bytes_received < 0) {
			perror("recvmsg");
			_exit(EXIT_FAILURE);
		}

		log_debug("extra bytes received == %lu", extra_bytes_received);
		bytes_received += extra_bytes_received;
	}

	// log_debug("Total message size == %ld", bytes_received);
	uint32_t opcode = par_net_header_get_opcode(worker->recv_buffer);

	if (opcode == 0) {
		log_fatal("invalid opcode");
		return EXIT_FAILURE;
	}

#ifdef USE_PAR_NET_METRICS
  worker->op_count[opcode]++;
  worker->total_ops_count++;
#endif /* ifdef USE_PAR_NET_METRICS */

  struct par_net_header *reply_header = par_net_call[opcode](worker, NULL);

	struct iovec iov_reply[1];
	struct msghdr msg_reply = { 0 };

	iov_reply[0].iov_base = reply_header;
	iov_reply[0].iov_len = reply_header->total_bytes;

	memset(&msg_reply, 0, sizeof(msg_reply));
	msg_reply.msg_iov = iov_reply;
	msg_reply.msg_iovlen = 1;

	ssize_t bytes_sent = sendmsg(client_sock, &msg_reply, 0);
	if (bytes_sent < 0) {
		log_debug("Remote side has probably closed the socket");
		if (close(client_sock) < 0) {
			log_debug("Could not close client socket");
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

#ifndef SSL
static int __pin_thread_to_core(int core)
{
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(core, &cpuset);

	return sched_setaffinity(0, sizeof(cpuset), &cpuset);
}
#endif

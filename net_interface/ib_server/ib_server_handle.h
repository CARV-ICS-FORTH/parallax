#include <arpa/inet.h>
#include <errno.h>
#include <log.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct server_options {
	uint32_t threadno;
	const char *parallax_vol_name;
	uint32_t l0_size;
	uint32_t growth_factor;
	uint8_t format;
	long port;
	struct sockaddr_storage inaddr;
};

#define USAGE_STRING                           \
	"Infinband Server: no options specified\n" \
	"try './infiniband_parallax_server --help' for more information\n"

#define HELP_STRING                                                                                         \
	"Usage:\n  Infinband Server <-bptf>\nOptions:\n"                                                        \
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

#define DECIMAL_BASE 10
#define PORT_MAX 65536

struct server_options *ib_server_parse_argv_opts(int argc, char **argv);

long ib_server_parse_number(const char *str, const char *opt);

void ib_server_check_arg(int argc, int option_id);

void ib_server_set_address(struct server_options *opts, const char *arg);

void ib_server_set_port(struct server_options *opts, const char *arg);

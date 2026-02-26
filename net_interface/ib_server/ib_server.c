#include "ib_server_handle.h"
#include <log.h>

int main(int argc, char **argv)
{
	log_info("Starting InfiniBand server...");
	struct server_options *server_options = par_ib_server_parse_argv_opts(argc, argv);

	struct server_handle *server_handle = par_ib_server_handle_init(server_options);

	if (NULL == server_handle) {
		log_debug("Failed to initialize portals server");
		_exit(EXIT_FAILURE);
	}

	if (par_ib_server_print_config(server_handle) < 0) {
		_exit(errno);
	}

	if (par_ib_server_start(server_handle) < 0) {
		_exit(errno);
	}
}

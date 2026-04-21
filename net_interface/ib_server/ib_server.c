#include "ib_server_handle.h"
#include <log.h>

int main(int argc, char **argv)
{
#ifdef LOG_LEVEL_RELEASE
	log_set_level(2);
#endif
	log_info("Starting InfiniBand server...");
	struct server_options *server_options = par_ib_server_parse_argv_opts(argc, argv);

	struct root_server_handle *super_handle = par_ib_server_handle_init(server_options);

	if (NULL == super_handle) {
		log_debug("Failed to initialize portals server");
		_exit(EXIT_FAILURE);
	}

	if (par_ib_server_print_config(super_handle) < 0) {
		_exit(errno);
	}

	if (par_ib_server_start(super_handle) < 0) {
		_exit(errno);
	}
}

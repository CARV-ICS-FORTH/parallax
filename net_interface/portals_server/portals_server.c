#include "../../lib/include/parallax/parallax.h"
#include "../../lib/include/parallax/structures.h"
#include <stdio.h>

#include "portals_server_handle.h"
#include <errno.h>
#include <log.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	struct server_options *server_options = prsv_server_parse_argv_opts(argc, argv);

	struct server_handle *server_handle = prsv_portals_server_handle_init(server_options);

	if (NULL == server_handle) {
		log_debug("Failed to initialize portals server");
		_exit(EXIT_FAILURE);
	}

	if (prsv_server_print_config(server_handle) < 0) {
		_exit(errno);
	}

	if (prsv_server_start(server_handle) < 0) {
		_exit(errno);
	}

	return EXIT_SUCCESS;
}

#include "ib_server_handle.h"
#include <log.h>

int main(int argc, char **argv)
{
	log_info("Starting InfiniBand server...");
	struct server_options *server_options = ib_server_parse_argv_opts(argc, argv);
}

#include <zookeeper/zookeeper.h>
#include <log.h>
#include "../utilities/spin_loop.h"
#include "metadata.h"
#include "zk_utils.h"
int is_connected = 0;

static void zk_watcher(zhandle_t *zkh, int type, int state, const char *path, void *context)
{
	/*
 	* zookeeper_init might not have returned, so we
 	* use zkh instead.
 	*/
	if (type == ZOO_SESSION_EVENT) {
		if (state == ZOO_CONNECTED_STATE) {
			is_connected = 1;

		} else if (state == ZOO_CONNECTING_STATE) {
			log_fatal("Disconnected from zookeeper");
			exit(EXIT_FAILURE);
		}
	}
}

int main(int argc, char *argv[])
{
	if (argc != 3) {
		log_fatal("wrong number of arguments usage ./create_server_node <zk_host:zk_port> <hostname-port>");
		exit(EXIT_FAILURE);
	}
	zoo_set_debug_level(ZOO_LOG_LEVEL_INFO);
	/*init zookeeper connection*/
	zhandle_t *zh = zookeeper_init(argv[1], zk_watcher, 15000, 0, 0, 0);
	wait_for_value((uint32_t *)&is_connected, 1);
	struct krm_server_name s_name;
	strcpy(s_name.kreon_ds_hostname, argv[2]);
	s_name.kreon_ds_hostname_length = strlen(s_name.kreon_ds_hostname);
	char *hostname = strtok(argv[2], ":");
	strcpy(s_name.hostname, hostname);
	s_name.epoch = 0;
	char *zk_path = zku_concat_strings(4, KRM_ROOT_PATH, KRM_SERVERS_PATH, KRM_SLASH, s_name.kreon_ds_hostname);
	int rc = zoo_create(zh, zk_path, (char *)&s_name, sizeof(struct krm_server_name), &ZOO_OPEN_ACL_UNSAFE, 0, NULL,
			    0);
	if (rc != ZOK) {
		log_fatal("Failed to create host node %s with error code %d", zk_path, rc);
		exit(EXIT_FAILURE);
	}
	free(zk_path);
}

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "../utilities/macros.h"
#include "globals.h"
#include <log.h>

static globals global_vars = { NULL, NULL, -1, 1 };
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

char *globals_get_RDMA_IP_filter()
{
	if (global_vars.RDMA_IP_filter == NULL) {
		log_fatal("RDMA_IP_filter host,port not set!\n");
		exit(EXIT_FAILURE);
	}
	return global_vars.RDMA_IP_filter;
}

void globals_set_RDMA_IP_filter(char *RDMA_IP_filter)
{
	if (pthread_mutex_lock(&g_lock) != 0) {
		log_fatal("Failed to acquire lock");
		exit(EXIT_FAILURE);
	}
	if (global_vars.RDMA_IP_filter == NULL) {
		global_vars.RDMA_IP_filter = (char *)malloc(strlen(RDMA_IP_filter) + 1);
		strcpy(global_vars.RDMA_IP_filter, RDMA_IP_filter);
	} else {
		log_warn("RDMA_IP_filter already set at %s", global_vars.RDMA_IP_filter);
	}
	if (pthread_mutex_unlock(&g_lock) != 0) {
		log_fatal("Failed to acquire lock");
		exit(EXIT_FAILURE);
	}
}

char *globals_get_zk_host(void)
{
	if (global_vars.zk_host_port == NULL) {
		log_fatal("Zookeeper host,port not set!\n");
		exit(EXIT_FAILURE);
	}
	return global_vars.zk_host_port;
}

void globals_set_zk_host(char *host)
{
	if (pthread_mutex_lock(&g_lock) != 0) {
		log_fatal("Failed to acquire lock");
		exit(EXIT_FAILURE);
	}
	if (global_vars.zk_host_port == NULL) {
		global_vars.zk_host_port = (char *)malloc(strlen(host) + 1);
		strcpy(global_vars.zk_host_port, host);
	} else {
		log_warn("Zookeeper already set at %s", global_vars.zk_host_port);
	}
	if (pthread_mutex_unlock(&g_lock) != 0) {
		log_fatal("Failed to acquire lock");
		exit(EXIT_FAILURE);
	}
}

int globals_get_RDMA_connection_port(void)
{
	return global_vars.RDMA_connection_port;
}
void globals_set_RDMA_connection_port(int port)
{
	global_vars.RDMA_connection_port = port;
}

void globals_disable_client_spinning_thread()
{
	global_vars.client_spinning_thread = 0;
}

void globals_enable_client_spinning_thread()
{
	global_vars.client_spinning_thread = 1;
}

int globals_spawn_client_spinning_thread()
{
	return global_vars.client_spinning_thread;
}

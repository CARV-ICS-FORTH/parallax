#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/hdreg.h>
#include <linux/fs.h>

#include "../utilities/macros.h"
#include "conf.h"
#include "globals.h"
#include "../kreon_rdma/rdma.h"
#include <log.h>
struct globals {
	char *zk_host_port;
	char *RDMA_IP_filter;
	char *dev;
	int RDMA_connection_port;
	int client_spinning_thread;
	uint64_t volume_size;
	struct channel_rdma *channel;
	int connections_per_server;
};
static struct globals global_vars = { NULL, NULL, NULL, -1, 1, 0, NULL, NUM_OF_CONNECTIONS_PER_SERVER };
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

int globals_get_connections_per_server(void)
{
	return global_vars.connections_per_server;
}

void globals_set_connections_per_server(int connections_per_server)
{
	global_vars.connections_per_server = connections_per_server;
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

void globals_set_dev(char *dev)
{
	if (pthread_mutex_lock(&g_lock) != 0) {
		log_fatal("Failed to acquire lock");
		exit(EXIT_FAILURE);
	}
	if (global_vars.dev == NULL)
		global_vars.dev = strdup(dev);
	else
		log_warn("dev already set to %s", global_vars.dev);

	int FD = open(dev, O_RDWR);
	if (FD == -1) {
		log_fatal("failed to open %s reason follows");
		perror("Reason");
		exit(EXIT_FAILURE);
	}
	if (strncmp(dev, "/dev/", 5) == 0) {
		if (ioctl(FD, BLKGETSIZE64, &global_vars.volume_size) == -1) {
			log_fatal("failed to determine volume's size", dev);
			exit(EXIT_FAILURE);
		}
		log_info("%s is a block device of size %llu", dev, global_vars.volume_size);
	} else {
		int64_t end_of_file;
		end_of_file = lseek(FD, 0, SEEK_END);
		if (end_of_file == -1) {
			log_fatal("failed to determine file's %s size exiting...", dev);
			perror("ioctl");
			exit(EXIT_FAILURE);
		}
		global_vars.volume_size = (uint64_t)end_of_file;
		log_info("%s is a file of size %llu", dev, global_vars.volume_size);
	}
	FD = close(FD);
	if (FD == -1) {
		log_fatal("failed to open %s reason follows");
		perror("Reason");
		exit(EXIT_FAILURE);
	}

	if (pthread_mutex_unlock(&g_lock) != 0) {
		log_fatal("Failed to acquire lock");
		exit(EXIT_FAILURE);
	}
}

char *globals_get_dev(void)
{
	return global_vars.dev;
}

uint64_t globals_get_dev_size()
{
	return global_vars.volume_size;
}

void globals_create_rdma_channel(void)
{
	if (pthread_mutex_lock(&g_lock) != 0) {
		log_fatal("Failed to acquire lock");
		exit(EXIT_FAILURE);
	}
	if (global_vars.channel == NULL)
		global_vars.channel = crdma_client_create_channel();
	else
		log_warn("rdma channel already set");
	if (pthread_mutex_unlock(&g_lock) != 0) {
		log_fatal("Failed to acquire lock");
		exit(EXIT_FAILURE);
	}
}

void globals_set_rdma_channel(struct channel_rdma *channel)
{
	if (pthread_mutex_lock(&g_lock) != 0) {
		log_fatal("Failed to acquire lock");
		exit(EXIT_FAILURE);
	}

	if (global_vars.channel == NULL)
		global_vars.channel = channel;
	else
		log_warn("rdma channel already set");

	if (pthread_mutex_unlock(&g_lock) != 0) {
		log_fatal("Failed to acquire lock");
		exit(EXIT_FAILURE);
	}
}

struct channel_rdma *globals_get_rdma_channel(void)
{
	return global_vars.channel;
}

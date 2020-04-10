#include <pthread.h>
#include "zk_server.h"

typedef struct globals {
	char *zk_host_port;
	char *RDMA_IP_filter;
	char *dev;
	int RDMA_connection_port;
	int client_spinning_thread;
} globals;

char *globals_get_RDMA_IP_filter();
void globals_set_RDMA_IP_filter();
char *globals_get_zk_host(void);
void globals_set_zk_host(char *host);

int globals_get_RDMA_connection_port(void);
void globals_set_RDMA_connection_port(int port);

void globals_disable_client_spinning_thread(void);
void globals_enable_client_spinning_thread(void);
int globals_spawn_client_spinning_thread(void);

void globals_set_dev(char *dev);
char *globals_get_dev(void);

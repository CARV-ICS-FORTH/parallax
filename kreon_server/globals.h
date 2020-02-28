#include <pthread.h>
#include "../kreon_server/zk_server.h"

typedef struct globals{
    char *zk_host_port;
    int RDMA_connection_port;
}globals;

char * globals_get_zk_host(void);
void globals_set_zk_host(char *host);

int globals_get_RDMA_connection_port(void);
void globals_set_RDMA_connection_port(int port);


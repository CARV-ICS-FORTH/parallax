#pragma once
#include <pthread.h>
#include <stdint.h>
#include "../kreon_rdma/rdma.h"
char *globals_get_RDMA_IP_filter(void);
void globals_set_RDMA_IP_filter(char *RDMA_IP_filter);

char *globals_get_zk_host(void);
void globals_set_zk_host(char *host);

int globals_get_RDMA_connection_port(void);
void globals_set_RDMA_connection_port(int port);

int globals_get_connections_per_server(void);
void globals_set_connections_per_server(int connections_per_server);

void globals_disable_client_spinning_thread(void);
void globals_enable_client_spinning_thread(void);
int globals_spawn_client_spinning_thread(void);

void globals_set_dev(char *dev);
char *globals_get_dev(void);
uint64_t globals_get_dev_size(void);

void globals_create_rdma_channel(void);
void globals_set_rdma_channel(struct channel_rdma *channel);
struct channel_rdma *globals_get_rdma_channel(void);

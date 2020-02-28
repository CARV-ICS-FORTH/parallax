
#ifndef _TU_NETWORK_DATA_SERVER_H
#define _TU_NETWORK_DATA_SERVER_H
 
//#ifndef _GNU_SOURCE
//#define _GNU_SOURCE     /* To get defns of NI_MAXSERV and NI_MAXHOST */
//#endif


#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <sys/types.h>

#include <zookeeper.jute.h> //For struct String_vector
#include "conf.h"


#if TU_RDMA_CONN_PER_SERVER
#include "../kreon_rdma/rdma.h"

struct server_conn_S {
	struct connection_rdma *rdma_conn[MAX_MAILBOX];
	int nusers[MAX_MAILBOX];
	pthread_mutex_t mutex_rdma_conn[MAX_MAILBOX];
};
#endif

typedef struct _server_tu_network_data {
	char *hostname;
	int num_NICs;
	char **IPs;
	void *net_private;
#if TU_RDMA_CONN_PER_SERVER
	struct server_conn_S *server_conn;
#endif
} _server_tu_network_data;


// To have a list of hostname and its list of IPs for each of them
typedef struct _array_server_tu_network_data {
	int count;
	_server_tu_network_data *net_data;
} _array_server_tu_network_data;

void Init_Server_Tu_Network_Data ( _server_tu_network_data *net);
void Server_Set_And_Alloc_IPs( const struct String_vector *zk_ip, _server_tu_network_data *net );
void PrintfServerNetData( _server_tu_network_data *net);
void Free_Server_Network_Data(_server_tu_network_data *net);
void Init_Array_Server_Tu_Network_Data( _array_server_tu_network_data *net_list );
void Set_And_Alloc_Tu_Server_Network_Data( const struct String_vector *zk_servers, _array_server_tu_network_data *net_list, void *net_private );
_server_tu_network_data *Server_FindHostname_Servers( char *hostname,  _array_server_tu_network_data *net_list );
#endif

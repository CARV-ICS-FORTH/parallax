#pragma once
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
#endif


/*
 * Client uses this descriptor to keep track number of connections 
 * for a given server. A set of regions might use this structure
 */
typedef struct _cli_tu_network_data {
	char *hostname;
	int num_NICs;
	char **IPs;
	void *net_private; 
#if TU_RDMA_CONN_PER_SERVER
	struct connection_rdma *rdma_conn[NUM_OF_CONNECTIONS_PER_SERVER];
	int number_of_mapped_regions;
	pthread_mutex_t mutex_rdma_conn[NUM_OF_CONNECTIONS_PER_SERVER];/*gesalous: also what is this ?*/
#endif
} _cli_tu_network_data;


/* To have a list of hostname and its list of IPs for each of them */
typedef struct _array_cli_tu_network_data {
	int count;
	_cli_tu_network_data *net_data;
} _array_cli_tu_network_data;

void Init_Cli_Tu_Network_Data ( _cli_tu_network_data *net);
void Client_Set_And_Alloc_IPs( const struct String_vector *zk_ip, _cli_tu_network_data *net );
void PrintfClientNetData( _cli_tu_network_data *net);
void Free_Client_Network_Data(_cli_tu_network_data *net);
void Init_Array_Client_Tu_Network_Data( _array_cli_tu_network_data *net_list );
void Set_And_Alloc_Tu_Client_Network_Data( const struct String_vector *zk_servers, _array_cli_tu_network_data *net_list, void *net_private );
_cli_tu_network_data *FindHostname_Servers( char *hostname,  _array_cli_tu_network_data *net_list );



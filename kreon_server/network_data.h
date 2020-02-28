
#ifndef _TU_NETWORK_DATA_H
#define _TU_NETWORK_DATA_H
 
#ifndef _GNU_SOURCE
#define _GNU_SOURCE     /* To get defns of NI_MAXSERV and NI_MAXHOST */
#endif

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

typedef struct _tu_network_data {
	char *hostname;
	int num_NICs;
	char **IPs;
} _tu_network_data;


// To have a list of hostname and its list of IPs for each of them
typedef struct _array_tu_network_data {
	int count;
	_tu_network_data *net_data;
} _array_tu_network_data;

void Init_Tu_Network_Data ( _tu_network_data *net);
char *get_my_hostname( void );
void Get_My_IP_Addresses( _tu_network_data *net );
void Get_Tu_Network_Data( _tu_network_data *net );

// [mvard] deprecated by Get_My_Hostname. To be removed
//void Set_and_Alloc_Hostname( const char *buf, _tu_network_data *net ) ;
void Set_And_Alloc_IPs( const struct String_vector *zk_ip, _tu_network_data *net );

void PrintfNetData( _tu_network_data *net);

void Free_Network_Data(_tu_network_data *net);
void Init_Array_Tu_Network_Data( _array_tu_network_data *net_list );
void Set_And_Alloc_Tu_Network_Data( const struct String_vector *zk_servers, _array_tu_network_data *net_list, void *net_private );

#endif

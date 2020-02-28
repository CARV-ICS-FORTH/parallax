
//  tu_network_data.c
//  Fuctions related to network stuff: get the hostname, get the IP address of all the nics,
//
//
//  Created by Pilar Gonzalez-Ferez on 28/07/16.
//  Copyright (c) 2016 Pilar Gonzalez-Ferez <pilar@ics.forth.gr>.
//  


#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <sys/types.h>



#include "regions.h"
#include "prototype.h"
#include "network_data_server.h"
#include "zk_server.h"

#if TU_RDMA_CONN_PER_SERVER
struct server_conn_S *Alloc_Init_Server_Rdma_Conn_S()
{	
	struct server_conn_S *server_conn;
	int i;
	server_conn = malloc( sizeof(struct server_conn_S)); 
	if ( server_conn == NULL ) 
	{
		perror("Alloc_Init_Server_Rdma_Conn_S: Memory problem\n");
		return NULL;
	}	
	for ( i = 0; i < MAX_MAILBOX;  i++ )
	{
		server_conn->rdma_conn[i] = NULL;
		server_conn->nusers[i] = 0;
		pthread_mutex_init( &server_conn->mutex_rdma_conn[i], NULL );
	} 	
	return server_conn;
}
#endif

void Init_Server_Tu_Network_Data ( _server_tu_network_data *net)
{
	net->hostname = NULL;
	net->IPs = NULL;
	net->num_NICs = 0;
	net->net_private = NULL;

#if TU_RDMA_CONN_PER_SERVER
	net->server_conn = Alloc_Init_Server_Rdma_Conn_S();
#endif

}


void Server_Set_And_Alloc_IPs( const struct String_vector *zk_ip, _server_tu_network_data *net )
{
	char **IPs;
	int num_NICs=0;
	int i;
	int j;

	for(i=0;i<zk_ip->count;i++){
		printf("[%s:%s:%d] zk ip = %s\n",__FILE__,__func__,__LINE__,zk_ip->data[i]);
		if(net->IPs != NULL)
			printf("[%s:%s:%d] net ips = %s\n\n",__FILE__,__func__,__LINE__,net->IPs[i]);
	}

	if (zk_ip->count <= 0 )
		return;

	if ( net->num_NICs > 0 ){
		IPs = net->IPs;
		num_NICs = net->num_NICs;
		net->IPs = NULL;
		printf("[%s:%s:%d] num of nics %d\n",__FILE__,__func__,__LINE__,num_NICs);
	}
	else
		IPs = NULL;

	net->num_NICs = zk_ip->count;
	net->IPs = (char **)malloc(sizeof(char *) * net->num_NICs );

	if (num_NICs == 0){
		for( i = 0; i < zk_ip->count; i++){
			net->IPs[i] = strdup(zk_ip->data[i]);
		}
	}
	else{
		for( i = 0; i < zk_ip->count; i++){
			int found_IP = 0;
			printf("[%s:%s:%d] num_NICS = %d\n",__FILE__,__func__,__LINE__,num_NICs);
			for ( j = 0; j < num_NICs; j++){

				printf("[%s:%s:%d] ip: %s\n",__FILE__,__func__,__LINE__,zk_ip->data[i]);
				if(strcmp(zk_ip->data[i], IPs[j] ) == 0 ){
					net->IPs[i] = IPs[j];
					/*gesalous buggy*/
					//IPs[j] = NULL;
					found_IP = 1;
					break;
				}
			}
			if ( found_IP == 0)
			{
				net->IPs[i] = strdup(zk_ip->data[i]);
			}
		}
		/*gesalous double check here possible memory leak*/
		//for( i = 0 ; i < num_NICs; i++ ){
		//	if ( IPs[i] != NULL )
		//		free( IPs[i] );
		//}
		//free(IPs);
		printf("[%s:%s:%d] Ommiting free(IPS), XXX TODO XXX check again possible memory leak\n",__FILE__,__func__,__LINE__);
	}
	//PrintfServerNetData(net);
}

void PrintfServerNetData( _server_tu_network_data *net )
{
	int i;
	for ( i = 0; i < net->num_NICs; i++)
	{
		printf("IP %d %s\n", i, net->IPs[i] );
	}
}

void Free_Server_Network_Data( _server_tu_network_data *net)
{
	int i;

	if ( net->hostname != NULL )
	{
		free( net->hostname );
		net->hostname = NULL;
	} 

	if ( net->num_NICs == 0 ) 
		return;
	
	for( i = 0 ; i < net->num_NICs; i++ )
		free( net->IPs[i] );
	free(net->IPs);  
	net->num_NICs = 0 ;
	net->IPs = NULL;
}



void Init_Array_Server_Tu_Network_Data( _array_server_tu_network_data *net_list )
{
	net_list->count = 0;
	net_list->net_data = NULL;
}



void Set_And_Alloc_Tu_Server_Network_Data( const struct String_vector *zk_servers, _array_server_tu_network_data *net_list , void *net_private)
{
	_server_tu_network_data *old_net_data;
	int old_count = 0;
	int i;
	int j;
	DPRINT("current sever count %d old server count %d\n",zk_servers->count, net_list->count);

	if ( zk_servers->count <= 0 )
		return;

	if (net_list->count > 0){
		old_net_data = net_list->net_data;
		old_count = net_list->count;
		net_list->net_data = NULL; 
	}

	net_list->count = zk_servers->count;
	net_list->net_data = malloc( net_list->count * sizeof(_server_tu_network_data) );

	// We copy the list of servers, and for each server we put the list of IPs to NULL
	if (old_count > 0){
		for ( i = 0; i< net_list->count; i++ )
		{
			int found_hostname;
			found_hostname = 0;
			for ( j = 0; j < old_count; j ++ )
			{
				if(strcmp(zk_servers->data[i], old_net_data[j].hostname ) == 0 )
				{
					net_list->net_data[i].hostname =  old_net_data[j].hostname ;
					net_list->net_data[i].num_NICs = old_net_data[j].num_NICs;
					net_list->net_data[i].IPs = old_net_data[j].IPs;
					/*gesalous buggy code caused seg fault*/
					//old_net_data[j].num_NICs = 0;
					//old_net_data[j].IPs = NULL;
					//old_net_data[j].hostname = NULL;
					found_hostname = 1;
					DPRINT("HOST-ALREADY-EXISTS %s\n",net_list->net_data[i].hostname );
					break;
				}
			}
			if ( found_hostname == 0  ){
				Init_Server_Tu_Network_Data ( &net_list->net_data[i] );
				net_list->net_data[i].hostname = strdup ( zk_servers->data[i] );
			}
			net_list->net_data[i].net_private = net_private;
			server_get_IP_server( &net_list->net_data[i] ); //We call zookeeper to update the list of IPs for the server
		}
	}
	else{
		for ( i = 0; i< net_list->count; i++ )
		{
			Init_Server_Tu_Network_Data ( &net_list->net_data[i] );
			net_list->net_data[i].hostname = strdup ( zk_servers->data[i] );
			net_list->net_data[i].net_private = net_private;
			server_get_IP_server( &net_list->net_data[i] ); //We call zookeeper to update the list of IPs for the server
		}
	}
	DPRINT("server list updated successfully\n", old_count);
	if ( old_count == 0 ) /*There was no data previously*/
		return;
	else{
		// Delete the old data
		for ( j = 0; j  < old_count; j ++){
			Free_Server_Network_Data( &old_net_data[j] );
		}
		free( old_net_data );
	}
}



_server_tu_network_data *Server_FindHostname_Servers( char *hostname,  _array_server_tu_network_data *net_list )
{
	int i;
	_server_tu_network_data *net_data;
	net_data = NULL;

	DPRINT("FIND %d\n",net_list->count);
	for (i = 0; i < net_list->count; i++ )
	{
		DPRINT("Find %d %d %s\n",net_list->count, i, hostname);
		if ( strcmp(hostname, net_list->net_data[i].hostname ) == 0 ){
			net_data = &net_list->net_data[i];
      break;
		}
	}
	return (net_data);
}


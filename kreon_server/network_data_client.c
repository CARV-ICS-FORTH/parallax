/**
 * tu_network_data.c
 * Fuctions related to network stuff: get the hostname, get the IP address of all the nics,
 *Created by Pilar Gonzalez-Ferez on 28/07/16.
 *  Copyright (c) 2016 Pilar Gonzalez-Ferez <pilar@ics.forth.gr>.
**/  


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
#include "network_data_client.h"
#include "zk_client.h"
#include "client_regions.h"



void Init_Cli_Tu_Network_Data ( _cli_tu_network_data *net)
{
	net->hostname = NULL;
	net->IPs = NULL;
	net->num_NICs = 0;
	net->net_private = NULL;
#if TU_RDMA_CONN_PER_SERVER
  int i;
  for ( i = 0; i < NUM_OF_CONNECTIONS_PER_SERVER;  i++ ){
		net->rdma_conn[i] = NULL;
    pthread_mutex_init( &net->mutex_rdma_conn[i], NULL );
	}
		net->number_of_mapped_regions = 0;
#endif
}

//..............................................................................
void Client_Set_And_Alloc_IPs( const struct String_vector *zk_ip, _cli_tu_network_data *net )
{
	char **IPs;
	int num_NICs=0;
	int i;
	int j;
	
	if (zk_ip->count <= 0 ) 
		return;
	
	if ( net->num_NICs > 0 )
	{	
		IPs = net->IPs;
		num_NICs = net->num_NICs;
		net->IPs = NULL; 
	}
	else IPs = NULL;

	net->num_NICs = zk_ip->count;
	net->IPs = (char **)malloc(sizeof(char *) * net->num_NICs );

	if ( num_NICs == 0 )
	{
        	for( i = 0; i < zk_ip->count; i++)
       		{
			net->IPs[i] = strdup(zk_ip->data[i]);
		}
	}
	else 
	{
        	for( i = 0; i < zk_ip->count; i++)
       		{
			int found_IP = 0;
			for ( j = 0; j < num_NICs; j++)
			{
				if (strcmp(zk_ip->data[i], IPs[j] ) == 0 )
				{
					net->IPs[i] = IPs[j];
					IPs[j] = NULL;
					found_IP = 1;
					break;
				}
			}
			if ( found_IP == 0)
			{
				net->IPs[i] = strdup(zk_ip->data[i]);
			}
		}
		for( i = 0 ; i < num_NICs; i++ )
		{
			if ( IPs[i] != NULL ) free( IPs[i] );
		}
		free(IPs);  
	}
	//rintfClientNetData(net);
}

void PrintfClientNetData( _cli_tu_network_data *net )
{
	int i;
	for ( i = 0; i < net->num_NICs; i++)
	{
		printf("IP %d %s\n", i, net->IPs[i] );
	}
}

void Free_Client_Network_Data( _cli_tu_network_data *net)
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
//..............................................................................

void Init_Array_Client_Tu_Network_Data( _array_cli_tu_network_data *net_list )
{
	net_list->count = 0;
	net_list->net_data = NULL;
}

//..............................................................................
void Set_And_Alloc_Tu_Client_Network_Data( const struct String_vector *zk_servers, _array_cli_tu_network_data *net_list , void *net_private)
{
	_cli_tu_network_data *old_net_data;
	int old_count = 0;
	int i;
	int j;

	if (zk_servers->count <= 0 ) 
		return;

	if ( net_list->count > 0 ){
		old_net_data = net_list->net_data;
		old_count = net_list->count;
		net_list->net_data = NULL; 
	}
	DPRINT("zk servers are %d\n",zk_servers->count);
	net_list->count = zk_servers->count;
	net_list->net_data = malloc( net_list->count * sizeof(_cli_tu_network_data) );
	if ( net_list->net_data == NULL )
	{
		perror("Set_And_Alloc_Tu_Network_Data: alloc net_data\n");
		exit(1);
	}
	// We copy the list of servers, and for each server we put the list of IPs to NULL
	if ( old_count > 0 ) 
	{
		for ( i = 0; i< net_list->count; i++ )
		{
			int found_hostname;
			found_hostname = 0;
			for ( j = 0; j < old_count; j ++ )
			{
				if (strcmp(zk_servers->data[i], old_net_data[j].hostname ) == 0 )
				{
					net_list->net_data[i].hostname =  old_net_data[j].hostname ;
					net_list->net_data[i].num_NICs = old_net_data[j].num_NICs;
					net_list->net_data[i].IPs = old_net_data[j].IPs;
					old_net_data[j].num_NICs = 0;
					old_net_data[j].IPs = NULL;
					old_net_data[j].hostname = NULL;
					found_hostname = 1;
					printf("HOST-ALREADY-EXITS %s\n",net_list->net_data[i].hostname );
					break;
				}
			}
			if ( found_hostname == 0  )
			{
				Init_Cli_Tu_Network_Data ( &net_list->net_data[i] );
				net_list->net_data[i].hostname = strdup ( zk_servers->data[i] );
			}
			net_list->net_data[i].net_private = net_private;
			client_get_IP_server( &net_list->net_data[i] ); //We call zookeeper to update the list of IPs for the server
		}
	}
	else
	{
		for ( i = 0; i< net_list->count; i++ )
		{
			Init_Cli_Tu_Network_Data ( &net_list->net_data[i] );
			net_list->net_data[i].hostname = strdup ( zk_servers->data[i] );
			net_list->net_data[i].net_private = net_private;
			client_get_IP_server( &net_list->net_data[i] ); //We call zookeeper to update the list of IPs for the server
		}
	}
//printf("SERVER LIST UPDATED %d\n",old_count); fflush(stdout);
	if ( old_count == 0 ) //There was no data previously
	{
		return;
	}

	// Delete the old data
	for ( j = 0; j  < old_count; j ++)
	{
		Free_Client_Network_Data( &old_net_data[j] );
	}
	free( old_net_data );
}


_cli_tu_network_data *FindHostname_Servers( char *hostname,  _array_cli_tu_network_data *net_list )
{
	int i;
	_cli_tu_network_data *net_data;
	net_data = NULL;
	DPRINT("net list count %d\n",net_list->count);
	for (i = 0; i < net_list->count; i++ ){
		if(strcmp(hostname, net_list->net_data[i].hostname ) == 0){
			DPRINT("hostname %s net list %s\n",hostname,  net_list->net_data[i].hostname);
			net_data = &net_list->net_data[i];
			//printf("Encontrado %d %d %s\n",net_list->count, i, hostname);
			break;
		}
	}
	return (net_data);
}






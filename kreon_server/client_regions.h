//
//  client_tucana_regions.h
//  Client Tucana Regions
//
//  Created by Pilar Gonzalez-Ferez on 28/07/16.
//  Copyright (c) 2016 Pilar Gonzalez Ferez <pilar@ics.forth.gr>.
//

#pragma once
#ifndef _GNU_SOURCE
#define _GNU_SOURCE     
#endif


// For ZooKeeper
#include <zookeeper.h>
#include <zookeeper_log.h>
#include <zookeeper.jute.h> //For struct String_vector

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>


#include "../kreon_rdma/rdma.h"


#include "conf.h"
#include "regions.h"
#include "zk_string_vector.h"
#include "messages.h"
#include "network_data_client.h"



typedef struct _client_mailbox 
{
	struct String_vector* zk_data_mb; 		// List with the mailboxess defined on Zookeeper for this sever
							// This list is obtained from /servers/head/mbdata (its children)
	//mailbox_t *mailbox;				// Mailbox for sending request

}_client_mailbox;

typedef struct _Client_Regions _Client_Regions;

typedef struct client_region
{
	_ID_region ID_region;		/*ID of the region, including the range*/
  _Client_Regions	*parent;	/* The root entry of all regions or as we say in greek o babas sas, sas ponaei?*/
	int inserted_tree;		/*This region has been already inserted in the rb_tree/To not insert the region more than once*/
	int ready;			/* Set to 1 when the region is ready to use, and for instance even the mailboxes are open/To 0 while the region is not ready, still getting data*/
	char *head;			/* Head of the region. To consult /server/hostname/mbdata*/
	_cli_tu_network_data *head_net; /*information about the head server of this regions (IP, hostname, e.t.c.)*/
	uint64_t stat;			/*controls how many message through this region*/
#if TU_RDMA_CONN_PER_REGION
  struct connection_rdma *rdma_conn[MAX_MAILBOX];
#endif
  pthread_t mail_th[MAX_MAILBOX];	//Threads receiving from the mailbox
	int next_mail; //from 0 to 4

	pthread_mutex_t mutex_mailbox;	// mutex for receive messages, a single thread should wait for messages
	_client_mailbox data_mailbox;	// Mailboxes for sending request
	int received_messages;		// Number of received messages, not proccessed
	int getting_messages;		// Number of threads messages ready to get messages
	pthread_mutex_t mutex_cond;	// mutex for received_messages and getting messages
	pthread_cond_t condition;	// To be able to wait
	void *list_pending_request;	// List of request issued, but not ACK yet by the chain/Maybe we dont need this list. Depending on how we wait for the request
	int connected;					// 1 to set that the client is connected, 0 to set is not connected.
}  client_region ;



struct _Client_Regions
{
  /* *
   * Tree to sorted the region by keys: red black tree
	 * Given a KV operation, this tree willl make easy to find the
	 * region involved in the operation
  struct rb_root tree;
  **/
	zhandle_t *zh;					// Handle of ZooKeeper
	int connected;					// 1 to set that the client is connected, 0 to set is not connected.
	int expired;					// 1 to set that the connection expired
	int flag_regions;				// 0 We could not get info of the regions/servers
	int flag_servers;				// 1 We could get info of the regions/servers
	int num_regions;				// Number of regions that has been inserted
	int num_regions_connected;			// Number of regions that has been inserted and connected to the remote server
	struct String_vector* zk_regions;		// List with the regions defined on Zookeeper
							// This list is obtained from /regions/ (its children)
	client_region ** tu_regions;		// Array with the tucana_region_client for the client.
							// There is an element per region, therefore, as many as zk_regions we have
							// Note that tucli_regions will store the regions in the same order as they
							// are sorted at zk_regions
	client_region ** sorted_tu_regions;	// Array with the tucana_region_client for the client, but sorted by ID
	_array_cli_tu_network_data servers;		// List of servers available
							// Instead of having each region its server, now we will have a list of servers
							// From the regions we will keep a pointer from there to one element of this list
	struct channel_rdma *channel;
};


//.... To easily integrate with C++
typedef struct cli_keyvalue_pairs
{
	int num; //Num of KV that have been inserted
	int pos; 	// To insert KV pairs
	int length; 	// Length of the keys and values: calculated while inserting them
	char **keys;	// Pointers to the keys	
	char **values;	// Pointers to the values
} cli_keyvalue_pairs ;

typedef struct cli_keys_list
{
	int num; //Num of KV that have been inserted
	int pos; 	// To insert KV pairs
	int length; 	// Length of the keys and values: calculated while inserting them
	char **keys;	// Pointers to the keys	
} cli_keys_list ;


//gesalous regions manager functions
void client_init_regions_manager();
int client_compare(void *key_1, void * key_2, int size_2);
client_region * client_find_region(void *key, int key_size);
int client_add_region(client_region* region);
int client_delete_region(client_region * region);

struct connection_rdma* get_connection_from_region(client_region* region, int seed);


_Client_Regions *Allocate_Init_Client_Regions( void );
void Init_Client_Regions( _Client_Regions *client_regions );
void Free_Client_Regions( _Client_Regions **a_client_regions );

client_region *allocateclient_regions( char *ID , _Client_Regions *client_regions );
client_region **allocate_arrayclient_regions_withregions( int count, _Client_Regions *client_regions );
client_region **allocate_arrayclient_regions( int count );
void free_arrayclient_regions( client_region **tmp_tu_client_region, int count );
void Update_Client_Regions( _Client_Regions *client_regions, const struct String_vector *zk_regions );
void Client_Set_and_Alloc_Head_Region( const char *buf, client_region *cli_tu_region );

void Assign_Region_Min_Range( client_region *cli_tu_region , const char *min_range );
void Assign_Region_Max_Range( client_region *cli_tu_region , const char *max_range );

void Insert_Tucana_Region_Tree( _Client_Regions *client_regions, client_region *cli_tu_region );
void Delete_Tucana_Region_Tree( _Client_Regions *client_regions, client_region *cli_tu_region );

void Client_Update_Open_Head_Data_Mailboxes( client_region *cli_tu_region, const struct String_vector *zk_mb );
void Free_Client_Data_Mailbox( client_region *cli_tu_region );
void Init_Client_Data_Mailbox( client_region *cli_tu_region );

void Set_Flag_Regions( _Client_Regions *client_regions, int id );
void Set_Flag_Servers( _Client_Regions *client_regions, int id );

void Client_New_Data_On_Root( const struct String_vector *zk_root,  _Client_Regions * client_regions );
void Client_Get_Info_Region( client_region *cli_tu_region );

void Client_Set_Ready_Region( client_region *cli_tu_region );
int Client_Get_Ready_Region( client_region *cli_tu_region );



void Client_Print_Stat_Client_Regions( _Client_Regions *client_regions );
client_region *Find_Client_Regions_By_ID( _Client_Regions *client_regions, uint32_t idregion );
void Free_Client_Regions_Sorted_Tu_Regions( _Client_Regions *client_regions );
void Client_Created_Sorted_Tu_Regions (_Client_Regions *client_regions );
void Client_Manage_Sorted_Tu_Regions( _Client_Regions *client_regions );
client_region *Find_Client_Sorted_Regions_By_ID( _Client_Regions *client_regions, uint32_t idregion );




struct tu_data_message *Client_Generic_Receive_Message( client_region* cli_tu_region, struct tu_data_message *data_message , int next_mail );

void *client_thread_receiving_messages( void *args );
int Get_NextMailbox_Cli_Tu_Region( client_region* cli_tu_region );
client_region* Client_Get_Tu_Region_and_Mailbox( _Client_Regions *client_regions, char *key, int key_len, uint32_t idregion, int *next_mail );


void Client_Free_Data_Message( struct tu_data_message **data_message, client_region* cli_tu_region, int next_mail );
struct tu_data_message * Client_Create_N_Messages_Put_KeyValue_Pairs_WithMR( int length, client_region* cli_tu_region, int next_mail );
struct tu_data_message * Client_Send_RDMA_N_Messages( client_region* cli_tu_region, struct tu_data_message *data_message, int next_mail );


void Client_Flush_Volume( _Client_Regions *client_regions );
/* 
 * Function to create the receive threads from the client application
 */
void Client_Create_Receiving_Threads( _Client_Regions *client_regions );

void Tu_Client_Create_RMDA_Connection( void *aux_client_regions );
void Client_Flush_Volume_MultipleServers( _Client_Regions *client_regions );



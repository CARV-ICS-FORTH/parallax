//
//  tucana_regions.h
//  Tucana Regions
//
//  Created by Pilar Gonzalez-Ferez on 28/07/16.
//  Copyright (c) 2016 Pilar Gonzalez Ferez <pilar@ics.forth.gr>.
//

#ifndef __SERVER_REGIONS_H_
#define __SERVER_REGIONS_H_

#include <semaphore.h>
#include <zookeeper.jute.h> //For struct String_vector


#include "../kreon_lib/allocator/allocator.h"
#include "../kreon_lib/btree/btree.h"
#include "../kreon_lib/scanner/scanner.h"
#include "../kreon_rdma/rdma.h"


#include "conf.h"
#include "network_data.h"
#include "regions.h"
#include "messages.h"
#include "network_data_server.h"

#define MAX_HOSTNAME 256
#define RECONFIGURATION_STATE 0x01
#define WORKING_STATE 0x02
#define WAITING_FOR_RECONFIGURATION 0x03
#define WORKING_STATE_LEADER 0x04

/*flags for dynamic opening/closing of a db*/
#define ENTERED_REGION 0x02
#define EXITED_REGION 0x03
#define THROTTLE 2048




enum replica_type {
	NON_REPLICA = 0,
	REPLICA_HEAD,
	REPLICA_NODE,
	REPLICA_TAIL
};

typedef struct group_membership_entry{
	int32_t state;
	int32_t current_group_size;
	int32_t max_group_size;
	uint64_t uuid;
	char hostname[MAX_HOSTNAME];
} group_membership_entry;


#define MAX_TREE_HEIGHT 12
typedef struct _tucana_region_S{
  /*parameters used for remote spills at replica with tiering*/
  node_header * last_node_per_level[MAX_TREE_HEIGHT];
  uint64_t cur_nodes_per_level[MAX_TREE_HEIGHT];
  uint64_t num_of_nodes_per_level[MAX_TREE_HEIGHT];
  uint64_t entries_in_semilast_node[MAX_TREE_HEIGHT];
  uint64_t entries_in_last_node[MAX_TREE_HEIGHT];
  uint32_t current_active_tree_in_the_forest;

  connection_rdma *replica_next_data_con;  /* Connection to next in chain */
	_ID_region ID_region;		// ID of the region, including the range, XXX TODO XXX patch not fix. Must be first as also in _client_tucana_region otherwise rbtree does not work
	group_membership_entry gmt;
	//struct _tree_min_key node_tree; // To include the region on the rb tree, to make easy the looking for regions, unused
	char *device;			// path name of the device, such as /dev/md0
					// It is allocated dynamically
	uint64_t size;			// Size of the device in bytes. Total Size. It should not change never
	uint64_t offset;		// Position where the segment start.
	int has_offset;			// 0 no offset yet, 1 offset yet

	db_handle *db;			//kreon handle
	long active_region_threads;

	int ready_db;			// 0 the DB is not open, 1 it is open
	int replica_connection_state;
	//mailbox_t *data_mailbox[MAX_MAILBOX];		// Mailbox for receiving request
	int next_mail; //from 0 to 4


	// Replica of this Region
	void *chain_replication;	// Chain for the replication of this region
	//mailbox_t *replica_mailbox;		// Mailbox for replicating requests
	void *list_pending_replicated;	// List of request replicated, but not ACK yet by the chain
	int inserted_tree;		// This region has been already inserted in the rb_tree.
					// To not insert the region more than once.

	int32_t n_replicas;                        //Number of elements that compose the chain of this region
	char **replicas_hostname;                  //List of hostnames with the replicas names
	int replica_type;                          //Type of chain node (HEAD/NODE/TAIL)
	char *hostname_replica_next;               //Hostname of next replica in chain
	_server_tu_network_data *replica_next_net; //Pointer to the next on the replica
	connection_rdma *replica_next_control_con; /* Connection for sending spill_buffers during spills from master to back up servers */
	pthread_mutex_t region_initialization_lock;
	volatile region_status status;
} _tucana_region_S ;


typedef struct _RegionsSe
{

	//struct rb_root tree;			/* Red-black tree that keeps regions ranges kept at the server
	//					For each KV operation, the server locates the corresponding region
	//					performing a look up with its key in this structure*/
	struct String_vector* primary_zk_regions;	/* List with the regions names in which this server is the primary.
							This list is obtained from /servers/<hostname>/regions*/
	_tucana_region_S ** primary_tu_regions;		/*Array with the primary tucana_regions this server has.
							We keep a _tucana_region_S per zk_region*/
	struct String_vector* replica_zk_regions;	/* List with the regions names in which this server keeps a replica
							This list is kept at zookeeper under /servers/<hostname>/replicas */
	_tucana_region_S ** replica_tu_regions;		/*Array with the primary tucana_regions this server has */
	struct channel_rdma *channel;		/*RDMA channel for managing/storing the rdma_connections*/
	sem_t	sem_regions;			/*Server will be blocked until a region is available*/
	int initiated;
#if TU_TIMING
	pthread_mutex_t mutex_timing;     /* mutex for controlling time*/
	double time_to_submit;		/*Time to submit the message*/
#endif
	pthread_mutex_t mutex_n_open_dbs;     /*mutex for controlling time*/
	int32_t n_open_dbs;		      /*To indicate how many dbs are open (primary + replica)*/
} _RegionsSe;


typedef struct _tucana_region_Replica
{
	_ID_region ID_region;		// ID of the region, including the range
	db_handle *db;			// Tucana tree itself
	int tail;			// 1 -> this node is the tail
					// 0 -> This node is an intermediate node

	void *chain_replication;	// Chain for the replication of this region
	void *receive_replica_mailbox;		// Mailbox for receiving ACK of replicated requests
	void *send_replica_mailbox;		// Mailbox for sending replica requests
	void *list_pending_replicated;	// List of request replicated, but not ACK yet by the chain
	//...................
} _tucana_region_Replica ;

typedef struct _ReplicasSe {
	 struct String_vector* zk_replicas;		// List with the regions that for this server the zookeper has
							// This list is obtained from /servers/hostname/regions/
	_tucana_region_Replica ** tu_replicas;		// Array with the tucana_regions the server has.
							// There is an element per region, therefore, as many as zk_regions we have
} _ReplicasSe;


int _init_replica_rdma_connections(_tucana_region_S *S_tu_region);

/* regions soft state kept in server functions */
void init_kreon_regions_manager();
_tucana_region_S * get_first_region();
_tucana_region_S * find_region(void *key, int key_size);
 int add_region(_tucana_region_S* region);
 int delete_region(_tucana_region_S * region);


_tucana_region_S * get_region(void *key, int key_len);
void * allocate_spill_buffer(_tucana_region_S * region, int size);
void  free_spill_buffer(_tucana_region_S * region, void * spill_buffer);



#if TU_TIMING
static inline void Server_Init_Times_Regions( _RegionsSe *client_regions )
{
	int i;

	for ( i = 0; i <  client_regions->zk_regions->count; i ++ ){
		client_regions->tu_regions[i]->time_to_prepare = 0 ;
		client_regions->tu_regions[i]->time_to_receive = 0;
	}
	client_regions->time_to_submit = 0;
}

static inline void Server_Print_Times_per_region( _tucana_region_S* serv_tu_region )
{
	printf("Time_Prepare %lf\n", serv_tu_region->time_to_prepare );
	//printf("Time_Send %lf\n", serv_tu_region->time_to_submit );
	printf("Time_Receive %lf\n", serv_tu_region->time_to_receive );

}
static inline void Server_Print_Times_Regions( _RegionsSe *client_regions )
{
	int i;
	double total_prepare = 0;
	double total_receive = 0;
	for ( i = 0; i <  client_regions->zk_regions->count; i ++ ){
		#if 0
		printf("Time_Prepare %lf\n", client_regions->tu_regions[i]->time_to_prepare );
		printf("Time_Receive %lf\n", client_regions->tu_regions[i]->time_to_receive );
		#endif
		total_prepare += client_regions->tu_regions[i]->time_to_prepare;
		total_receive += client_regions->tu_regions[i]->time_to_receive;
	}
	printf("TOTAL_Time_Prepare %lf\n", total_prepare );
	printf("TOTAL_Time_Send %lf\n", client_regions->time_to_submit);
	printf("TOTAL_Time_Receive %lf\n", total_receive );
}

static inline void Server_Update_Time_Prepare(  _tucana_region_S* serv_tu_region,  struct timeval *start, struct timeval *end )
{
	double delta = 0 ;
	delta = ((end->tv_sec  - start->tv_sec) * 1000000u + end->tv_usec - start->tv_usec) / 1.e6;
	pthread_mutex_lock( &serv_tu_region->mutex_timing );     
	serv_tu_region->time_to_prepare += delta ;
	pthread_mutex_unlock( &serv_tu_region->mutex_timing );  
}
static inline void Server_Update_Time_Submit(  _RegionsSe * serv_tu_region_S,  struct timeval *start, struct timeval *end )
{
	double delta = 0 ;
	delta = ((end->tv_sec  - start->tv_sec) * 1000000u + end->tv_usec - start->tv_usec) / 1.e6;
	pthread_mutex_lock( &serv_tu_region_S->mutex_timing );     
	serv_tu_region_S->time_to_submit += delta ;
	pthread_mutex_unlock( &serv_tu_region_S->mutex_timing );  
}
static inline void Server_Update_Time_Receive(  _tucana_region_S* serv_tu_region,  struct timeval *start, struct timeval *end )
{
	double delta = 0 ;
	delta = ((end->tv_sec  - start->tv_sec) * 1000000u + end->tv_usec - start->tv_usec) / 1.e6;
	pthread_mutex_lock( &serv_tu_region->mutex_timing );     
	serv_tu_region->time_to_receive += delta ;
	pthread_mutex_unlock( &serv_tu_region->mutex_timing );  
}
#endif



#endif

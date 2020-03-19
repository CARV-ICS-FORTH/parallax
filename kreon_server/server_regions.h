//
//  tucana_regions.h
//  Tucana Regions
//
//  Created by Pilar Gonzalez-Ferez on 28/07/16.
//  Copyright (c) 2016 Pilar Gonzalez Ferez <pilar@ics.forth.gr>.
//
#pragma once
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

enum replica_type { NON_REPLICA = 0, REPLICA_HEAD, REPLICA_NODE, REPLICA_TAIL };

typedef struct group_membership_entry {
	int32_t state;
	int32_t current_group_size;
	int32_t max_group_size;
	uint64_t uuid;
	char hostname[MAX_HOSTNAME];
} group_membership_entry;

#define SE_REPLICA_NUM_SEGMENTS 4
#define SE_REGION_KEY_SIZE 256
/*this staff are rdma registered*/
typedef struct se_seg_metadata {
	uint64_t master_segment;
	uint64_t end_of_log;
	uint64_t log_padding;
	uint64_t segment_id;
	uint32_t region_key_size;
	char region_key[SE_REGION_KEY_SIZE];
	uint64_t tail;
} se_seg_metadata;

typedef struct se_rdma_buffer {
	struct tu_data_message msg;
	se_seg_metadata metadata;
	char padding[4096 - sizeof(se_seg_metadata)];
	uint8_t seg[SEGMENT_SIZE];
} se_rdma_buffer;

typedef struct se_replica_log_segment {
	se_rdma_buffer *rdma_local_buf;
	se_rdma_buffer *rdma_remote_buf;
	int64_t bytes_wr_per_seg;
	int64_t buffer_free;
} se_replica_log_segment;

typedef struct se_seg_bound{
	uint64_t start;
	uint64_t end;
}se_seg_bound;

typedef struct se_replica_log_buffer {
	/*put <start, end> for each segment here to fit in one cache line and search them faster :-)*/
	se_seg_bound bounds[SE_REPLICA_NUM_SEGMENTS];
	se_replica_log_segment seg_bufs[SE_REPLICA_NUM_SEGMENTS];
} se_replica_log_buffer;



#define MAX_TREE_HEIGHT 12
typedef struct _tucana_region_S {
	/*parameters used for remote spills at replica with tiering*/
	node_header *last_node_per_level[MAX_TREE_HEIGHT];
	uint64_t cur_nodes_per_level[MAX_TREE_HEIGHT];
	uint64_t num_of_nodes_per_level[MAX_TREE_HEIGHT];
	uint64_t entries_in_semilast_node[MAX_TREE_HEIGHT];
	uint64_t entries_in_last_node[MAX_TREE_HEIGHT];
	uint32_t current_active_tree_in_the_forest;
	/* Connection to next in chain */
	connection_rdma *replica_next_data_con;
	union {
		se_replica_log_buffer *rep_master_buf;
		se_replica_log_buffer *master_rep_buf;
	};
	// ID of the region, including the range, XXX TODO XXX patch not fix.
	// Must be first as also in _client_tucana_region otherwise rbtree does not work
	_ID_region ID_region;
	group_membership_entry gmt;
	// path name of the device, such as /dev/md0
	char *device;
	// It is allocated dynamically
	uint64_t size; // Size of the device in bytes. Total Size. It should not change never
	uint64_t offset; // Position where the segment start.
	int has_offset; // 0 no offset yet, 1 offset yet
	/*kreon handle*/
	db_handle *db;

	/*parameters for to ensure log buffer has been completely written prior to*/
	long active_region_threads;

	int ready_db; // 0 the DB is not open, 1 it is open
	int replica_connection_state;
	//mailbox_t *data_mailbox[MAX_MAILBOX];		// Mailbox for receiving request
	int next_mail; //from 0 to 4
	// This region has been already inserted in the rb_tree.
	int inserted_tree;
	int32_t n_replicas; //Number of elements that compose the chain of this region
	char **replicas_hostname; //List of hostnames with the replicas names
	int replica_type; //Type of chain node (HEAD/NODE/TAIL)
	char *hostname_replica_next; //Hostname of next replica in chain
	_server_tu_network_data *replica_next_net; //Pointer to the next on the replica
	connection_rdma *
		replica_next_control_con; /* Connection for sending spill_buffers during spills from master to back up servers */
	pthread_mutex_t region_initialization_lock;
	volatile region_status status;
} _tucana_region_S;

typedef struct _RegionsSe {
	//struct rb_root tree;			/* Red-black tree that keeps regions ranges kept at the server
	//					For each KV operation, the server locates the corresponding region
	//					performing a look up with its key in this structure*/
	struct String_vector *primary_zk_regions; /* List with the regions names in which this server is the primary.
							This list is obtained from /servers/<hostname>/regions*/
	_tucana_region_S **primary_tu_regions; /*Array with the primary tucana_regions this server has.
							We keep a _tucana_region_S per zk_region*/
	struct String_vector *replica_zk_regions; /* List with the regions names in which this server keeps a replica
							This list is kept at zookeeper under /servers/<hostname>/replicas */
	_tucana_region_S **replica_tu_regions; /*Array with the primary tucana_regions this server has */
	struct channel_rdma *channel; /*RDMA channel for managing/storing the rdma_connections*/
	sem_t sem_regions; /*Server will be blocked until a region is available*/
	int initiated;

	pthread_mutex_t mutex_n_open_dbs; /*mutex for controlling time*/
	int32_t n_open_dbs; /*To indicate how many dbs are open (primary + replica)*/
} _RegionsSe;

int _init_replica_rdma_connections(_tucana_region_S *S_tu_region);

/* regions soft state kept in server functions */
void init_kreon_regions_manager();
_tucana_region_S *get_first_region();
_tucana_region_S *find_region(void *key, int key_size);
int add_region(_tucana_region_S *region);
int delete_region(_tucana_region_S *region);

_tucana_region_S *get_region(void *key, int key_len);
void *allocate_spill_buffer(_tucana_region_S *region, int size);
void free_spill_buffer(_tucana_region_S *region, void *spill_buffer);


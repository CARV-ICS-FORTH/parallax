#pragma once
#define KRM_HOSTNAME_SIZE 128
#define IP_SIZE 4
#include <stdint.h>
#include <semaphore.h>
#include <zookeeper/zookeeper.h>
#include "../utilities/list.h"
#include "../kreon_lib/btree/btree.h"
#include "../kreon_lib/btree/uthash.h"
#include "../kreon_rdma/rdma.h"
#define KRM_MAX_REGIONS 1024
#define KRM_MAX_DS_REGIONS 256
#define KRM_MAX_KEY_SIZE 64
#define KRM_MAX_REGION_ID_SIZE 16
#define KRM_MAX_BACKUPS 4
#define KRM_MAX_RDMA_IP_SIZE 22
#define KRM_ROOT_PATH "/kreonR"
#define KRM_SERVERS_PATH "/servers"
#define KRM_SLASH "/"
#define KRM_LEADER_PATH "/leader"
#define KRM_MAILBOX_PATH "/mailbox"
#define KRM_MAIL_TITLE "/msg"
#define KRM_ALIVE_SERVERS_PATH "/alive_dataservers"
#define KRM_ALIVE_LEADER_PATH "/alive_leader"
#define KRM_REGIONS_PATH "/regions"

#define RU_REPLICA_NUM_SEGMENTS 4
#define RU_REGION_KEY_SIZE 256
#define RU_MAX_TREE_HEIGHT 12

enum krm_zk_conn_state { KRM_INIT, KRM_CONNECTED, KRM_DISCONNECTED, KRM_EXPIRED };

enum krm_server_state {
	KRM_BOOTING = 1,
	KRM_CLEAN_MAILBOX,
	KRM_SET_DS_WATCHERS,
	KRM_SET_LD_WATCHERS,
	KRM_BUILD_DATASERVERS_TABLE,
	KRM_BUILD_REGION_TABLE,
	KRM_ASSIGN_REGIONS,
	KRM_OPEN_LD_REGIONS,
	KRM_LD_ANNOUNCE_JOINED,
	KRM_DS_ANNOUNCE_JOINED,
	KRM_PROCESSING_MSG,
	KRM_WAITING_FOR_MSG
};

enum krm_server_role { KRM_LEADER, KRM_DATASERVER };

enum krm_region_role { KRM_PRIMARY, KRM_BACKUP };
enum krm_region_status { KRM_OPEN, KRM_OPENING, KRM_FRESH };

enum krm_msg_type {
	KRM_OPEN_REGION_AS_PRIMARY = 1,
	KRM_ACK_OPEN_PRIMARY,
	KRM_NACK_OPEN_PRIMARY,
	KRM_OPEN_REGION_AS_BACKUP,
	KRM_ACK_OPEN_BACKUP,
	KRM_NACK_OPEN_BACKUP,
	KRM_CLOSE_REGION,
	KRM_BUILD_PRIMARY
};

enum krm_error_code { KRM_SUCCESS = 0, KRM_BAD_EPOCH, KRM_DS_TABLE_FULL, KRM_REGION_EXISTS };

/*this staff are rdma registered*/
struct ru_seg_metadata {
	uint64_t master_segment;
	uint64_t end_of_log;
	uint64_t log_padding;
	uint64_t segment_id;
	uint32_t region_key_size;
	char region_key[RU_REGION_KEY_SIZE];
	uint64_t tail;
};

struct ru_rdma_buffer {
	struct msg_header msg;
	struct ru_seg_metadata metadata;
	char padding[4096 - sizeof(struct ru_seg_metadata)];
	uint8_t seg[SEGMENT_SIZE];
};

struct ru_replica_log_segment {
	struct ru_rdma_buffer *rdma_local_buf;
	struct ru_rdma_buffer *rdma_remote_buf;
	int64_t bytes_wr_per_seg;
	int64_t buffer_free;
};

struct ru_seg_bound {
	uint64_t start;
	uint64_t end;
};

struct ru_replica_log_buffer {
	/*put <start, end> for each segment here to fit in one cache line and search them faster :-)*/
	struct ru_seg_bound bounds[RU_REPLICA_NUM_SEGMENTS];
	struct ru_replica_log_segment seg_bufs[RU_REPLICA_NUM_SEGMENTS];
};

struct ru_replication_state {
	connection_rdma **data_conn;
	connection_rdma **control_conn;
	/*parameters used for remote spills at replica with tiering*/
	node_header *last_node_per_level[RU_MAX_TREE_HEIGHT];
	uint64_t cur_nodes_per_level[RU_MAX_TREE_HEIGHT];
	uint64_t num_of_nodes_per_level[RU_MAX_TREE_HEIGHT];
	uint64_t entries_in_semilast_node[RU_MAX_TREE_HEIGHT];
	uint64_t entries_in_last_node[RU_MAX_TREE_HEIGHT];
	uint32_t current_active_tree_in_the_forest;
	union {
		struct ru_replica_log_buffer *rep_master_buf;
		struct ru_replica_log_buffer *master_rep_buf;
	};
};

struct krm_server_name {
	char hostname[KRM_HOSTNAME_SIZE];
	/*kreon hostname - RDMA port*/
	char kreon_ds_hostname[KRM_HOSTNAME_SIZE];
	char kreon_leader[KRM_HOSTNAME_SIZE];
	char RDMA_IP_addr[KRM_MAX_RDMA_IP_SIZE];
	uint32_t kreon_ds_hostname_length;
	uint64_t epoch;
};

struct krm_region {
	struct krm_server_name primary;
	struct krm_server_name backups[KRM_MAX_BACKUPS];
	uint32_t min_key_size;
	uint32_t max_key_size;
	char id[KRM_MAX_REGION_ID_SIZE];
	char min_key[KRM_MAX_KEY_SIZE];
	char max_key[KRM_MAX_KEY_SIZE];
	uint32_t num_of_backup;
	enum krm_region_status status;
};

struct krm_region_desc {
	struct krm_region *region;
	enum krm_region_role role;
	db_handle *db;
	int init_rdma_conn;
	struct ru_replication_state *r_state;
};

struct krm_ds_regions {
	struct krm_region_desc r_desc[KRM_MAX_DS_REGIONS];
	uint64_t lamport_counter_1;
	uint64_t lamport_counter_2;
	uint32_t num_ds_regions;
};

struct krm_leader_regions {
	struct krm_region regions[KRM_MAX_REGIONS];
	int num_regions;
};

struct krm_regions_per_server {
	struct krm_server_name server_id;
	uint64_t hash_key;
	LIST *regions;
	UT_hash_handle hh;
};

struct krm_server_desc {
	struct krm_server_name name;
	char mail_path[KRM_HOSTNAME_SIZE];
	sem_t wake_up;
	pthread_mutex_t msg_list_lock;
	LIST *msg_list;
	zhandle_t *zh;
	uint8_t IP[IP_SIZE];
	uint8_t RDMA_IP[IP_SIZE];
	uint32_t RDMA_port;
	enum krm_server_role role;
	enum krm_server_state state;
	volatile uint32_t zconn_state;
	/*filled only by the leader server*/
	struct krm_leader_regions *ld_regions;
	struct krm_regions_per_server *dataservers_table;
	/*filled by the ds*/
	struct krm_ds_regions *ds_regions;
};

struct krm_msg {
	struct krm_region region;
	char sender[KRM_HOSTNAME_SIZE];
	enum krm_msg_type type;
	enum krm_error_code error_code;
	uint64_t epoch;
};

void *krm_metadata_server(void *args);
struct krm_region_desc *krm_get_region(char *key, uint32_t key_size);

int ru_flush_replica_log_buffer(db_handle *handle, segment_header *master_log_segment, void *buffer,
				uint64_t end_of_log, uint64_t bytes_to_pad, uint64_t segment_id);

void ru_calculate_btree_index_nodes(struct ru_replication_state *r_state, uint64_t num_of_keys);

void ru_append_entry_to_leaf_node(struct krm_region_desc *r_desc, void *pointer_to_kv_pair, void *prefix,
				  int32_t tree_id);

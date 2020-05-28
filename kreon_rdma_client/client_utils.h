#pragma once
#include <stdint.h>
#include <pthread.h>
#include "../kreon_server/metadata.h"
#include "../kreon_server/conf.h"
#include "../kreon_rdma/rdma.h"

struct cu_lamport_counter {
	uint64_t c1;
	uint64_t c2;
};

struct cu_region_desc {
	struct krm_region region;
	/*plus future other staff*/
};

typedef struct cu_conn_per_server {
	struct krm_server_name server_id;
	uint64_t hash_key;
	connection_rdma *connections[NUM_OF_CONNECTIONS_PER_SERVER];
	UT_hash_handle hh;
} cu_conn_per_server;

struct cu_regions {
	struct cu_region_desc r_desc[KRM_MAX_REGIONS];
	pthread_mutex_t r_lock;
	struct cu_lamport_counter lc;
	uint32_t num_regions;
	cu_conn_per_server *root_cps;
	struct cu_lamport_counter lc_conn;
	pthread_mutex_t conn_lock;
	struct channel_rdma *channel;
	/*plus future other staff*/
};

uint8_t cu_init(char *zookeeper_ip, int zk_port);
struct cu_region_desc *cu_get_region(char *key, uint32_t key_size);
struct cu_region_desc *cu_get_first_region(void);
connection_rdma *cu_get_conn_for_region(struct cu_region_desc *r_desc, uint64_t seed);
void cu_close_open_connections();

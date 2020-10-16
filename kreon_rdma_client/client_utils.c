#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <zookeeper/zookeeper.h>
#include "../kreon_server/globals.h"
#include "../kreon_server/zk_utils.h"
#include "../utilities/spin_loop.h"
#include "../kreon_server/djb2.h"
#include "client_utils.h"
#include <log.h>

static int cu_is_connected = 0;
static zhandle_t *cu_zh = NULL;
struct cu_regions client_regions;

static void _cu_zk_watcher(zhandle_t *zkh, int type, int state, const char *path, void *context)
{
	/*
 	* zookeeper_init might not have returned, so we
 	* use zkh instead.
 	*/
	if (type == ZOO_SESSION_EVENT) {
		if (state == ZOO_CONNECTED_STATE)
			cu_is_connected = 1;
		else if (state == ZOO_CONNECTING_STATE) {
			log_fatal("Disconnected from zookeeper");
			exit(EXIT_FAILURE);
		}
	}
}

static uint8_t _cu_insert_region(struct cu_regions *regions, struct cu_region_desc *c_region)
{
	int64_t ret;
	int start_idx = 0;
	int end_idx = regions->num_regions - 1;
	int middle = 0;
	uint8_t rc = 0;

	pthread_mutex_lock(&client_regions.r_lock);
	++client_regions.lc.c1;
	if (regions->num_regions == KRM_MAX_REGIONS) {
		log_warn("Warning! Adding new region failed, max_regions %d reached", KRM_MAX_REGIONS);
		rc = 0;
		goto exit;
	}

	if (regions->num_regions > 0) {
		while (start_idx <= end_idx) {
			middle = (start_idx + end_idx) / 2;
			ret = zku_key_cmp(regions->r_desc[middle].region.min_key_size,
					  regions->r_desc[middle].region.min_key, c_region->region.min_key_size,
					  c_region->region.min_key);
			//log_info("compared %s with %s got %ld", desc->ld_regions->regions[middle].min_key,
			//	 region->min_key, ret);
			if (ret == 0) {
				log_warn("Warning failed to add region, range already present\n");
				rc = 0;
				break;
			} else if (ret > 0) {
				end_idx = middle - 1;
				if (start_idx > end_idx) {
					memmove(&regions->r_desc[middle + 1], &regions->r_desc[middle],
						(regions->num_regions - middle) * sizeof(struct cu_region_desc));
					regions->r_desc[middle] = *c_region;
					++regions->num_regions;
					rc = 1;
					goto exit;
				}
			} else {
				start_idx = middle + 1;
				if (start_idx > end_idx) {
					middle++;
					memmove(&regions->r_desc[middle + 1], &regions->r_desc[middle],
						(regions->num_regions - middle) * sizeof(struct cu_region_desc));
					regions->r_desc[middle] = *c_region;
					++regions->num_regions;
					rc = 1;
					goto exit;
				}
			}
		}
	} else {
		regions->r_desc[0] = *c_region;
		++regions->num_regions;
		rc = 1;
	}
exit:
	++client_regions.lc.c2;
	pthread_mutex_unlock(&client_regions.r_lock);
	return rc;
}

uint8_t _cu_fetch_region_table()
{
	struct cu_region_desc r_desc;
	char *region = NULL;
	struct Stat stat;
	int ret = 0;

	if (cu_zh == NULL) {
		log_warn("ZK is not initialized!");
		return 0;
	}

	memset(&client_regions, 0x00, sizeof(struct cu_regions));
	/*get regions and fix table*/
	char *regions_path = zku_concat_strings(2, KRM_ROOT_PATH, KRM_REGIONS_PATH);
	struct String_vector *regions = (struct String_vector *)malloc(sizeof(struct String_vector));
	int rc = zoo_get_children(cu_zh, regions_path, 0, regions);
	if (rc != ZOK) {
		log_warn("Can't fetch regions from zookeeper path %s error code %s", regions_path, zku_op2String(rc));
		ret = 0;
		goto exit;
	}
	int i;
	int buffer_len = sizeof(struct krm_region);
	client_regions.num_regions = 0;
	for (i = 0; i < regions->count; i++) {
		/*iterate old mails and delete them*/
		region = zku_concat_strings(4, KRM_ROOT_PATH, KRM_REGIONS_PATH, KRM_SLASH, regions->data[i]);

		buffer_len = sizeof(struct krm_msg);
		rc = zoo_get(cu_zh, region, 0, (char *)&r_desc.region, &buffer_len, &stat);
		if (rc != ZOK) {
			log_warn("Failed to fetch region info %s with code %s", region, zku_op2String(rc));
			ret = 0;
			goto exit;
		}
		_cu_insert_region(&client_regions, &r_desc);
		free(region);
		region = NULL;
	}
exit:

	if (!region)
		free(region);
	free(regions_path);
	free(regions);
	ret = 1;
	return ret;
}

uint8_t cu_init(char *zookeeper_ip, int zk_port)
{
	LIBRARY_MODE = CLIENT_MODE;
	pthread_mutex_init(&client_regions.r_lock, NULL);
	pthread_mutex_init(&client_regions.conn_lock, NULL);
	globals_create_rdma_channel();
	/*channel related initializations*/
	//struct channel_rdma *channel = globals_get_rdma_channel();

	//channel->spinning_num_th = 1;

	/**/
	client_regions.lc.c1 = 0;
	client_regions.lc.c2 = 0;
	client_regions.lc_conn.c1 = 0;
	client_regions.lc_conn.c2 = 0;
	char *zk_host_port = malloc(strlen(zookeeper_ip) + 16);
	strcpy(zk_host_port, zookeeper_ip);
	*(char *)(zk_host_port + strlen(zookeeper_ip)) = ':';
	sprintf(zk_host_port + strlen(zookeeper_ip) + 1, "%d", zk_port);
	//log_info("Initializing, connectiong to zookeeper at %s", zk_host_port);
	globals_set_zk_host(zk_host_port);
	free(zk_host_port);
	cu_zh = zookeeper_init(globals_get_zk_host(), _cu_zk_watcher, 15000, 0, 0, 0);
	wait_for_value((uint32_t *)&cu_is_connected, 1);
	_cu_fetch_region_table();
	return 1;
}

struct cu_region_desc *cu_get_region(char *key, uint32_t key_size)
{
	struct cu_regions *cli_regions = &client_regions;
	struct cu_region_desc *region = NULL;
	int start_idx;
	int end_idx;
	int middle;
	int ret;

	uint64_t lc2, lc1;
retry:
	lc2 = client_regions.lc.c2;
	start_idx = 0;
	end_idx = cli_regions->num_regions - 1;
	region = NULL;

	while (start_idx <= end_idx) {
		middle = (start_idx + end_idx) / 2;
		ret = zku_key_cmp(cli_regions->r_desc[middle].region.min_key_size,
				  cli_regions->r_desc[middle].region.min_key, key_size, key);
		//log_info("Comparing region min %s with key %s ret %ld",
		//	 kreon_regions[middle]->ID_region.minimum_range + 4, key, ret);
		if (ret < 0 || ret == 0) {
			start_idx = middle + 1;
			if (zku_key_cmp(cli_regions->r_desc[middle].region.max_key_size,
					cli_regions->r_desc[middle].region.max_key, key_size, key) > 0) {
				region = &cli_regions->r_desc[middle];
				break;
			}
		} else
			end_idx = middle - 1;
	}
	lc1 = client_regions.lc.c1;
	if (lc1 != lc2)
		goto retry;

	if (region == NULL) {
		log_fatal("NULL region for key %s of size %u\n", key, key_size);
		exit(EXIT_FAILURE);
	}
	return region;
}

struct cu_region_desc *cu_get_first_region(void)
{
	struct cu_regions *cli_regions = &client_regions;
	if (cli_regions->num_regions == 0) {
		log_warn("Sorry no regions");
		return NULL;
	}
	return &cli_regions->r_desc[0];
}

static void _cu_add_conn_for_server(struct krm_server_name *server, uint64_t hash_key)
{
	char *host = server->RDMA_IP_addr;
	//log_info("Connection to RDMA IP %s", server->RDMA_IP_addr);
	cu_conn_per_server *cps = (cu_conn_per_server *)malloc(sizeof(cu_conn_per_server));
	cps->connections = (struct connection_rdma **)malloc(globals_get_connections_per_server() *
							     sizeof(struct connection_rdma *));
	for (int i = 0; i < globals_get_connections_per_server(); i++) {
		cps->connections[i] = crdma_client_create_connection_list_hosts(globals_get_rdma_channel(), &host, 1,
										CLIENT_TO_SERVER_CONNECTION);
	}
	cps->hash_key = hash_key;
	HASH_ADD_PTR(client_regions.root_cps, hash_key, cps);
}

connection_rdma *cu_get_conn_for_region(struct cu_region_desc *r_desc, uint64_t seed)
{
	cu_conn_per_server *cps = NULL;
	uint64_t hash_key;
	uint64_t c1, c2;

	hash_key = djb2_hash((unsigned char *)r_desc->region.primary.kreon_ds_hostname,
			     r_desc->region.primary.kreon_ds_hostname_length);
retry:
	cps = NULL;
	c2 = client_regions.lc_conn.c2;
	/*Do we have any open connections with the server?*/
	HASH_FIND_PTR(client_regions.root_cps, &hash_key, cps);
	c1 = client_regions.lc_conn.c1;
	if (c1 != c2)
		goto retry;
	if (cps == NULL) {
		pthread_mutex_lock(&client_regions.conn_lock);
		++client_regions.lc_conn.c1;
		HASH_FIND_PTR(client_regions.root_cps, &hash_key, cps);
		if (cps == NULL) {
			/*Refresh your knowledge about the server*/
			struct Stat stat;
			char *primary = zku_concat_strings(4, KRM_ROOT_PATH, KRM_SERVERS_PATH, KRM_SLASH,
							   r_desc->region.primary.kreon_ds_hostname);

			int buffer_len = sizeof(struct krm_server_name);
			int rc = zoo_get(cu_zh, primary, 0, (char *)&r_desc->region.primary, &buffer_len, &stat);
			if (rc != ZOK) {
				log_warn("Failed to refresh server info %s with code %s", primary, zku_op2String(rc));
				free(primary);
				++client_regions.lc_conn.c2;
				pthread_mutex_unlock(&client_regions.conn_lock);
				return NULL;
			}
			//log_info("RDMA addr = %s", r_desc->region.primary.RDMA_IP_addr);
			_cu_add_conn_for_server(&r_desc->region.primary, hash_key);
			++client_regions.lc_conn.c2;
		}
		pthread_mutex_unlock(&client_regions.conn_lock);
		goto retry;
	}
	return cps->connections[seed % globals_get_connections_per_server()];
}

void cu_close_open_connections()
{
	struct cu_conn_per_server *current = NULL;
	struct cu_conn_per_server *tmp = NULL;
	msg_header *req_header;
	int i;
	/*iterate all open connections and send the disconnect message*/
	HASH_ITER(hh, client_regions.root_cps, current, tmp)
	{
		//log_info("Closing connections with server %s", current->server_id.kreon_ds_hostname);
		for (i = 0; i < globals_get_connections_per_server(); i++) {
			/*send disconnect msg*/
			pthread_mutex_lock(&current->connections[i]->buffer_lock);
			req_header = client_allocate_rdma_message(current->connections[i], 0, DISCONNECT);
			pthread_mutex_unlock(&current->connections[i]->buffer_lock);
			req_header->reply = NULL;
			req_header->reply_length = 0;
			req_header->got_send_completion = 0;

			if (client_send_rdma_message(current->connections[i], req_header) != KREON_SUCCESS) {
				log_warn("failed to send message");
				exit(EXIT_FAILURE);
			}

			// FIXME calling free for the connection_rdma* isn't enough. We need to free the rest
			// of the resources allocated for the connection, like the memory region buffers
			free(current->connections[i]);
			//log_info("Closing connection number %d", i);
		}
		HASH_DEL(client_regions.root_cps, current);
		free(current); /* free it */
	}
}

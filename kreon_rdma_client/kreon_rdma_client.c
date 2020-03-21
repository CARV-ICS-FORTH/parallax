#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <immintrin.h>
#include "kreon_rdma_client.h"
#include "../kreon_rdma/rdma.h"
#include "../kreon_server/globals.h"
#include "../build/external-deps/log/src/log.h"

krc_handle *krc_init(char *zookeeper_ip, int zk_port, uint32_t *error_code)
{
	krc_handle *hd = (krc_handle *)malloc(sizeof(krc_handle));
	char *zk_host_port = malloc(strlen(zookeeper_ip) + 16);
	strcpy(zk_host_port, zookeeper_ip);
	*(char *)(zk_host_port + strlen(zookeeper_ip)) = ':';
	sprintf(zk_host_port + strlen(zookeeper_ip) + 1, "%d", zk_port);
	log_info("Initializing, connectiong to zookeeper at %s", zk_host_port);
	globals_set_zk_host(zookeeper_host_port);
	free(zk_host_port);
	hd->client_regions = Allocate_Init_Client_Regions();
	while (hd->client_regions->num_regions_connected < 1) {
		log_warn("No regions yet");
		sleep(1);
	}
	*error_code = KRC_SUCCESS;
	return hd;
}

uint32_t krc_put(krc_handle *hd, uint32_t key_size, void *key, uint32_t val_size, void *value)
{
	tu_data_message *req_msg;
	tu_data_message *rep_msg;
	int mailbox; //note this is useless needs refactoring

	client_region *region =
		Client_Get_Tu_Region_and_Mailbox(hd->client_regions, (char *)key, key_size, 0, &mailbox);
	connection_rdma *conn = get_connection_from_region(region, (uint64_t)key);

	req_msg = allocate_rdma_message(conn, key_size + val_size + (2 * sizeof(uint32_t)), TU_GET_QUERY);
	/*fill in the key payload part the data*/
	*(uint32_t *)req_msg->next = key_size;
	req_msg->next += sizeof(uint32_t);
	if (!push_buffer_in_tu_data_message(req_msg, key, key_size)) {
		log_fatal("Failed to fill rdma buffer");
		exit(EXIT_FAILURE);
	}

	rep_msg = NULL;
	req_msg->request_message_local_addr = req_msg;
	req_msg->ack_arrived = KR_REP_PENDING;
	/*Spin until reply*/
	while (req_msg->ack_arrived == KR_REP_PENDING)
		_mm_pause();
	assert(req_msg->reply != NULL);
	rep_msg = req_msg->reply;

	client_free_rpc_pair(conn, req_msg);
	/*check ret code*/
	if (rep_msg->error_code != KREON_SUCCESS) {
		log_fatal("put operation failed for key %s", key);
		exit(EXIT_FAILURE);
	}
	return KRC_SUCCESS;
}

krc_value *get(krc_handle *hd, uint32_t key_size, void *key, uint32_t *error_code)
{
	tu_data_message *req_msg;
	tu_data_message *rep_msg;
	int mailbox; //note this is useless needs refactoring

	client_region *region =
		Client_Get_Tu_Region_and_Mailbox(hd->client_regions, (char *)key, key_size, 0, &mailbox);
	connection_rdma *conn = get_connection_from_region(region, (uint64_t)key);

	req_msg = allocate_rdma_message(conn, key_size + sizeof(uint32_t), TU_GET_QUERY);
	/*fill in the key payload part the data*/
	*(uint32_t *)req_msg->next = key_size;
	req_msg->next += sizeof(uint32_t);
	if (!push_buffer_in_tu_data_message(req_msg, key, key_size)) {
		log_fatal("Failed to fill rdma buffer");
		exit(EXIT_FAILURE);
	}

	rep_msg = NULL;
	req_msg->request_message_local_addr = req_msg;
	req_msg->ack_arrived = KR_REP_PENDING;
	/*Spin until reply*/
	while (req_msg->ack_arrived == KR_REP_PENDING)
		_mm_pause();
	assert(req_msg->reply != NULL);
	rep_msg = req_msg->reply;

	*error_code = rep_msg->error_code;

	/*check ret code*/
	if (*error_code != KREON_SUCCESS) {
		log_warn("get operation failed for key %s with code %d", key, rep_msg->error_code);
		client_free_rpc_pair(conn, req_msg);
		return NULL;
	} else {
		uint32_t rep_size = *(uint32_t *)rep_msg->data;
		krc_value *value = malloc(sizeof(krc_value) + rep_size);
		value->val_size = rep_size;
		memcpy(value->val_buf, rep_msg->data + sizeof(uint32_t), rep_size);
		client_free_rpc_pair(conn, req_msg);
		return value;
	}
}


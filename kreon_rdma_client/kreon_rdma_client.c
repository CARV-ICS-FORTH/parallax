#include <stdint.h>
#include <stdio.h>
#include <string.h>
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

uint32_t krc_put(krc_handle *hd, krc_key *key, krc_value *value)
{
	struct tu_data_message *req_msg;
	struct tu_data_message *rep_msg;
	int mailbox; //note this is useless needs refactoring
	client_region *region =
		Client_Get_Tu_Region_and_Mailbox(hd->client_regions, (char *)key->key_buf, key->key_size, 0, &mailbox);
	connection_rdma *conn = get_connection_from_region(region, (uint64_t)key->key_buf);

	req_msg = allocate_rdma_message(conn, key->key_size + value->value_size + (2 * sizeof(uint64_t)), PUT_REQUEST);
	/*fill in the key payload part the data*/
	if (!push_buffer_in_tu_data_message(req_msg, &key, sizeof(krc_key) + key->keysize)) {
		log_fatal("Failed to fill rdma buffer");
		exit(EXIT_FAILURE);
	}

	/*Now the data*/
	if (!push_buffer_in_tu_data_message(req_msg, &value, sizeof(krc_value) + key->val_size)) {
		log_fatal("Failed to fill rdma buffer");
		exit(EXIT_FAILURE);
	}

	rep_msg = NULL;
	req_msg->request_message_local_addr = req_msg;
	req_msg->ack_arrived = KR_REP_PENDING;
	/*Spin until reply*/
	while(req->msg->ack_arrived == KR_REP_PENDING)
		__mm_pause();


	return KRC_SUCCESS;
}

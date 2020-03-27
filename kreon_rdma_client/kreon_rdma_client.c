#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <immintrin.h>
#include "kreon_rdma_client.h"
#include "../kreon_rdma/rdma.h"
#include "../kreon_server/globals.h"
#include "../build/external-deps/log/src/log.h"

static char *neg_infinity = "-oo";

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
	msg_header *req_msg;
	msg_header *rep_msg;
	int mailbox; //note this is useless needs refactoring

	client_region *region =
		Client_Get_Tu_Region_and_Mailbox(hd->client_regions, (char *)key, key_size, 0, &mailbox);
	connection_rdma *conn = get_connection_from_region(region, (uint64_t)key);

	req_msg = allocate_rdma_message(conn, key_size + val_size + (2 * sizeof(uint32_t)), PUT_REQUEST);
	/*fill in the key payload part the data*/
	*(uint32_t *)req_msg->next = key_size;
	req_msg->next += sizeof(uint32_t);
	if (!push_buffer_in_msg_header(req_msg, key, key_size)) {
		log_fatal("Failed to fill rdma buffer");
		exit(EXIT_FAILURE);
	}

	*(uint32_t *)req_msg->next = val_size;
	req_msg->next += sizeof(uint32_t);
	if (!push_buffer_in_msg_header(req_msg, value, val_size)) {
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
	msg_header *req_msg;
	msg_header *rep_msg;
	int mailbox; //note this is useless needs refactoring

	client_region *region =
		Client_Get_Tu_Region_and_Mailbox(hd->client_regions, (char *)key, key_size, 0, &mailbox);
	connection_rdma *conn = get_connection_from_region(region, (uint64_t)key);

	req_msg = allocate_rdma_message(conn, key_size + sizeof(uint32_t), TU_GET_QUERY);
	/*fill in the key payload part the data*/
	*(uint32_t *)req_msg->next = key_size;
	req_msg->next += sizeof(uint32_t);
	if (!push_buffer_in_msg_header(req_msg, key, key_size)) {
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

/*scanner staff*/
krc_scanner *krc_scan_init(krc_handle *hd, uint32_t prefetch_num_entries, uint32_t prefetch_mem_size)
{
	krc_scanner *scanner = (krc_scanner *)malloc(sizeof(krc_scanner) + prefetch_mem_size);
	scanner->hd = hd;
	scanner->prefix_key = NULL;
	scanner->start_key = NULL;
	scanner->stop_key = NULL;
	scanner->prefetch_num_entries = prefetch_num_entries;
	scanner->prefetch_mem_size = prefetch_mem_size;
	scanner->pos = 0;
	scanner->start_infinite = 1;
	scanner->stop_infinite = 1;
	scanner->prefix_filter_enable = 0;
	scanner->state = KRC_UNITIALIZED;
	scanner->multi_kv_buf = (msg_multi_get_rep *)malloc(sizeof(msg_multi_get_rep) + scanner->prefetch_mem_size);
	return scanner;
}

void krc_scan_get_next(krc_scanner *sc)
{
	msg_header *req_header;
	msg_multi_get_req *m_get;
	msg_header *rep_header;
	msg_multi_get_rep *m_get_rep;
	connection_rdma *conn;
	char *seek_key;
	uint32_t seek_key_size;
	uint32_t seek_mode;
	int mailbox; //note this is useless needs refactoring

	while (1) {
		switch (sc->state) {
		case KRC_UNITIALIZED:
			if (!sc->start_infinite) {
				seek_key = sc->start_key->key_buf;
				seek_key_size = sc->start_key->key_size;
			} else {
				seek_key = neg_infinity;
				seek_key_size = 4;
			}
			seek_mode = GREATER_OR_EQUAL;
			sc->state = KRC_ISSUE_MGET_REQ;
			break;

		case KRC_FETCH_NEXT_BATCH:
			/*seek key will be the last of the batch*/
			seek_key = sc->curr_key->key_buf;
			seek_key_size = sc->curr_key->key_size;
			seek_mode = GREATER;
			sc->state = KRC_ISSUE_MGET_REQ;
			break;

		case KRC_ISSUE_MGET_REQ:
			sc->region = Client_Get_Tu_Region_and_Mailbox(sc->hd->client_regions, seek_key, seek_key_size,
								      0, &mailbox);
			conn = get_connection_from_region(sc->region, (uint64_t)sc->start_key);
			/*the request part*/
			req_header = allocate_rdma_message(conn, sizeof(msg_multi_get_req) + seek_key_size,
							   MULTI_GET_REQUEST);
			m_get = (msg_multi_get_req *)((uint64_t)req_header + sizeof(msg_header));
			m_get->max_num_entries = sc->prefetch_num_entries;
			m_get->seek_mode = seek_mode;
			m_get->seek_key_size = seek_key_size;
			memcpy(m_get->seek_key, seek_key, seek_key_size);
			/*the reply part*/
			rep_header = allocate_rdma_message(conn, sizeof(msg_multi_get_rep) + sc->prefetch_mem_size,
							   MULTI_GET_REPLY);
			req_header->reply =
				(char *)((uint64_t)rep_header - (uint64_t)conn->recv_circular_buf->memory_region);
			rep_header->reply_length =
				sizeof(msg_header) + sizeof(msg_multi_get_rep) + sc->prefetch_mem_size;
			rep_header->receive = 0;
			/*sent the request*/
			if (send_rdma_message_busy_wait(conn, req_header) != KREON_SUCCESS) {
				log_warn("failed to send message");
				exit(EXIT_FAILURE);
			}
			/*Spin until reply*/
			while (req_header->ack_arrived == KR_REP_PENDING)
				_mm_pause();

			m_get_rep = (msg_multi_get_rep *)((uint64_t)rep_header + sizeof(msg_header));

			if (m_get_rep->buffer_overflow) {
				sc->state = KRC_BUFFER_OVERFLOW;
				break;
			}
			/*copy to local buffer to free rdma communication buffer*/
			memcpy(sc->multi_kv_buf, m_get_rep, sizeof(msg_multi_get_rep) + sc->prefetch_mem_size);
			client_free_rpc_pair(conn, rep_header);
			sc->state = KRC_ADVANCE;
			break;
		case KRC_ADVANCE:
			/*point to the next element*/
			if (sc->multi_kv_buf->curr_entry < sc->multi_kv_buf->num_entries) {
				sc->curr_key = (krc_key *)sc->multi_kv_buf->kv_buffer + sc->multi_kv_buf->pos;
				sc->multi_kv_buf->pos += (sizeof(krc_key) + sc->curr_key->key_size);
				sc->curr_value = (krc_value *)sc->multi_kv_buf->kv_buffer + sc->multi_kv_buf->pos;
				sc->multi_kv_buf->pos += (sizeof(krc_value) + sc->curr_value->val_size);
				++sc->multi_kv_buf->curr_entry;
				return;
			} else {
				if (sc->multi_kv_buf->end_of_region &&
				    !strcmp(sc->region->ID_region.maximum_range, "+oo")) {
					seek_key = sc->region->ID_region.maximum_range;
					seek_key_size = strlen(seek_key) + 1;
					sc->state = KRC_FETCH_NEXT_BATCH;
				} else
					sc->state = KRC_END_OF_DB;
			}
			break;
		case KRC_BUFFER_OVERFLOW:
		case KRC_END_OF_DB:
			sc->curr_key = NULL;
			sc->curr_value = NULL;
			sc->is_valid = 0;
			return;
		default:
			log_fatal("faulty scanner state");
			exit(EXIT_FAILURE);
		}
	}
}

void krc_scan_set_start(krc_scanner *sc, uint32_t start_key_size, void *start_key)
{
	if (!sc->start_infinite) {
		log_warn("Nothing to do already set start key for this scanner");
		return;
	}
	sc->start_infinite = 0;
	sc->start_key = (krc_key *)malloc(sizeof(krc_key) + start_key_size);
	sc->start_key->key_size = start_key_size;
	memcpy(sc->start_key->key_buf, start_key, start_key_size);
	return;
}

void krc_scan_set_stop(krc_scanner *sc, uint32_t stop_key_size, void *stop_key)
{
	if (!sc->stop_infinite) {
		log_warn("Nothing to do already set stop key for this scanner");
		return;
	}
	sc->stop_infinite = 0;
	sc->stop_key = (krc_key *)malloc(sizeof(krc_key) + stop_key_size);
	sc->stop_key->key_size = stop_key_size;
	memcpy(sc->stop_key->key_buf, stop_key, stop_key_size);
	return;
}

void krc_scan_set_prefix_filter(krc_scanner *sc, uint32_t prefix_size, void *prefix)
{
	if (sc->prefix_filter_enable) {
		log_warn("Nothing to do already set prefix key for this scanner");
		return;
	}
	sc->prefix_filter_enable = 0;
	sc->prefix_key = (krc_key *)malloc(sizeof(krc_key) + prefix_size);
	sc->prefix_key->key_size = prefix_size;
	memcpy(sc->prefix_key->key_buf, prefix, prefix_size);
	return;
}

void krc_scan_close(krc_scanner *sc)
{
	if (sc->prefix_filter_enable)
		free(sc->prefix_key);
	if (!sc->start_infinite)
		free(sc->start_key);
	if (!sc->stop_infinite)
		free(sc->stop_key);
	return;
}

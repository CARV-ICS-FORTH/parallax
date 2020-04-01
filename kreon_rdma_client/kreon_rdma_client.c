#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <immintrin.h>
#include "kreon_rdma_client.h"
#include "../kreon_server/client_regions.h"
#include "../kreon_rdma/rdma.h"
#include "../kreon_server/globals.h"
#include "../build/external-deps/log/src/log.h"

static char *neg_infinity = "00000000";

ZooLogLevel logLevel = ZOO_LOG_LEVEL_INFO;

static _Client_Regions *client_regions = NULL;

krc_ret_code krc_init(char *zookeeper_ip, int zk_port)
{
	globals_disable_client_spinning_thread();
	char *zk_host_port = malloc(strlen(zookeeper_ip) + 16);
	strcpy(zk_host_port, zookeeper_ip);
	*(char *)(zk_host_port + strlen(zookeeper_ip)) = ':';
	sprintf(zk_host_port + strlen(zookeeper_ip) + 1, "%d", zk_port);
	log_info("Initializing, connectiong to zookeeper at %s", zk_host_port);
	globals_set_zk_host(zk_host_port);
	free(zk_host_port);
	client_regions = Allocate_Init_Client_Regions();
	while (client_regions->num_regions_connected < 1) {
		log_warn("No regions yet");
		sleep(1);
	}
	return KRC_SUCCESS;
}

uint32_t krc_put(uint32_t key_size, void *key, uint32_t val_size, void *value)
{
	msg_header *req_header;
	msg_put_key *put_key;
	msg_put_value *put_value;
	msg_header *rep_header;
	msg_put_rep *put_rep;

	if (key_size + val_size + (2 * sizeof(uint32_t)) > SEGMENT_SIZE - sizeof(segment_header)) {
		log_fatal("KV size too large currently for Kreon, current max value size supported = %u bytes",
			  SEGMENT_SIZE - sizeof(segment_header));
		log_fatal("Contact gesalous@ics.forth.gr");
		exit(EXIT_FAILURE);
	}
	client_region *region = client_find_region(key, key_size);
	connection_rdma *conn = get_connection_from_region(region, (uint64_t)key);

	req_header = allocate_rdma_message(conn, key_size + val_size + (2 * sizeof(uint32_t)), PUT_REQUEST);
	put_key = (msg_put_key *)((uint64_t)req_header + sizeof(msg_header));
	/*fill in the key payload part the data, caution we are 100% sure that it fits :-)*/
	put_key->key_size = key_size;
	memcpy(put_key->key, key, key_size);
	put_value = (msg_put_value *)((uint64_t)put_key + sizeof(msg_put_key) + put_key->key_size);
	put_value->value_size = val_size;
	memcpy(put_value->value, value, val_size);

	/*Now the reply part*/
	rep_header = allocate_rdma_message(conn, sizeof(msg_put_rep), PUT_REPLY);
	rep_header->receive = 0;
	put_rep = (msg_put_rep *)((uint64_t)rep_header + sizeof(msg_header));
	put_rep->status = KR_REP_PENDING;

	/*inform the req about its buddy*/
	req_header->request_message_local_addr = req_header;
	req_header->ack_arrived = KR_REP_PENDING;
	/*location where server should put the reply*/
	req_header->reply = (char *)((uint64_t)rep_header - (uint64_t)conn->recv_circular_buf->memory_region);
	req_header->reply_length = sizeof(msg_header) + rep_header->pay_len + rep_header->padding_and_tail;

	/*send the actual put*/
	if (send_rdma_message_busy_wait(conn, req_header) != KREON_SUCCESS) {
		log_warn("failed to send message");
		exit(EXIT_FAILURE);
	}

	/*Spin until header arrives*/
	while (rep_header->receive != TU_RDMA_REGULAR_MSG)
		_mm_pause();
	rep_header->receive = 0;
	/*Spin until payload arrives*/
	uint32_t *tail = (uint32_t *)(((uint64_t)rep_header + sizeof(msg_header) + rep_header->pay_len +
				       rep_header->padding_and_tail) -
				      TU_TAIL_SIZE);
	while (*tail != TU_RDMA_REGULAR_MSG)
		_mm_pause();
	*tail = 0;
	put_rep = (msg_put_rep *)((uint64_t)rep_header + sizeof(msg_header));
	/*check ret code*/
	if (put_rep->status != KREON_SUCCESS) {
		log_fatal("put operation failed for key %s", key);
		exit(EXIT_FAILURE);
	}
	_zero_rendezvous_locations(rep_header);
	client_free_rpc_pair(conn, rep_header);
	return KRC_SUCCESS;
}

krc_value *krc_get(uint32_t key_size, void *key, uint32_t reply_length, uint32_t *error_code)
{
	krc_value *val = NULL;
	client_region *region = client_find_region(key, key_size);
	connection_rdma *conn = get_connection_from_region(region, (uint64_t)key);
	/*the request part*/
	msg_header *req_header = allocate_rdma_message(conn, sizeof(msg_get_req) + key_size, TU_GET_QUERY);

	msg_get_req *m_get = (msg_get_req *)((uint64_t)req_header + sizeof(msg_header));
	m_get->key_size = key_size;
	memcpy(m_get->key, key, key_size);
	/*the reply part*/
	msg_header *rep_header = allocate_rdma_message(conn, sizeof(msg_get_req) + reply_length, TU_GET_REPLY);
	req_header->reply = (char *)((uint64_t)rep_header - (uint64_t)conn->recv_circular_buf->memory_region);
	req_header->reply_length = sizeof(msg_header) + rep_header->pay_len + rep_header->padding_and_tail;

	req_header->request_message_local_addr = req_header;
	rep_header->receive = 0;
	/*sent the request*/
	if (send_rdma_message_busy_wait(conn, req_header) != KREON_SUCCESS) {
		log_warn("failed to send message");
		exit(EXIT_FAILURE);
	}
	/*Spin until header arrives*/
	while (rep_header->receive != TU_RDMA_REGULAR_MSG)
		_mm_pause();
	/*Spin until payload arrives*/
	uint32_t *tail = (uint32_t *)(((uint64_t)rep_header + sizeof(msg_header) + rep_header->pay_len +
				       rep_header->padding_and_tail) -
				      TU_TAIL_SIZE);

	while (*tail != TU_RDMA_REGULAR_MSG)
		_mm_pause();
	msg_get_rep *get_rep = (msg_get_rep *)((uint64_t)rep_header + sizeof(msg_header));

	if (get_rep->buffer_overflow) {
		log_warn("Receive buffer is smaller than the actual reply :-(");
		*error_code = KRC_BUFFER_OVERFLOW;
		goto exit;
	}

	if (!get_rep->key_found) {
		log_warn("Key %s not found!", key);
		*error_code = KRC_KEY_NOT_FOUND;
		goto exit;
	}
	val = (krc_value *)malloc(sizeof(krc_value) + get_rep->value_size);
	val->val_size = get_rep->value_size;
	memcpy(val->val_buf, get_rep->value, val->val_size);
	*error_code = KRC_SUCCESS;
exit:
	_zero_rendezvous_locations(rep_header);
	client_free_rpc_pair(conn, rep_header);
	return val;
}

/*scanner staff*/
krc_scanner *krc_scan_init(uint32_t prefetch_num_entries, uint32_t prefetch_mem_size)
{
	krc_scanner *scanner =
		(krc_scanner *)malloc(sizeof(krc_scanner) + sizeof(msg_multi_get_rep) + prefetch_mem_size);
	scanner->prefix_key = NULL;
	scanner->start_key = NULL;
	scanner->stop_key = NULL;
	scanner->prefetch_num_entries = prefetch_num_entries;
	scanner->prefetch_mem_size = prefetch_mem_size;
	scanner->pos = 0;
	scanner->start_infinite = 1;
	scanner->stop_infinite = 1;
	scanner->is_valid = 1;
	scanner->prefix_filter_enable = 0;
	scanner->state = KRC_UNITIALIZED;
	scanner->multi_kv_buf = (msg_multi_get_rep *)((uint64_t)scanner + sizeof(krc_scanner));
	return scanner;
}

uint8_t krc_scan_is_valid(krc_scanner *sc)
{
	return sc->is_valid;
}
void krc_scan_get_next(krc_scanner *sc)
{
	msg_header *req_header;
	msg_multi_get_req *m_get;
	msg_header *rep_header;
	msg_multi_get_rep *m_get_rep;
	char *seek_key;
	client_region *curr_region = (client_region *)sc->curr_region;
	msg_multi_get_rep *multi_kv_buf = (msg_multi_get_rep *)sc->multi_kv_buf;
	connection_rdma *conn;

	uint32_t seek_key_size;
	uint32_t seek_mode;

	while (1) {
		switch (sc->state) {
		case KRC_UNITIALIZED:
			if (!sc->start_infinite) {
				seek_key = sc->start_key->key_buf;
				seek_key_size = sc->start_key->key_size;
				if (sc->seek_mode == KRC_GREATER_OR_EQUAL)
					seek_mode = GREATER_OR_EQUAL;
				else
					seek_mode = GREATER;

			} else {
				seek_key = neg_infinity;
				seek_key_size = 4;
				seek_mode = GREATER_OR_EQUAL;
			}

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

			curr_region = client_find_region(seek_key, seek_key_size);
			sc->curr_region = (void *)curr_region;
			conn = get_connection_from_region(curr_region, (uint64_t)seek_key);
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
			req_header->reply_length =
				sizeof(msg_header) + rep_header->pay_len + rep_header->padding_and_tail;

			req_header->request_message_local_addr = req_header;
			rep_header->receive = 0;
			/*sent the request*/
			if (send_rdma_message_busy_wait(conn, req_header) != KREON_SUCCESS) {
				log_warn("failed to send message");
				exit(EXIT_FAILURE);
			}
			/*Spin until header arrives*/
			while (rep_header->receive != TU_RDMA_REGULAR_MSG)
				_mm_pause();
			/*Spin until payload arrives*/
			uint32_t *tail = (uint32_t *)(((uint64_t)rep_header + sizeof(msg_header) + rep_header->pay_len +
						       rep_header->padding_and_tail) -
						      TU_TAIL_SIZE);

			while (*tail != TU_RDMA_REGULAR_MSG)
				_mm_pause();

			//log_info("got multi get reply!");
			m_get_rep = (msg_multi_get_rep *)((uint64_t)rep_header + sizeof(msg_header));

			if (m_get_rep->buffer_overflow) {
				sc->state = KRC_BUFFER_OVERFLOW;
				break;
			}
			/*copy to local buffer to free rdma communication buffer*/
			memcpy(sc->multi_kv_buf, m_get_rep, sizeof(msg_multi_get_rep) + sc->prefetch_mem_size);
			_zero_rendezvous_locations(rep_header);
			client_free_rpc_pair(conn, rep_header);
			multi_kv_buf = (msg_multi_get_rep *)sc->multi_kv_buf;
			sc->state = KRC_ADVANCE;
			multi_kv_buf->pos = 0;
			multi_kv_buf->remaining = multi_kv_buf->capacity;
			break;
		case KRC_ADVANCE:
			/*point to the next element*/
			//log_info("sc curr %u num entries %u", sc->multi_kv_buf->curr_entry,
			//	 sc->multi_kv_buf->num_entries);
			if (multi_kv_buf->curr_entry < multi_kv_buf->num_entries) {
				sc->curr_key = (krc_key *)((uint64_t)multi_kv_buf->kv_buffer + multi_kv_buf->pos);
				multi_kv_buf->pos += (sizeof(krc_key) + sc->curr_key->key_size);
				sc->curr_value = (krc_value *)((uint64_t)multi_kv_buf->kv_buffer + multi_kv_buf->pos);
				multi_kv_buf->pos += (sizeof(krc_value) + sc->curr_value->val_size);
				++multi_kv_buf->curr_entry;
				return;
			} else {
				if (!multi_kv_buf->end_of_region) {
					seek_key = sc->curr_key->key_buf;
					seek_key_size = sc->curr_key->key_size;
					seek_mode = GREATER;
					sc->state = KRC_ISSUE_MGET_REQ;
					//log_info("Time for next batch, within region, seek key %s", seek_key);
				} else if (multi_kv_buf->end_of_region &&
					   strncmp(curr_region->ID_region.maximum_range+sizeof(uint32_t), "+oo", 3) != 0) {
					seek_key = curr_region->ID_region.maximum_range + sizeof(uint32_t);
					seek_key_size = *(uint32_t *)curr_region->ID_region.maximum_range;
					sc->state = KRC_ISSUE_MGET_REQ;
					//log_info("Time for next batch, crossing regions, seek key %s", seek_key);
				} else {
					sc->state = KRC_END_OF_DB;
					log_info("sorry end of db end of region = %d maximum_range %s minimum range %s",
						 multi_kv_buf->end_of_region,
						 curr_region->ID_region.maximum_range + sizeof(uint32_t),
						 curr_region->ID_region.minimum_range + sizeof(uint32_t));
				}
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

void krc_scan_set_start(krc_scanner *sc, uint32_t start_key_size, void *start_key, krc_seek_mode seek_mode)
{
	if (!sc->start_infinite) {
		log_warn("Nothing to do already set start key for this scanner");
		return;
	}
	switch (seek_mode) {
	case KRC_GREATER_OR_EQUAL:
	case KRC_GREATER:
		break;
	default:
		log_fatal("unknown seek_mode");
		exit(EXIT_FAILURE);
	}
	sc->seek_mode = seek_mode;
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
	log_fatal("Not fully implemneted yet contact gesalous@ics.forth.gr");
	exit(EXIT_FAILURE);
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
	log_fatal("Not fully implemneted yet contact gesalous@ics.forth.gr");
	exit(EXIT_FAILURE);
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
	free(sc);
	return;
}

krc_ret_code krc_close()
{
	log_fatal("Unimplemented contact gesalous@ics.forth.gr");
	//exit(EXIT_FAILURE);
	return KRC_FAILURE;
}


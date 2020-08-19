#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <immintrin.h>
#include <assert.h>
#include "kreon_rdma_client.h"
#include "client_utils.h"
//#include "../kreon_server/client_regions.h"
#include "../kreon_rdma/rdma.h"
#include "../kreon_server/globals.h"
#include "../kreon_server/messages.h"
#include "../utilities/spin_loop.h"
#include "../kreon_lib/scanner/scanner.h"
#include "../kreon_server/djb2.h"
#include <log.h>
#define KRC_GET_SIZE 4096

static volatile uint32_t reply_checker_started = 0;
static volatile uint32_t reply_checker_exit = 0;

struct krc_scanner {
	krc_key *prefix_key;
	krc_key *start_key;
	krc_key *stop_key;
	krc_key *curr_key;
	krc_value *curr_value;
	uint32_t prefetch_num_entries;
	uint32_t prefetch_mem_size;
	uint32_t actual_mem_size;
	uint32_t pos;
	krc_seek_mode seek_mode;
	krc_seek_mode stop_key_seek_mode;
	uint8_t start_infinite : 1;
	uint8_t stop_infinite : 1;
	uint8_t prefix_filter_enable : 1;
	uint8_t is_valid : 1;
	uint8_t fetch_keys_only : 1;

	krc_scan_state state;
	/*copy of the server's reply*/
	msg_multi_get_rep *multi_kv_buf;
	struct cu_region_desc *curr_region;
};

static char neg_infinity[1] = { 0 };
static char *pos_infinity = "+oo";

ZooLogLevel logLevel = ZOO_LOG_LEVEL_ERROR;

static int krc_lib_init = 0;
static pthread_mutex_t lib_lock = PTHREAD_MUTEX_INITIALIZER;

/*async staff*/

struct krc_async_params {
	int num_queues;
	int bufs_per_queue;
};

struct krc_async_req {
	struct connection_rdma *conn;
	struct msg_header *request;
	struct msg_header *reply;
	void *context;
	void (*callback)(void *);
	uint32_t id;
	volatile uint32_t is_valid;
};

struct krc_async_queue {
	pthread_mutex_t queue_lock;
	utils_queue_s avail_buffers;
	uint32_t outstanding_requests;
	uint32_t num_requests;
	struct krc_async_req requests[];
};

struct krc_spinner {
	int bufs_per_queue;
	int num_queues;
	struct krc_async_queue *queue[];
};
static struct krc_spinner *spinner = NULL;
pthread_t spinner_cnxt;

static void _krc_get_rpc_pair(connection_rdma *conn, msg_header **req, int req_msg_type, int req_size, msg_header **rep,
			      int rep_msg_type, uint32_t rep_size)
{
	pthread_mutex_lock(&conn->buffer_lock);
	*req = client_allocate_rdma_message(conn, req_size, req_msg_type);
	*rep = client_allocate_rdma_message(conn, rep_size, rep_msg_type);
	pthread_mutex_unlock(&conn->buffer_lock);
}

static int64_t krc_compare_keys(krc_key *key1, krc_key *key2)
{
	int64_t ret;
	uint32_t size;

	if (key1->key_size > key2->key_size)
		size = key2->key_size;
	else
		size = key1->key_size;

	ret = memcmp(key2->key_buf, key1->key_buf, size);
	if (ret != 0)
		return ret;
	else if (ret == 0 && key1->key_size == key2->key_size)
		return 0;
	else {
		/*larger key wins*/
		if (key2->key_size > key1->key_size)
			return 1;
		else
			return -1;
	}
}

static int64_t krc_prefix_match(krc_key *prefix, krc_key *key)
{
	if (key->key_size < prefix->key_size)
		return -1;
	if (memcmp(prefix->key_buf, key->key_buf, prefix->key_size) == 0)
		return 1;
	else
		return 0;
}

static void kreon_op_stat2string(kreon_op_status stat)
{
	switch (stat) {
	case KREON_SUCCESS:
		printf("KREON_SUCCESS");
		break;
	case KREON_FAILURE:
		printf("KREON_FAILURE");
		break;
	case KREON_KEY_NOT_FOUND:
		printf("KEY_NOT_FOUND");
		break;
	case KREON_VALUE_TOO_LARGE:
		printf("VALUE_TOO_LARGE");
		break;
	}
	return;
}

krc_ret_code krc_init(char *zookeeper_ip, int zk_port)
{
	if (!krc_lib_init) {
		pthread_mutex_lock(&lib_lock);
		if (!krc_lib_init) {
			cu_init(zookeeper_ip, zk_port);
			//char *zk_host_port = malloc(strlen(zookeeper_ip) + 16);
			//strcpy(zk_host_port, zookeeper_ip);
			//*(char *)(zk_host_port + strlen(zookeeper_ip)) = ':';
			//sprintf(zk_host_port + strlen(zookeeper_ip) + 1, "%d", zk_port);
			//log_info("Initializing, connectiong to zookeeper at %s", zk_host_port);
			//globals_set_zk_host(zk_host_port);
			//free(zk_host_port);
			//old school
			//client_regions = Allocate_Init_Client_Regions();
			//while (client_regions->num_regions_connected < 1) {
			//	log_warn("No regions yet");
			//	sleep(1);
			//}

			krc_lib_init = 1;
		}
		pthread_mutex_unlock(&lib_lock);
	}
	return KRC_SUCCESS;
}

krc_ret_code krc_put_with_offset(uint32_t key_size, void *key, uint32_t offset, uint32_t val_size, void *value)
{
	msg_header *req_header;
	msg_put_offt_req *put_offt_req;
	msg_put_key *update_key;
	msg_put_value *update_value;
	msg_header *rep_header;
	msg_put_offt_rep *put_offt_rep;

	if (key_size + val_size + (2 * sizeof(uint32_t)) > SEGMENT_SIZE - sizeof(segment_header)) {
		log_fatal("KV size too large currently for Kreon, current max value size supported = %u bytes",
			  SEGMENT_SIZE - sizeof(segment_header));
		log_fatal("Contact <gesalous@ics.forth.gr>");
		exit(EXIT_FAILURE);
	}

	if (offset > SEGMENT_SIZE - sizeof(segment_header)) {
		log_fatal("offset too large currently for Kreon, current max value size supported = %u bytes",
			  SEGMENT_SIZE - sizeof(segment_header));
		log_fatal("Contact <gesalous@ics.forth.gr>");
		exit(EXIT_FAILURE);
	}

	struct cu_region_desc *r_desc = cu_get_region(key, key_size);
	connection_rdma *conn = cu_get_conn_for_region(r_desc, (uint64_t)key);

	_krc_get_rpc_pair(conn, &req_header, PUT_OFFT_REQUEST,
			  sizeof(msg_put_offt_req) + key_size + val_size + (2 * sizeof(uint32_t)), &rep_header,
			  PUT_OFFT_REPLY, sizeof(msg_put_offt_rep));
	//req_header = allocate_rdma_message(
	//	conn, sizeof(msg_put_offt_req) + key_size + val_size + (2 * sizeof(uint32_t)), PUT_OFFT_REQUEST);

	put_offt_req = (msg_put_offt_req *)((uint64_t)req_header + sizeof(msg_header));
	put_offt_req->offset = offset;
	/*fill in the key payload part the data, caution we are 100% sure that it fits :-)*/
	update_key = (msg_put_key *)put_offt_req->kv;
	update_key->key_size = key_size;
	memcpy(update_key->key, key, key_size);
	update_value = (msg_put_value *)((uint64_t)update_key + sizeof(msg_put_key) + update_key->key_size);
	update_value->value_size = val_size;
	memcpy(update_value->value, value, val_size);

	/*Now the reply*/
	//rep_header = allocate_rdma_message(conn, sizeof(msg_put_offt_rep), PUT_OFFT_REPLY);
	rep_header->receive = 0;
	put_offt_rep = (msg_put_offt_rep *)((uint64_t)rep_header + sizeof(msg_header));

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
	wait_for_value(&rep_header->receive, TU_RDMA_REGULAR_MSG);
	rep_header->receive = 0;
	/*Spin until payload arrives*/
	uint32_t *tail = (uint32_t *)(((uint64_t)rep_header + sizeof(msg_header) + rep_header->pay_len +
				       rep_header->padding_and_tail) -
				      TU_TAIL_SIZE);
	wait_for_value(tail, TU_RDMA_REGULAR_MSG);

	put_offt_rep = (msg_put_offt_rep *)((uint64_t)rep_header + sizeof(msg_header));
	/*check ret code*/
	if (put_offt_rep->status != KREON_SUCCESS) {
		log_fatal("put operation failed for key %s with status %u", key, put_offt_rep->status);
		exit(EXIT_FAILURE);
	}
	_zero_rendezvous_locations_l(rep_header, req_header->reply_length);
	client_free_rpc_pair(conn, rep_header);
	return KRC_SUCCESS;
}

krc_ret_code krc_put(uint32_t key_size, void *key, uint32_t val_size, void *value)
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
	//old school
	//client_region *region = client_find_region(key, key_size);
	//connection_rdma *conn = get_connection_from_region(region, (uint64_t)key);
	struct cu_region_desc *r_desc = cu_get_region(key, key_size);
	connection_rdma *conn = cu_get_conn_for_region(r_desc, (uint64_t)key);

	_krc_get_rpc_pair(conn, &req_header, PUT_REQUEST, key_size + val_size + (2 * sizeof(uint32_t)), &rep_header,
			  PUT_REPLY, sizeof(msg_put_rep));
	//req_header = allocate_rdma_message(conn, key_size + val_size + (2 * sizeof(uint32_t)), PUT_REQUEST);
	put_key = (msg_put_key *)((uint64_t)req_header + sizeof(msg_header));
	/*fill in the key payload part the data, caution we are 100% sure that it fits :-)*/
	put_key->key_size = key_size;
	memcpy(put_key->key, key, key_size);
	put_value = (msg_put_value *)((uint64_t)put_key + sizeof(msg_put_key) + put_key->key_size);
	put_value->value_size = val_size;
	memcpy(put_value->value, value, val_size);

	/*Now the reply part*/
	//rep_header = allocate_rdma_message(conn, sizeof(msg_put_rep), PUT_REPLY);
	rep_header->receive = 0;
	put_rep = (msg_put_rep *)((uint64_t)rep_header + sizeof(msg_header));
	put_rep->status = KR_REP_PENDING;

	/*inform the req about its buddy*/
	req_header->request_message_local_addr = req_header;
	req_header->ack_arrived = KR_REP_PENDING;
	/*location where server should put the reply*/
	req_header->reply = (char *)((uint64_t)rep_header - (uint64_t)conn->recv_circular_buf->memory_region);
	req_header->reply_length = sizeof(msg_header) + rep_header->pay_len + rep_header->padding_and_tail;
	//log_info("put rep length %lu", req_header->reply_length);
	/*send the actual put*/
	if (send_rdma_message_busy_wait(conn, req_header) != KREON_SUCCESS) {
		log_warn("failed to send message");
		exit(EXIT_FAILURE);
	}

	/*Spin until header arrives*/
	wait_for_value(&rep_header->receive, TU_RDMA_REGULAR_MSG);
	rep_header->receive = 0;
	/*Spin until payload arrives*/
	uint32_t *tail = (uint32_t *)(((uint64_t)rep_header + sizeof(msg_header) + rep_header->pay_len +
				       rep_header->padding_and_tail) -
				      TU_TAIL_SIZE);
	wait_for_value(tail, TU_RDMA_REGULAR_MSG);

	put_rep = (msg_put_rep *)((uint64_t)rep_header + sizeof(msg_header));
	/*check ret code*/
	if (put_rep->status != KREON_SUCCESS) {
		log_fatal("put operation failed for key %s", key);
		exit(EXIT_FAILURE);
	}
	_zero_rendezvous_locations_l(rep_header, req_header->reply_length);
	client_free_rpc_pair(conn, rep_header);
	return KRC_SUCCESS;
}

#if 0
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
	msg_header *rep_header = allocate_rdma_message(conn, sizeof(msg_get_rep) + reply_length, TU_GET_REPLY);
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
	wait_for_value(&rep_header->receive, TU_RDMA_REGULAR_MSG);

	/*Spin until payload arrives*/
	uint32_t *tail = (uint32_t *)(((uint64_t)rep_header + sizeof(msg_header) + rep_header->pay_len +
				       rep_header->padding_and_tail) -
				      TU_TAIL_SIZE);

	wait_for_value(tail, TU_RDMA_REGULAR_MSG);

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
	_zero_rendezvous_locations_l(rep_header, req_header->reply_length);
	client_free_rpc_pair(conn, rep_header);
	return val;
}


krc_value *krc_get_with_offset(uint32_t key_size, void *key, uint32_t offset, uint32_t size, uint32_t *error_code)
{
	msg_header *rep_header;
	/*if size is 0 it will try to read the remaining value*/
	krc_value *val = NULL;
	client_region *region = client_find_region(key, key_size);
	connection_rdma *conn = get_connection_from_region(region, (uint64_t)key);
	/*the request part*/
	msg_header *req_header = allocate_rdma_message(conn, sizeof(msg_get_offt_req) + key_size, GET_OFFT_REQUEST);

	msg_get_offt_req *get_offt_req = (msg_get_offt_req *)((uint64_t)req_header + sizeof(msg_header));
	get_offt_req->offset = offset;
	get_offt_req->size = size;
	get_offt_req->key_size = key_size;
	memcpy(get_offt_req->key_buf, key, key_size);
	/*the reply part*/
	if (size == UINT_MAX)
		rep_header =
			allocate_rdma_message(conn, sizeof(msg_get_req) + KRC_GET_OFFT_DEFAULT_SIZE, GET_OFFT_REPLY);
	else if (size == 0)
		rep_header = allocate_rdma_message(conn, sizeof(msg_get_req), GET_OFFT_REPLY);
	else
		rep_header = allocate_rdma_message(conn, sizeof(msg_get_req) + size, GET_OFFT_REPLY);

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
	wait_for_value(&rep_header->receive, TU_RDMA_REGULAR_MSG);

	/*Spin until payload arrives*/
	uint32_t *tail = (uint32_t *)(((uint64_t)rep_header + sizeof(msg_header) + rep_header->pay_len +
				       rep_header->padding_and_tail) -
				      TU_TAIL_SIZE);

	wait_for_value(tail, TU_RDMA_REGULAR_MSG);

	msg_get_offt_rep *get_offt_rep = (msg_get_offt_rep *)((uint64_t)rep_header + sizeof(msg_header));

	if (!get_offt_rep->key_found) {
		//log_warn("Key %s not found!", key);
		*error_code = KRC_KEY_NOT_FOUND;
		goto exit;
	}

	if (size > 0) {
		val = (krc_value *)malloc(sizeof(krc_value) + get_offt_rep->value_bytes_read);
		val->val_size = get_offt_rep->value_bytes_read;
		memcpy(val->val_buf, get_offt_rep->value, val->val_size);
	}
	*error_code = KRC_SUCCESS;
exit:
	_zero_rendezvous_locations_l(rep_header, req_header->reply_length);
	client_free_rpc_pair(conn, rep_header);
	return val;
}
#endif

krc_ret_code krc_get(uint32_t key_size, char *key, char **buffer, uint32_t *size, uint32_t offset)
{
	msg_header *req_header = NULL;
	msg_header *rep_header = NULL;
	msg_get_req *get_req = NULL;
	msg_get_rep *get_rep = NULL;
	uint32_t reply_size;
	uint32_t local_offset = offset;
	uint32_t local_buf_offset = 0;
	//old school
	//client_region *region = client_find_region(key, key_size);
	//connection_rdma *conn = get_connection_from_region(region, (uint64_t)key);
	struct cu_region_desc *r_desc = cu_get_region(key, key_size);
	connection_rdma *conn = cu_get_conn_for_region(r_desc, (uint64_t)key);
	krc_ret_code code = KRC_FAILURE;
	uint8_t read_whole_value;

	if (*buffer == NULL) {
		/*app wants us to fetch the whole thing from offset, allocate, and return a buffer*/
		read_whole_value = 1;
		reply_size = KRC_GET_SIZE;
	} else {
		read_whole_value = 0;
		reply_size = *size;
	}

	while (1) {
		_krc_get_rpc_pair(conn, &req_header, TU_GET_QUERY, sizeof(msg_get_req) + key_size, &rep_header,
				  TU_GET_REPLY, sizeof(msg_get_rep) + reply_size);
		//req_header = allocate_rdma_message(conn, sizeof(msg_get_req) + key_size, TU_GET_QUERY);
		get_req = (msg_get_req *)((uint64_t)req_header + sizeof(msg_header));
		get_req->key_size = key_size;
		memcpy(get_req->key, key, key_size);
		get_req->offset = local_offset;
		get_req->fetch_value = 1;
		get_req->bytes_to_read = reply_size;
		/*the reply part*/
		//rep_header = allocate_rdma_message(conn, sizeof(msg_get_rep) + reply_size, TU_GET_REPLY);
		req_header->reply = (char *)((uint64_t)rep_header - (uint64_t)conn->recv_circular_buf->memory_region);
		req_header->reply_length = sizeof(msg_header) + rep_header->pay_len + rep_header->padding_and_tail;

		req_header->request_message_local_addr = req_header;
		rep_header->receive = 0;

		/*send the request*/
		if (send_rdma_message_busy_wait(conn, req_header) != KREON_SUCCESS) {
			log_warn("failed to send message");
			exit(EXIT_FAILURE);
		}
		/*Spin until header arrives*/
		wait_for_value(&rep_header->receive, TU_RDMA_REGULAR_MSG);

		/*Spin until payload arrives*/
		uint32_t *tail = (uint32_t *)(((uint64_t)rep_header + sizeof(msg_header) + rep_header->pay_len +
					       rep_header->padding_and_tail) -
					      TU_TAIL_SIZE);

		wait_for_value(tail, TU_RDMA_REGULAR_MSG);

		get_rep = (msg_get_rep *)((uint64_t)rep_header + sizeof(msg_header));
		/*various reply checks*/
		if (!get_rep->key_found) {
			//log_warn("Key %s not found!", key);
			code = KRC_KEY_NOT_FOUND;
			goto exit;
		}
		if (get_rep->offset_too_large) {
			code = KRC_OFFSET_TOO_LARGE;
			goto exit;
		}

		if (*buffer == NULL) {
			*size = get_rep->value_size + get_rep->bytes_remaining;
			(*buffer) = malloc(*size);
		}

		memcpy((*buffer) + local_buf_offset, get_rep->value, get_rep->value_size);
		if (!read_whole_value) {
			//log_info("actual value from server %u", get_rep->value_size);
			*size = get_rep->value_size;
			code = KRC_SUCCESS;
			goto exit;
		}
		local_offset += get_rep->value_size;
		local_buf_offset += get_rep->value_size;

		if (get_rep->bytes_remaining == 0) {
			code = KRC_SUCCESS;
			goto exit;
		} else {
			_zero_rendezvous_locations_l(rep_header, req_header->reply_length);
			client_free_rpc_pair(conn, rep_header);
		}
	}

exit:
	_zero_rendezvous_locations_l(rep_header, req_header->reply_length);
	client_free_rpc_pair(conn, rep_header);
	return code;
}

uint8_t krc_exists(uint32_t key_size, void *key)
{
	msg_header *req_header = NULL;
	msg_header *rep_header = NULL;
	msg_get_req *get_req = NULL;
	msg_get_rep *get_rep = NULL;

	struct cu_region_desc *r_desc = cu_get_region(key, key_size);
	connection_rdma *conn = cu_get_conn_for_region(r_desc, (uint64_t)key);
	uint8_t ret;

	_krc_get_rpc_pair(conn, &req_header, TU_GET_QUERY, sizeof(msg_get_req) + key_size, &rep_header, TU_GET_REPLY,
			  sizeof(msg_get_rep));
	//req_header = allocate_rdma_message(conn, sizeof(msg_get_req) + key_size, TU_GET_QUERY);
	get_req = (msg_get_req *)((uint64_t)req_header + sizeof(msg_header));
	get_req->key_size = key_size;
	memcpy(get_req->key, key, key_size);
	get_req->offset = 0;
	get_req->fetch_value = 0;
	/*the reply part*/
	//rep_header = allocate_rdma_message(conn, sizeof(msg_get_rep), TU_GET_REPLY);
	req_header->reply = (char *)((uint64_t)rep_header - (uint64_t)conn->recv_circular_buf->memory_region);
	req_header->reply_length = sizeof(msg_header) + rep_header->pay_len + rep_header->padding_and_tail;

	req_header->request_message_local_addr = req_header;
	rep_header->receive = 0;
	/*send the request*/
	if (send_rdma_message_busy_wait(conn, req_header) != KREON_SUCCESS) {
		log_warn("failed to send message");
		exit(EXIT_FAILURE);
	}
	/*Spin until header arrives*/
	wait_for_value(&rep_header->receive, TU_RDMA_REGULAR_MSG);

	/*Spin until payload arrives*/
	uint32_t *tail = (uint32_t *)(((uint64_t)rep_header + sizeof(msg_header) + rep_header->pay_len +
				       rep_header->padding_and_tail) -
				      TU_TAIL_SIZE);

	wait_for_value(tail, TU_RDMA_REGULAR_MSG);

	get_rep = (msg_get_rep *)((uint64_t)rep_header + sizeof(msg_header));
	/*various reply checks*/
	if (get_rep->key_found)
		ret = 1;
	else
		ret = 0;

	_zero_rendezvous_locations_l(rep_header, req_header->reply_length);
	client_free_rpc_pair(conn, rep_header);
	return ret;
}

krc_ret_code krc_delete(uint32_t key_size, void *key)
{
	msg_header *req_header;
	msg_header *rep_header;
	uint32_t error_code;

	struct cu_region_desc *r_desc = cu_get_region(key, key_size);
	connection_rdma *conn = cu_get_conn_for_region(r_desc, (uint64_t)key);

	_krc_get_rpc_pair(conn, &req_header, DELETE_REQUEST, sizeof(msg_delete_req) + key_size, &rep_header,
			  DELETE_REPLY, sizeof(msg_delete_rep));
	/*the request part*/
	//	msg_header *req_header = allocate_rdma_message(conn, sizeof(msg_delete_req) + key_size, DELETE_REQUEST);

	msg_delete_req *m_del = (msg_delete_req *)((uint64_t)req_header + sizeof(msg_header));
	m_del->key_size = key_size;
	memcpy(m_del->key, key, key_size);
	/*the reply part*/
	//msg_header *rep_header = allocate_rdma_message(conn, sizeof(msg_delete_rep), DELETE_REPLY);
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
	wait_for_value(&rep_header->receive, TU_RDMA_REGULAR_MSG);

	/*Spin until payload arrives*/
	uint32_t *tail = (uint32_t *)(((uint64_t)rep_header + sizeof(msg_header) + rep_header->pay_len +
				       rep_header->padding_and_tail) -
				      TU_TAIL_SIZE);

	wait_for_value(tail, TU_RDMA_REGULAR_MSG);

	msg_delete_rep *del_rep = (msg_delete_rep *)((uint64_t)rep_header + sizeof(msg_header));

	if (del_rep->status != KREON_SUCCESS) {
		log_warn("Key %s not found!", key);
		error_code = KRC_KEY_NOT_FOUND;
	} else
		error_code = KRC_SUCCESS;
	_zero_rendezvous_locations_l(rep_header, req_header->reply_length);
	client_free_rpc_pair(conn, rep_header);
	return error_code;
}

/*scanner staff*/
krc_scannerp krc_scan_init(uint32_t prefetch_num_entries, uint32_t prefetch_mem_size)
{
	/*roundity as the rdma allocator will*/
	uint32_t padding;
	uint32_t actual_size = sizeof(msg_header) + sizeof(msg_multi_get_rep) + prefetch_mem_size + TU_TAIL_SIZE;
	if (actual_size % MESSAGE_SEGMENT_SIZE != 0)
		padding = MESSAGE_SEGMENT_SIZE - (actual_size % MESSAGE_SEGMENT_SIZE);
	else
		padding = 0;
	struct krc_scanner *scanner = (struct krc_scanner *)malloc(sizeof(struct krc_scanner) + actual_size + padding);
	scanner->actual_mem_size = actual_size + padding;
	scanner->prefetch_mem_size = prefetch_mem_size;
	scanner->prefix_key = NULL;
	scanner->start_key = NULL;
	scanner->stop_key = NULL;
	scanner->stop_key_seek_mode = KRC_GREATER;
	scanner->prefetch_num_entries = prefetch_num_entries;
	scanner->pos = 0;
	scanner->start_infinite = 1;
	scanner->stop_infinite = 1;
	scanner->is_valid = 1;
	scanner->prefix_filter_enable = 0;
	scanner->state = KRC_UNITIALIZED;
	scanner->fetch_keys_only = 0;
	scanner->multi_kv_buf = (msg_multi_get_rep *)((uint64_t)scanner + sizeof(struct krc_scanner));
	return (krc_scannerp)scanner;
}

uint8_t krc_scan_is_valid(krc_scannerp sp)
{
	struct krc_scanner *sc = (struct krc_scanner *)sp;
	return sc->is_valid;
}

void krc_scan_fetch_keys_only(krc_scannerp sp)
{
	struct krc_scanner *sc = (struct krc_scanner *)sp;
	sc->fetch_keys_only = 1;
}

uint8_t krc_scan_get_next(krc_scannerp sp, char **key, size_t *keySize, char **value, size_t *valueSize)
{
	struct krc_scanner *sc = (struct krc_scanner *)sp;
	msg_header *req_header;
	msg_multi_get_req *m_get;
	msg_header *rep_header;
	msg_multi_get_rep *m_get_rep;
	char *seek_key;
	//old school
	//client_region *curr_region = (client_region *)sc->curr_region;
	struct cu_region_desc *r_desc = (struct cu_region_desc *)sc->curr_region;

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
				seek_key_size = 1;
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
		case KRC_STOP_FILTER: {
			int ret;
			if (sc->stop_key != NULL) {
				ret = krc_compare_keys(sc->curr_key, sc->stop_key);
				if (ret < 0 || (ret == 0 && sc->stop_key_seek_mode == KRC_GREATER)) {
					log_info("stop key reached curr key %s stop key %s", sc->curr_key->key_buf,
						 sc->stop_key->key_buf);
					sc->is_valid = 0;
					sc->state = KRC_INVALID;
					sc->curr_key = NULL;
					sc->curr_value = NULL;
					goto exit;
				}
			}
			sc->state = KRC_PREFIX_FILTER;
			break;
		}
		case KRC_PREFIX_FILTER:

			if (sc->prefix_key == NULL) {
				sc->state = KRC_ADVANCE;
				goto exit;
			} else if (sc->prefix_key != NULL && krc_prefix_match(sc->prefix_key, sc->curr_key)) {
				sc->state = KRC_ADVANCE;
				goto exit;
			} else {
				sc->state = KRC_INVALID;
				sc->is_valid = 0;
				goto exit;
			}
		case KRC_ISSUE_MGET_REQ: {
			r_desc = cu_get_region(seek_key, seek_key_size);
			sc->curr_region = (void *)r_desc;
			conn = cu_get_conn_for_region(r_desc, (uint64_t)key);

			_krc_get_rpc_pair(conn, &req_header, MULTI_GET_REQUEST,
					  sizeof(msg_multi_get_req) + seek_key_size, &rep_header, MULTI_GET_REPLY,
					  sc->prefetch_mem_size);
			/*the request part*/
			//req_header = allocate_rdma_message(conn, sizeof(msg_multi_get_req) + seek_key_size,
			//				   MULTI_GET_REQUEST);
			m_get = (msg_multi_get_req *)((uint64_t)req_header + sizeof(msg_header));
			m_get->max_num_entries = sc->prefetch_num_entries;
			m_get->seek_mode = seek_mode;
			m_get->fetch_keys_only = sc->fetch_keys_only;
			m_get->seek_key_size = seek_key_size;
			memcpy(m_get->seek_key, seek_key, seek_key_size);
			/*the reply part*/
			//rep_header = allocate_rdma_message(conn, sc->prefetch_mem_size, MULTI_GET_REPLY);
			req_header->reply =
				(char *)((uint64_t)rep_header - (uint64_t)conn->recv_circular_buf->memory_region);
			req_header->reply_length =
				sizeof(msg_header) + rep_header->pay_len + rep_header->padding_and_tail;
			//log_info("Client allocated for my replu %u bytes", req_header->reply_length);
			req_header->request_message_local_addr = req_header;
			rep_header->receive = 0;

			/*sent the request*/
			if (send_rdma_message_busy_wait(conn, req_header) != KREON_SUCCESS) {
				log_warn("failed to send message");
				exit(EXIT_FAILURE);
			}
			/*Spin until header arrives*/
			wait_for_value(&rep_header->receive, TU_RDMA_REGULAR_MSG);
			/*Spin until payload arrives*/
			uint32_t *tail = (uint32_t *)((uint64_t)rep_header + sizeof(msg_header) + rep_header->pay_len +
						      (rep_header->padding_and_tail));

			tail = (uint32_t *)((uint64_t)tail - TU_TAIL_SIZE);
			wait_for_value(tail, TU_RDMA_REGULAR_MSG);

			//log_info("pay len %u padding_and_tail %u", rep_header->pay_len, rep_header->padding_and_tail);
			m_get_rep = (msg_multi_get_rep *)((uint64_t)rep_header + sizeof(msg_header));

			if (m_get_rep->buffer_overflow) {
				sc->state = KRC_BUFFER_OVERFLOW;
				break;
			}
			/*copy to local buffer to free rdma communication buffer*/
			//assert(rep_header->pay_len <= sc->actual_mem_size);

			multi_kv_buf = m_get_rep;
			/*
			uint32_t i;
			uint32_t idx = 0;
			krc_key *my_key;
			krc_value *my_val;
			for (i = 0; i < multi_kv_buf->num_entries; i++) {
				my_key = (krc_key *)((uint64_t)multi_kv_buf->kv_buffer + idx);
				assert(my_key->key_size < 27);

				idx += (sizeof(krc_key) + my_key->key_size);
				my_val = (krc_value *)((uint64_t)multi_kv_buf->kv_buffer + idx);
				assert(my_val->val_size < 1200);
				idx += (sizeof(krc_value) + my_val->val_size);
			}
			*/
			memcpy(sc->multi_kv_buf, m_get_rep, rep_header->pay_len);
			_zero_rendezvous_locations_l(rep_header, req_header->reply_length);

			client_free_rpc_pair(conn, rep_header);
			multi_kv_buf = (msg_multi_get_rep *)sc->multi_kv_buf;
			multi_kv_buf->pos = 0;
			multi_kv_buf->remaining = multi_kv_buf->capacity;
			multi_kv_buf->curr_entry = 0;
			sc->state = KRC_ADVANCE;
			break;
		}
		case KRC_ADVANCE:
			/*point to the next element*/

			if (multi_kv_buf->curr_entry < multi_kv_buf->num_entries) {
				//log_info("sc curr %u num entries %u", multi_kv_buf->curr_entry, multi_kv_buf->num_entries);
				sc->curr_key = (krc_key *)((uint64_t)multi_kv_buf->kv_buffer + multi_kv_buf->pos);
				multi_kv_buf->pos += (sizeof(krc_key) + sc->curr_key->key_size);
				sc->curr_value = (krc_value *)((uint64_t)multi_kv_buf->kv_buffer + multi_kv_buf->pos);
				multi_kv_buf->pos += (sizeof(krc_value) + sc->curr_value->val_size);
				++multi_kv_buf->curr_entry;
				sc->state = KRC_STOP_FILTER;
				break;
			} else {
				if (!multi_kv_buf->end_of_region) {
					seek_key = sc->curr_key->key_buf;
					seek_key_size = sc->curr_key->key_size;
					seek_mode = GREATER;
					sc->state = KRC_ISSUE_MGET_REQ;
					//log_info("Time for next batch, within region, seek key %s", seek_key);
				} else if (multi_kv_buf->end_of_region &&
					   strncmp(r_desc->region.max_key, "+oo", 3) != 0) {
					seek_key = r_desc->region.max_key;
					seek_key_size = r_desc->region.max_key_size;
					sc->state = KRC_ISSUE_MGET_REQ;
					seek_mode = GREATER_OR_EQUAL;
					//log_info("Time for next batch, crossing regions, seek key %s", seek_key);
				} else {
					sc->state = KRC_END_OF_DB;
					//log_info("sorry end of db end of region = %d maximum_range %s minimum range %s",
					//	 multi_kv_buf->end_of_region, r_desc->region.max_key,
					//		 r_desc->region.min_key);
				}
			}
			break;
		case KRC_BUFFER_OVERFLOW:
		case KRC_END_OF_DB:
			sc->curr_key = NULL;
			sc->curr_value = NULL;
			sc->is_valid = 0;
			goto exit;
		default:
			log_fatal("faulty scanner state");
			exit(EXIT_FAILURE);
		}
	}
exit:
	if (sc->is_valid) {
		*keySize = sc->curr_key->key_size;
		*key = sc->curr_key->key_buf;
		*valueSize = sc->curr_value->val_size;
		*value = sc->curr_value->val_buf;
	} else {
		*keySize = 0;
		*key = NULL;
		*valueSize = 0;
		*value = NULL;
	}
	return sc->is_valid;
}

void krc_scan_set_start(krc_scannerp sp, uint32_t start_key_size, void *start_key, krc_seek_mode seek_mode)
{
	struct krc_scanner *sc = (struct krc_scanner *)sp;
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
	//log_info("start key set to %s", sc->start_key->key_buf);
	return;
}

void krc_scan_set_stop(krc_scannerp sp, uint32_t stop_key_size, void *stop_key, krc_seek_mode seek_mode)
{
	struct krc_scanner *sc = (struct krc_scanner *)sp;
	if (stop_key_size >= 3 && memcmp(stop_key, pos_infinity, stop_key_size) == 0) {
		sc->stop_infinite = 1;
		return;
	}

	if (!sc->stop_infinite) {
		log_warn("Nothing to do already set stop key for this scanner");
		return;
	}
	sc->stop_infinite = 0;
	sc->seek_mode = seek_mode;
	sc->stop_key = (krc_key *)malloc(sizeof(krc_key) + stop_key_size);
	sc->stop_key->key_size = stop_key_size;
	memcpy(sc->stop_key->key_buf, stop_key, stop_key_size);
	log_info("stop key set to %s", sc->stop_key->key_buf);
	return;
}

void krc_scan_set_prefix_filter(krc_scannerp sp, uint32_t prefix_size, void *prefix)
{
	struct krc_scanner *sc = (struct krc_scanner *)sp;
	if (sc->prefix_filter_enable) {
		log_warn("Nothing to do already set prefix key for this scanner");
		return;
	}
	sc->seek_mode = KRC_GREATER_OR_EQUAL;
	sc->start_infinite = 0;
	sc->start_key = (krc_key *)malloc(sizeof(krc_key) + prefix_size);
	sc->start_key->key_size = prefix_size;
	memcpy(sc->start_key->key_buf, prefix, prefix_size);
	sc->prefix_filter_enable = 1;
	sc->prefix_key = (krc_key *)malloc(sizeof(krc_key) + prefix_size);
	sc->prefix_key->key_size = prefix_size;
	memcpy(sc->prefix_key->key_buf, prefix, prefix_size);
	return;
}

void krc_scan_close(krc_scannerp sp)
{
	struct krc_scanner *sc = (struct krc_scanner *)sp;
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
	if (reply_checker_started) {
		/*wait to flush outstanding requests from all queues*/
		int num_empty_queues = 0;
		while (num_empty_queues != spinner->num_queues) {
			num_empty_queues = 0;
			for (int i = 0; i < spinner->num_queues; i++) {
				if (spinner->queue[i]->outstanding_requests == 0) {
					++num_empty_queues;
				}
			}
		}
		log_info("All outstanding requests done!");
	}
	cu_close_open_connections();
	return KRC_SUCCESS;
}

/*new functions for asynchronous client related to #57*/

static uint8_t krc_async_send_request(struct connection_rdma *conn, struct msg_header *request,
				      struct msg_header *reply, callback t, void *context)
{
	//static uint32_t cnt = 0;
	/*choose randomly, a spinner queue*/

	uint32_t id = djb2_hash((unsigned char *)reply, sizeof(struct msg_header)) % spinner->num_queues;
	//uint32_t id = (uint64_t)conn % spinner->num_queues;
	pthread_mutex_lock(&spinner->queue[id]->queue_lock);
	/*get an async req buffer*/
	struct krc_async_req *req = utils_queue_pop(&spinner->queue[id]->avail_buffers);
	if (req == NULL) {
		log_fatal("Out of buffers, should you increase them");
		exit(EXIT_FAILURE);
	}
	req->conn = conn;
	req->request = request;
	req->reply = reply;
	req->request->receive = TU_RDMA_REGULAR_MSG;
	//uint32_t *req_tail = (uint32_t *)((uint64_t)req + sizeof(struct msg_header) + req->request->pay_len +
	//		     (req->request->padding_and_tail - TU_TAIL_SIZE));
	//*req_tail = TU_RDMA_REGULAR_MSG;
	//log_info("rendezvous set to %lu",tmp);
	req->callback = t;
	req->context = context;
	//++cnt;
	//req->id = cnt;
	//log_info("req id is %lu cnt is %lu", req->id, cnt);
	if (send_rdma_message_busy_wait(req->conn, req->request) != KREON_SUCCESS) {
		log_warn("failed to send message");
		exit(EXIT_FAILURE);
	}

	__sync_fetch_and_add(&spinner->queue[id]->outstanding_requests, 1);
	req->is_valid = 1;
	pthread_mutex_unlock(&spinner->queue[id]->queue_lock);

	return 1;
}

krc_ret_code krc_aput(uint32_t key_size, void *key, uint32_t val_size, void *value, callback t, void *context)
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

	struct cu_region_desc *r_desc = cu_get_region(key, key_size);
	connection_rdma *conn = cu_get_conn_for_region(r_desc, (uint64_t)key);
	_krc_get_rpc_pair(conn, &req_header, PUT_REQUEST, key_size + val_size + (2 * sizeof(uint32_t)), &rep_header,
			  PUT_REPLY, sizeof(msg_put_rep));
	put_key = (msg_put_key *)((uint64_t)req_header + sizeof(msg_header));
	/*fill in the key payload part the data, caution we are 100% sure that it fits :-)*/
	put_key->key_size = key_size;
	memcpy(put_key->key, key, key_size);
	put_value = (msg_put_value *)((uint64_t)put_key + sizeof(msg_put_key) + put_key->key_size);
	put_value->value_size = val_size;
	memcpy(put_value->value, value, val_size);

	/*Now the reply part*/
	//rep_header = allocate_rdma_message(conn, sizeof(msg_put_rep), PUT_REPLY);
	rep_header->receive = 0;
	put_rep = (msg_put_rep *)((uint64_t)rep_header + sizeof(msg_header));
	put_rep->status = KR_REP_PENDING;

	/*inform the req about its buddy*/
	req_header->request_message_local_addr = req_header;
	req_header->ack_arrived = KR_REP_PENDING;
	/*location where server should put the reply*/
	req_header->reply = (char *)((uint64_t)rep_header - (uint64_t)conn->recv_circular_buf->memory_region);
	req_header->reply_length = sizeof(msg_header) + rep_header->pay_len + rep_header->padding_and_tail;
	//log_info("put rep length %lu", req_header->reply_length);

	/*now inform the spinner to check for the reply, and what to do with it.
	 * The function internally will send the message in order not to violate order*/
	if (!krc_async_send_request(conn, req_header, rep_header, t, context)) {
		log_fatal("Failed to add request to reply checker");
		exit(EXIT_FAILURE);
	}
	return KRC_SUCCESS;
}

static uint8_t krc_has_reply_arrived(struct krc_async_req *req)
{
	if (req != NULL) {
		if (req->reply != NULL) {
			if (req->reply->receive == TU_RDMA_REGULAR_MSG) {
				//log_info("header is here");
				uint32_t *tail = (uint32_t *)(((uint64_t)req->reply + sizeof(struct msg_header) +
							       req->reply->pay_len + req->reply->padding_and_tail) -
							      TU_TAIL_SIZE);
				if (*tail == TU_RDMA_REGULAR_MSG) {
					//log_info("Payload is here");
					return 1;
				}
			}
		} else
			return 0;
	} else {
		assert(0);
		return 0;
	}
	return 0;
}

void krc_free_rpc_buffers(connection_rdma *conn, struct msg_header *request, msg_header *reply)
{
	uint32_t size;
	if (request->pay_len == 0) {
		size = MESSAGE_SEGMENT_SIZE;
	} else {
		size = TU_HEADER_SIZE + request->pay_len + request->padding_and_tail;
		assert(size % MESSAGE_SEGMENT_SIZE == 0);
	}
	free_space_from_circular_buffer(conn->send_circular_buf, (char *)request, size);

	if (reply->pay_len == 0) {
		size = MESSAGE_SEGMENT_SIZE;
	} else {
		size = TU_HEADER_SIZE + reply->pay_len + reply->padding_and_tail;
		assert(size % MESSAGE_SEGMENT_SIZE == 0);
	}
	free_space_from_circular_buffer(conn->recv_circular_buf, (char *)reply, size);
	return;
}

static void *krc_reply_checker(void *args)
{
	//uint32_t next_id = 1;
	pthread_setname_np(pthread_self(), "reply_checker");
	struct krc_async_params *params = (struct krc_async_params *)args;

	uint32_t async_queue_size =
		sizeof(struct krc_async_queue) + (params->bufs_per_queue * sizeof(struct krc_async_req));

	spinner = (struct krc_spinner *)malloc(sizeof(struct krc_spinner) +
					       (params->num_queues * sizeof(struct krc_async_queue *)));
	spinner->num_queues = params->num_queues;
	spinner->bufs_per_queue = params->bufs_per_queue;

	for (int i = 0; i < spinner->num_queues; i++) {
		spinner->queue[i] = (struct krc_async_queue *)malloc(async_queue_size);
		pthread_mutex_init(&spinner->queue[i]->queue_lock, NULL);
		utils_queue_init(&spinner->queue[i]->avail_buffers);
		/*now put the actual async_req buffers*/
		spinner->queue[i]->num_requests = params->bufs_per_queue;
		spinner->queue[i]->outstanding_requests = 0;
		log_info("bufs per queue set to %lu", spinner->queue[i]->num_requests);
		for (uint32_t j = 0; j < spinner->queue[i]->num_requests; j++) {
			memset(&spinner->queue[i]->requests[j], 0x00, sizeof(struct krc_async_req));
			if (utils_queue_push(&spinner->queue[i]->avail_buffers, &spinner->queue[i]->requests[j]) ==
			    NULL) {
				log_fatal(
					"Failed to add %d bufs per queue maybe capacity of queue is set to smaller size?",
					spinner->bufs_per_queue);
				exit(EXIT_FAILURE);
			}
		}
	}

	log_info("reply_checker done initialization starting spinning for possible replies");
	reply_checker_started = 1;
	while (!reply_checker_exit) {
		for (int i = 0; i < spinner->num_queues; i++) {
			for (uint32_t j = 0; j < spinner->queue[i]->num_requests; j++) {
				struct krc_async_req *req = &spinner->queue[i]->requests[j];

				if (req->is_valid) {
					//log_info("Checking req for queue %d", i);

					if (krc_has_reply_arrived(req)) {
						if (req->callback != NULL) {
							//log_info("Calling callback for req");
							req->callback(req->context);
						}
						uint32_t size;
						if (req->reply->pay_len == 0) {
							size = MESSAGE_SEGMENT_SIZE;
						} else {
							size = TU_HEADER_SIZE + req->reply->pay_len +
							       req->reply->padding_and_tail;
							assert(size % MESSAGE_SEGMENT_SIZE == 0);
						}
						_zero_rendezvous_locations_l(req->reply, size);
						krc_free_rpc_buffers(req->conn, req->request, req->reply);
						req->conn = NULL;
						//memset(req, 0x00, sizeof(struct krc_async_req));
						req->is_valid = 0;
						__sync_fetch_and_sub(&spinner->queue[i]->outstanding_requests, 1);
						if (utils_queue_push(&spinner->queue[i]->avail_buffers, req) == NULL) {
							log_fatal("Failed to return buffer!");
							exit(EXIT_FAILURE);
						}
						//assert(req->id == next_id);
						//assert(req->id == next_id);
						//++next_id;
					}
				} //else {
				//log_info("Reply has not arrived");
				//}
			}
		}
	}
	log_info("reply_checker exiting");
	free(params);
	for (int i = 0; i < spinner->num_queues; i++)
		free(spinner->queue[i]);
	free(spinner);
	return NULL;
}

uint8_t krc_start_async_thread(int num_queues, int bufs_per_queue)
{
	struct krc_async_params *args = (struct krc_async_params *)malloc(sizeof(struct krc_async_params));
	args->num_queues = num_queues;
	args->bufs_per_queue = bufs_per_queue;
	if (pthread_create(&spinner_cnxt, NULL, krc_reply_checker, (void *)args) != 0) {
		log_fatal("Failed to spawn async reply checker");
		exit(EXIT_FAILURE);
	}

	wait_for_value((uint32_t *)&reply_checker_started, 1);
	log_info("Successfully spawned async reply checker");
	return 1;
}

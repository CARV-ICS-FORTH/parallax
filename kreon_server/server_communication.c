#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include "server_communication.h"
#include "djb2.h"
#include "globals.h"
#include "metadata.h"
#include "../utilities/circular_buffer.h"
#include "../kreon_lib/btree/uthash.h"
#include <log.h>

struct sc_conn_per_server {
	uint64_t hash_key;
	struct krm_server_name server;
	struct connection_rdma *conn;
	UT_hash_handle hh;
};
struct sc_conn_per_server *sc_root_cps = NULL;
static pthread_mutex_t conn_map_lock = PTHREAD_MUTEX_INITIALIZER;
struct sc_msg_pair sc_allocate_rpc_pair(struct connection_rdma *conn, uint32_t request_size, uint32_t reply_size,
					enum message_type type)
{
	struct sc_msg_pair rep = { NULL, NULL, 0 };

	char *addr;
	uint32_t actual_request_size;
	uint32_t actual_reply_size;
	uint32_t request_padding;
	uint32_t reply_padding;
	uint32_t receive_type = TU_RDMA_REGULAR_MSG;
	enum message_type req_type;
	enum message_type rep_type;
	/*calculate the sizes for both request and reply*/
	if (request_size > 0) {
		actual_request_size = TU_HEADER_SIZE + request_size + TU_TAIL_SIZE;
		if (actual_request_size % MESSAGE_SEGMENT_SIZE != 0) {
			/*need to pad */
			request_padding = (MESSAGE_SEGMENT_SIZE - (actual_request_size % MESSAGE_SEGMENT_SIZE));
			actual_request_size += request_padding;
		} else
			request_padding = 0;
	} else {
		actual_request_size = MESSAGE_SEGMENT_SIZE;
		request_padding = 0;
	}

	if (reply_size > 0) {
		actual_reply_size = TU_HEADER_SIZE + reply_size + TU_TAIL_SIZE;
		if (actual_reply_size % MESSAGE_SEGMENT_SIZE != 0) {
			/*need to pad */
			reply_padding = (MESSAGE_SEGMENT_SIZE - (actual_reply_size % MESSAGE_SEGMENT_SIZE));
			actual_reply_size += reply_padding;
		} else
			reply_padding = 0;
	} else {
		actual_reply_size = MESSAGE_SEGMENT_SIZE;
		reply_padding = 0;
	}

	pthread_mutex_lock(&conn->buffer_lock);
	switch (type) {
	case GET_LOG_BUFFER_REQ:
		req_type = type;
		rep_type = GET_LOG_BUFFER_REP;
		/*The idea is the following, if we are not able to allocate both
		 * buffers while acquiring the lock we should rollback. Also we need to 
		 * allocate receive buffer first and then send buffer.
		 */
		/*first allocate the receive buffer, aka where we expect the reply*/
		rep.stat = allocate_space_from_circular_buffer(conn->recv_circular_buf, actual_reply_size, &addr);
		if (rep.stat != ALLOCATION_IS_SUCCESSFULL)
			goto exit;
		rep.reply = (struct msg_header *)addr;

		rep.stat = allocate_space_from_circular_buffer(conn->send_circular_buf, actual_request_size, &addr);
		if (rep.stat != ALLOCATION_IS_SUCCESSFULL) {
			/*rollback previous allocation*/
			free_space_from_circular_buffer(conn->recv_circular_buf, (char *)rep.reply, actual_reply_size);
			goto exit;
		}
		rep.request = (struct msg_header *)addr;
		/*init the headers*/
		goto init_messages;
	default:
		log_fatal("Unsupported message type %d", type);
		exit(EXIT_FAILURE);
	}

init_messages : {
	struct msg_header *msg;
	struct circular_buffer *c_buf;
	uint32_t payload_size;
	uint32_t padding;
	uint32_t msg_type;
	int i = 0;
	c_buf = conn->send_circular_buf;
	msg = rep.request;
	payload_size = request_size;
	padding = request_padding;
	msg_type = req_type;

	while (i < 2) {
		if (payload_size > 0) {
			msg->pay_len = payload_size;
			msg->padding_and_tail = padding + TU_TAIL_SIZE;
			msg->data = (void *)((uint64_t)msg + TU_HEADER_SIZE);
			msg->next = msg->data;
			/*set the tail to the proper value*/
			if (i == 0) //this is the request
				*(uint32_t *)(((uint64_t)msg + TU_HEADER_SIZE + msg->pay_len + msg->padding_and_tail) -
					      sizeof(uint32_t)) = receive_type;
			else //this is the reply
				*(uint32_t *)(((uint64_t)msg + TU_HEADER_SIZE + msg->pay_len + msg->padding_and_tail) -
					      sizeof(uint32_t)) = 0;
		} else {
			msg->pay_len = 0;
			msg->padding_and_tail = 0;
			msg->data = NULL;
			msg->next = NULL;
		}

		msg->type = msg_type;
		msg->receive = receive_type;
		msg->local_offset = (uint64_t)msg - (uint64_t)c_buf->memory_region;
		msg->remote_offset = (uint64_t)msg - (uint64_t)c_buf->memory_region;

		msg->ack_arrived = 0; //????? really?
		msg->callback_function = NULL;
		msg->request_message_local_addr = NULL;
		rep.request->reply = NULL;
		rep.request->reply_length = 0;

		c_buf = conn->recv_circular_buf;
		msg = rep.reply;
		payload_size = reply_size;
		padding = reply_padding;
		msg_type = rep_type;
		++i;
	}
}

	rep.request->reply = (char *)((uint64_t)rep.reply - (uint64_t)conn->recv_circular_buf->memory_region);
	rep.request->reply_length = sizeof(msg_header) + rep.reply->pay_len + rep.reply->padding_and_tail;

exit:
	pthread_mutex_unlock(&conn->buffer_lock);
	return rep;
}

void sc_free_rpc_pair(struct sc_msg_pair *p)
{
}

struct connection_rdma *sc_get_conn(char *hostname)
{
	struct sc_conn_per_server *cps;
	uint64_t hash_key;
	log_info("Conn for %s", hostname);
	hash_key = djb2_hash((unsigned char *)hostname, strlen(hostname));
	HASH_FIND_PTR(sc_root_cps, &hash_key, cps);
	if (cps == NULL) {
		pthread_mutex_lock(&conn_map_lock);
		HASH_FIND_PTR(sc_root_cps, &hash_key, cps);
		if (cps == NULL) {
			/*ok update server info from zookeeper*/
			cps = (struct sc_conn_per_server *)malloc(sizeof(struct sc_conn_per_server));
			if (krm_get_server_info(hostname, &cps->server) == KREON_FAILURE) {
				log_fatal("Failed to refresh info for server %s", hostname);
				exit(EXIT_FAILURE);
			}
			char *IP =  cps->server.RDMA_IP_addr;
			cps->conn = crdma_client_create_connection_list_hosts(globals_get_rdma_channel(), &IP, 1,
									      MASTER_TO_REPLICA_CONNECTION);
			/*init list here*/
			cps->hash_key = hash_key;
			HASH_ADD_PTR(sc_root_cps, hash_key, cps);
			log_info("Got connection with %s", hostname);
		}
		pthread_mutex_unlock(&conn_map_lock);
	}

	return cps->conn;
}


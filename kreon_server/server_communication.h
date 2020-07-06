#pragma once
#include "../kreon_rdma/rdma.h"
#include "messages.h"
struct sc_msg_pair {
	struct msg_header *request;
	struct msg_header *reply;
	enum circular_buffer_op_status stat;
};

struct sc_msg_pair sc_allocate_rpc_pair(struct connection_rdma *conn, uint32_t request_size, uint32_t reply_size,
					enum message_type type);

struct connection_rdma *sc_get_conn(char *hostname);
//int sc_send_rdma_message(connection_rdma *conn, msg_header *msg);
//void sc_free_rpc_pair(struct sc_msg_pair m_pair);
//typedef void (*sc_process_log_buffer_reply)(void *);




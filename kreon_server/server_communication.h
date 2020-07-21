#pragma once
#include "../kreon_rdma/rdma.h"
#include "messages.h"
struct sc_msg_pair {
	struct connection_rdma *conn;
	struct msg_header *request;
	struct msg_header *reply;
	enum circular_buffer_op_status stat;
};

struct sc_msg_pair sc_allocate_rpc_pair(struct connection_rdma *conn, uint32_t request_size, uint32_t reply_size,
					enum message_type type);

struct connection_rdma *sc_get_conn(char *hostname);
void sc_free_rpc_pair(struct sc_msg_pair *p);

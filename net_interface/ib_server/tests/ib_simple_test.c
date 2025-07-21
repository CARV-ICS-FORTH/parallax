#include "../ib_client_ctx.h"
#include "../ib_protocol.h"
#include <infiniband/verbs.h>
#include <netdb.h>
#include <rdma/rdma_cma.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define IP "192.168.5.120"
#define PORT "7741"
#define TIMEOUT_MS 500

#define NUM_TEST_ITERATIONS 6

struct my_conn_metadata {
	uint32_t max_value_size;
};

int send_protocol_header(struct ib_client_ctx *ctx, enum op_code op, uint64_t va, uint64_t size, uint32_t rkey,
			 uint64_t db_id, uint8_t inline_flag)
{
	struct protocol_header *hdr = (struct protocol_header *)ctx->buf;
	hdr->virtual_address = va;
	hdr->size = size;
	hdr->op = op;
	hdr->rkey = rkey;
	hdr->db_id = db_id;
	hdr->inline_flag = inline_flag;
	memset(hdr->future_use, 0, sizeof(hdr->future_use));

	struct ibv_sge sge = {
		.addr = (uintptr_t)ctx->buf,
		.length = sizeof(struct protocol_header),
		.lkey = ctx->mr->lkey,
	};

	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)ctx->buf,
		.opcode = IBV_WR_SEND,
		.sg_list = &sge,
		.num_sge = 1,
		.send_flags = IBV_SEND_SIGNALED,
	};
	struct ibv_send_wr *bad_wr = NULL;

	if (ibv_post_send(ctx->id->qp, &wr, &bad_wr)) {
		perror("ibv_post_send");
		return -1;
	}

	struct ibv_wc wc;
	struct ibv_cq *ev_cq;
	void *cq_context;

	if (ibv_get_cq_event(ctx->comp_channel, &ev_cq, &cq_context)) {
		perror("ibv_get_cq_event");
		return -1;
	}
	ibv_ack_cq_events(ev_cq, 1);
	ibv_req_notify_cq(ev_cq, 0);

	while (ibv_poll_cq(ctx->cq, 1, &wc) == 0)
		;

	if (wc.status != IBV_WC_SUCCESS) {
		fprintf(stderr, "Send failed: %s\n", ibv_wc_status_str(wc.status));
		return -1;
	}

	printf("Sent op=%d db_id=%lu inline=%d va=0x%lx size=%lu\n", op, db_id, inline_flag, va, size);

	return 0;
}

int main()
{
	struct addrinfo *addr;
	struct rdma_cm_id *cm_id = NULL;
	struct rdma_event_channel *ec = NULL;
	struct rdma_cm_event *event;
	struct ibv_pd *pd;
	struct ibv_comp_channel *comp_chan;
	struct ibv_cq *cq;
	struct ibv_mr *mr;
	struct ibv_qp_init_attr qp_attr;
	struct protocol_header *hdr;
	struct ibv_send_wr wr;
	struct ibv_sge sge;

	struct ib_client_ctx *client_ctx = malloc(sizeof(struct ib_client_ctx));
	if (!client_ctx) {
		perror("malloc");
		return -1;
	}

	srand(time(NULL));

	getaddrinfo(IP, PORT, NULL, &addr);
	ec = rdma_create_event_channel();
	rdma_create_id(ec, &cm_id, NULL, RDMA_PS_TCP);
	rdma_resolve_addr(cm_id, NULL, addr->ai_addr, TIMEOUT_MS);
	freeaddrinfo(addr);

	rdma_get_cm_event(ec, &event);
	rdma_ack_cm_event(event);

	rdma_resolve_route(cm_id, TIMEOUT_MS);
	rdma_get_cm_event(ec, &event);
	rdma_ack_cm_event(event);

	pd = ibv_alloc_pd(cm_id->verbs);
	comp_chan = ibv_create_comp_channel(cm_id->verbs);
	cq = ibv_create_cq(cm_id->verbs, 10, NULL, comp_chan, 0);
	ibv_req_notify_cq(cq, 0);

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.send_cq = cq;
	qp_attr.recv_cq = cq;
	qp_attr.qp_type = IBV_QPT_RC;
	qp_attr.cap.max_send_wr = 10;
	qp_attr.cap.max_recv_wr = 10;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.cap.max_recv_sge = 1;

	rdma_create_qp(cm_id, pd, &qp_attr);

	struct rdma_conn_param conn_param = { 0 };
	conn_param.initiator_depth = 1;
	conn_param.responder_resources = 1;
	conn_param.retry_count = 7;
	rdma_connect(cm_id, &conn_param);
	rdma_get_cm_event(ec, &event);
	struct my_conn_metadata *meta = (struct my_conn_metadata *)event->param.conn.private_data;
	printf("Server max value size: %u\n", meta->max_value_size);
	rdma_ack_cm_event(event);

	hdr = malloc(sizeof(struct protocol_header));

	mr = ibv_reg_mr(pd, hdr, sizeof(struct protocol_header), IBV_ACCESS_LOCAL_WRITE);

	memset(&sge, 0, sizeof(sge));
	sge.addr = (uintptr_t)hdr;
	sge.length = sizeof(struct protocol_header);
	sge.lkey = mr->lkey;

	memset(&wr, 0, sizeof(wr));
	wr.wr_id = (uintptr_t)hdr;
	wr.opcode = IBV_WR_SEND;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IBV_SEND_SIGNALED;

	client_ctx->id = cm_id;
	client_ctx->pd = pd;
	client_ctx->cq = cq;
	client_ctx->comp_channel = comp_chan;
	client_ctx->mr = mr;
	client_ctx->buf = hdr;

	for (int i = 0; i < NUM_TEST_ITERATIONS; i++) {
		enum op_code op = i % 6;
		uint64_t db_id = rand() % 64;
		uint8_t inline_flag = 0; // 0 for now, later will use this flag for optimization

		uint64_t size = (rand() % 10 + 1) * 64;
		void *dummy_buf = malloc(size);
		memset(dummy_buf, 'A' + (i % 26), size);

		struct ibv_mr *mr =
			ibv_reg_mr(client_ctx->pd, dummy_buf, size, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
		if (!mr) {
			perror("ibv_reg_mr");
			continue;
		}

		uint64_t va = (uint64_t)(uintptr_t)dummy_buf;
		uint32_t rkey = mr->rkey;

		send_protocol_header(client_ctx, op, va, size, rkey, db_id, inline_flag);
		usleep(3000);
	}

	// Cleanup
	rdma_disconnect(cm_id);
	rdma_destroy_qp(cm_id);
	ibv_dereg_mr(mr);
	free(hdr);
	ibv_destroy_cq(cq);
	ibv_destroy_comp_channel(comp_chan);
	ibv_dealloc_pd(pd);
	rdma_destroy_id(cm_id);
	rdma_destroy_event_channel(ec);

	return 0;
}

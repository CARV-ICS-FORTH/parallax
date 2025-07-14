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
#define MSG_SIZE 17
#define NUM_TEST_ITERATIONS 10

struct my_conn_metadata {
	uint32_t max_value_size;
};

int main()
{
	struct addrinfo *addr;
	struct rdma_cm_id *cm_id = NULL;
	struct rdma_event_channel *ec = NULL;
	struct rdma_cm_event *event;
	struct ibv_pd *pd;
	struct ibv_comp_channel *comp_chan;
	struct ibv_cq *cq;
	void *cq_context;
	struct ibv_mr *mr;
	struct ibv_qp_init_attr qp_attr;
	ib_header *hdr;
	struct ibv_send_wr wr, *bad_wr = NULL;
	struct ibv_sge sge;
	struct ibv_wc wc;

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

	hdr = malloc(sizeof(ib_header));

	mr = ibv_reg_mr(pd, hdr, sizeof(ib_header), IBV_ACCESS_LOCAL_WRITE);

	memset(&sge, 0, sizeof(sge));
	sge.addr = (uintptr_t)hdr;
	sge.length = sizeof(ib_header);
	sge.lkey = mr->lkey;

	memset(&wr, 0, sizeof(wr));
	wr.wr_id = (uintptr_t)hdr;
	wr.opcode = IBV_WR_SEND;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IBV_SEND_SIGNALED;

	for (int i = 0; i < NUM_TEST_ITERATIONS; i++) {
		const ib_opcode valid_ops[] = {
			IB_OP_OPEN, IB_OP_CLOSE, IB_OP_WRITE, IB_OP_READ, IB_OP_DEL, IB_OP_SCAN
		};
		hdr->op = valid_ops[rand() % (sizeof(valid_ops) / sizeof(valid_ops[0]))];
		hdr->db_id = rand() % 16;
		hdr->inline_flag = rand() % 2;
		if (hdr->inline_flag == 1) {
			hdr->virtual_address = 0;
		} else {
			hdr->virtual_address = ((uint64_t)(rand() % 1024) * 4096);
		}
		const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		for (int i = 0; i < sizeof(hdr->buffer) - 1; i++) {
			hdr->buffer[i] = charset[rand() % (sizeof(charset) - 1)];
		}
		hdr->buffer[sizeof(hdr->buffer) - 1] = '\0';

		memset(&wr, 0, sizeof(wr));
		wr.wr_id = (uintptr_t)hdr;
		wr.opcode = IBV_WR_SEND;
		wr.sg_list = &sge;
		wr.num_sge = 1;
		wr.send_flags = IBV_SEND_SIGNALED;

		ibv_post_send(cm_id->qp, &wr, &bad_wr);

		ibv_get_cq_event(comp_chan, &cq, &cq_context);
		ibv_ack_cq_events(cq, 1);
		ibv_req_notify_cq(cq, 0);

		while (ibv_poll_cq(cq, 1, &wc) == 0)
			;
		if (wc.status != IBV_WC_SUCCESS) {
			fprintf(stderr, "Send failed: %s\n", ibv_wc_status_str(wc.status));
			break;
		} else {
			printf("[%d/%d] Sent header: op=%d, db_id=%d, inline=%d, va=0x%lx, buf='%.*s'\n", i + 1,
			       NUM_TEST_ITERATIONS, hdr->op, hdr->db_id, hdr->inline_flag, hdr->virtual_address,
			       (int)sizeof(hdr->buffer), hdr->buffer);
		}
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

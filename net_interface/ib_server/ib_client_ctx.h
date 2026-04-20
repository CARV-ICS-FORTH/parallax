#ifndef IB_CLIENT_CTX_H
#define IB_CLIENT_CTX_H

#include <pthread.h>
#include <rdma/rdma_cma.h>
#include <stdbool.h>

#define RDMA_READ_POOL_SIZE 16
#define RDMA_READ_BUF_SIZE (4 * 1024 * 1024) // 4MB
#define PAR_IB_RECV_BUFFER_NUMBER 8

struct rdma_read_slot {
	void *buf;
	struct ibv_mr *mr;
	size_t size;
	bool in_use;
};

struct par_ib_recv_slot {
	void *buf;
	struct ibv_mr *mr;
	int buf_idx;
	void *read_slot_ptr;
};

struct par_ib_client_ctx {
	struct ibv_pd *pd;
	struct ibv_qp *qp;
};

#endif

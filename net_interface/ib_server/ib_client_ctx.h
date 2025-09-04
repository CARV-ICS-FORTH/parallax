#ifndef IB_CLIENT_CTX_H
#define IB_CLIENT_CTX_H

#include <pthread.h>
#include <rdma/rdma_cma.h>
#include <stdbool.h>

#define RDMA_READ_POOL_SIZE 16
#define RDMA_READ_BUF_SIZE (4 * 1024 * 1024) // 4MB

struct rdma_read_slot {
	void *buf;
	struct ibv_mr *mr;
	size_t size;
	bool in_use;
};

struct ib_client_ctx {
	struct ibv_pd *pd;
	struct ibv_qp *qp;
	struct ibv_mr *mr;
	void *buf;
	struct rdma_read_slot read_pool[RDMA_READ_POOL_SIZE];
	bool rdma_read_pool_initialized;
};

#endif

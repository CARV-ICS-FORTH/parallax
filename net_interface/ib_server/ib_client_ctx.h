#ifndef IB_CLIENT_CTX_H
#define IB_CLIENT_CTX_H

#include <rdma/rdma_cma.h>

struct ib_client_ctx {
	struct ibv_pd *pd;
	struct ibv_mr *mr;
	struct ibv_qp *qp;
	void *buf;
};

#endif

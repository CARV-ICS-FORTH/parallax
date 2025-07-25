#include <rdma/rdma_cma.h>

struct ib_client_ctx {
	struct rdma_event_channel *ec;
	struct rdma_cm_id *id;
	struct ibv_pd *pd;
	struct ibv_cq *cq;
	struct ibv_mr *mr;
	struct ibv_qp *qp;
	struct ibv_comp_channel *comp_channel;
	void *buf;
	struct server_handle *server_handle;
};

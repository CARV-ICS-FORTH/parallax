#ifndef IB_WORKER_REQUEST_H
#define IB_WORKER_REQUEST_H

#include <infiniband/verbs.h>

struct ib_worker_request {
    uint32_t qp_num;
    void *user_ptr;
};

struct ib_worker_request *ib_worker_create_req(struct ibv_wc *wc);
uint32_t ib_worker_get_qp_num(struct ib_worker_request *req);
void *ib_worker_get_user_ptr(struct ib_worker_request *req);

#endif

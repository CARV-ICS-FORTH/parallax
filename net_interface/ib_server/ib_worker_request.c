#include <stdlib.h>
#include <infiniband/verbs.h>
#include "ib_worker_request.h"

uint32_t ib_worker_get_qp_num(struct ib_worker_request *req) {
    return req->qp_num;
}

void *ib_worker_get_user_ptr(struct ib_worker_request *req) {
    return req->user_ptr;
}

struct ib_worker_request *ib_worker_create_req(struct ibv_wc *wc) {
    if (!wc)
        return NULL;

    struct ib_worker_request *req = calloc(1U, sizeof(struct ib_worker_request));
    if (!req)
        return NULL;

    req->qp_num = wc->qp_num;
    req->user_ptr = (void *)(uintptr_t)wc->wr_id;

    return req;
}

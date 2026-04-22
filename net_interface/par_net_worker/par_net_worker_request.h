#ifndef PAR_NET_WORKER_REQUEST_H
#define PAR_NET_WORKER_REQUEST_H

#ifdef USE_PORTALS
#include "portals4.h"
#endif

struct par_net_worker_request;

/* Header for worker request obj*/

#ifdef USE_PORTALS

struct par_net_worker_request *par_net_worker_create_req(ptl_event_t event);

ptl_process_t par_net_worker_get_initiator(const struct par_net_worker_request *req);

void *par_net_worker_get_user_ptr(const struct par_net_worker_request *req);

#endif

void *par_net_worker_get_start(const struct par_net_worker_request *req);

#endif

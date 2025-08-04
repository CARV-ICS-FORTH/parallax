#ifndef WORKER_REQUEST_H
#define WORKER_REQUEST_H

#ifdef USE_PORTALS
#include "portals4.h"
#endif

struct portals_worker_request;

/* Header for worker request obj*/

#ifdef USE_PORTALS

struct portals_worker_request *portals_worker_create_req(ptl_event_t event);

ptl_process_t portals_worker_get_initiator(const struct portals_worker_request *req);

#elif USE_INFINIBAND

struct portals_worker_request *portals_worker_create_req(void *buf);

#endif

void *portals_worker_get_start(const struct portals_worker_request *req);

void *portals_worker_get_user_ptr(const struct portals_worker_request *req);

#endif

#ifndef WORKER_REQUEST_H
#define WORKER_REQUEST_H
#include "portals4.h"
struct portals_worker_request;

/* Header for worker request obj*/

ptl_process_t portals_worker_get_initiator(const struct portals_worker_request *req);

void *portals_worker_get_start(const struct portals_worker_request *req);

void *portals_worker_get_user_ptr(const struct portals_worker_request *req);

struct portals_worker_request *portals_worker_create_req(ptl_event_t event);
#endif

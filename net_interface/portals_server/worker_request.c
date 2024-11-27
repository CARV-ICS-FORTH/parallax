#include "worker_request.h"
#include "portals.h"
#include "portals4.h"
#include <stdlib.h>

struct portals_worker_request {
	ptl_process_t initiator;
	void *start;
	void *user_ptr;
};

ptl_process_t portals_worker_get_initiator(const struct portals_worker_request *req)
{
	return req->initiator;
}

void *portals_worker_get_start(const struct portals_worker_request *req)
{
	return req->start;
}

void *portals_worker_get_user_ptr(const struct portals_worker_request *req)
{
	return req->user_ptr;
}

struct portals_worker_request *portals_worker_create_req(ptl_event_t event)
{
	struct portals_worker_request *req = calloc(1U, sizeof(struct portals_worker_request));
	req->initiator = event.initiator;
	req->start = event.start;
	req->user_ptr = event.user_ptr;
	return req;
}

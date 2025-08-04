#include "portals.h"
#include "worker_request.h"
#ifdef USE_PORTALS
#include "portals4.h"
#endif
#include <stdlib.h>

struct portals_worker_request {
#ifdef USE_PORTALS
	ptl_process_t initiator;
#endif
	void *start;
	void *user_ptr;
};

#ifdef USE_PORTALS
ptl_process_t portals_worker_get_initiator(const struct portals_worker_request *req)
{
	return req->initiator;
}
#endif

void *portals_worker_get_start(const struct portals_worker_request *req)
{
	return req->start;
}

void *portals_worker_get_user_ptr(const struct portals_worker_request *req)
{
	return req->user_ptr;
}

#ifdef USE_PORTALS
struct portals_worker_request *portals_worker_create_req(ptl_event_t event)
{
	struct portals_worker_request *req = calloc(1U, sizeof(struct portals_worker_request));
	req->initiator = event.initiator;
	req->start = event.start;
	req->user_ptr = event.user_ptr;
	return req;
}
#elif USE_INFINIBAND
struct portals_worker_request *portals_worker_create_req(void *buf)
{
	struct portals_worker_request *req = calloc(1U, sizeof(struct portals_worker_request));
	req->start = buf;
	req->user_ptr = buf;
	return req;
}
#endif

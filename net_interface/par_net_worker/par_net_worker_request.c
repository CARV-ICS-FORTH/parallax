#include "portals.h"
#include "par_net_worker_request.h"
#ifdef USE_PORTALS
#include "portals4.h"
#endif
#include <stdlib.h>

struct par_net_worker_request {
#ifdef USE_PORTALS
	ptl_process_t initiator;
#endif
	void *start;
	void *user_ptr;
};

#ifdef USE_PORTALS
ptl_process_t par_net_worker_get_initiator(const struct par_net_worker_request *req)
{
	return req->initiator;
}
#endif

void *par_net_worker_get_start(const struct par_net_worker_request *req)
{
	return req->start;
}

void *par_net_worker_get_user_ptr(const struct par_net_worker_request *req)
{
	return req->user_ptr;
}

#ifdef USE_PORTALS
struct par_net_worker_request *par_net_worker_create_req(ptl_event_t event)
{
	struct par_net_worker_request *req = calloc(1U, sizeof(struct par_net_worker_request));
	req->initiator = event.initiator;
	req->start = event.start;
	req->user_ptr = event.user_ptr;
	return req;
}
#elif USE_INFINIBAND
struct par_net_worker_request *par_net_worker_create_req(void *buf)
{
	struct par_net_worker_request *req = calloc(1U, sizeof(struct par_net_worker_request));
	req->start = buf;
	req->user_ptr = buf;
	return req;
}
#endif

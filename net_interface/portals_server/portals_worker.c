#include "portals_worker.h"
#include "ccqueue.h"
#include "config.h"
#include "portals.h"
#include "portals4.h"
#include "portals4_ext.h"
#include "primitives.h"
#include <bits/pthreadtypes.h>
#include <log.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

#define PORTALS_TNUM 5

struct portals_worker {
	struct server_handle *server_handle;
	pthread_t tid;
	uint64_t core;
	ptl_md_t md;
	CCQueueStruct *queue_object CACHE_ALIGN;
	CCQueueThreadState *th_state;
	ptl_handle_md_t mdh;
	char *send_buffer;
	ptl_handle_eq_t send_eqh;
	uint32_t send_buffer_size;
	ptl_event_t event2;
};

size_t portals_worker_size(void)
{
	return (size_t)sizeof(struct portals_worker);
}

int portals_worker_poll(struct portals_worker *worker, ptl_event_t *event)
{
	ptl_event_t *ev;
	RetVal rawval = CCQueueApplyDequeue(worker->queue_object, worker->th_state, worker->tid);
	ev = (ptl_event_t *)rawval;
	if (ev) {
		event = ev;
		return 1;
	}
	return 0;
}

void portals_worker_put(struct portals_worker *worker, ptl_event_t *event)
{
	CCQueueThreadStateInit(worker->queue_object, worker->th_state, worker->tid);
	CCQueueApplyEnqueue(worker->queue_object, worker->th_state, (ArgVal)event, worker->tid);
}

struct portals_worker *portals_worker_create(struct server_handle *server_handle, ptl_handle_ni_t nih, uint32_t index)
{
	int ret;
	struct portals_worker *worker = calloc(1, sizeof(struct portals_worker));
	worker->core = index;
	worker->server_handle = server_handle;

	worker->queue_object = synchGetAlignedMemory(S_CACHE_LINE_SIZE, sizeof(CCQueueStruct));
	CCQueueStructInit(worker->queue_object, PORTALS_TNUM);
	worker->th_state = synchGetAlignedMemory(CACHE_LINE_SIZE, sizeof(CCQueueThreadState));

	CCQueueThreadStateInit(worker->queue_object, worker->th_state, worker->tid);

	ret = PtlEQAlloc(nih, 2048, &worker->send_eqh);
	if (ret != PTL_OK) {
		log_debug("PtlEQAlloc failed");
		return NULL;
	}
	ret = posix_memalign((void **)&worker->send_buffer, 4096, PRSV_COM_BUF_SIZE);
	if (ret != 0) {
		log_debug("posix_memalign failed");
		return NULL;
	}
	worker->send_buffer_size = PRSV_COM_BUF_SIZE;
	return worker;
}

char *portals_worker_get_buffer(struct portals_worker *worker)
{
	return (char *)worker->send_buffer;
}

struct server_handle *portals_worker_get_server_handle(struct portals_worker *worker)
{
	return (struct server_handle *)worker->server_handle;
}

uint32_t portals_worker_get_buffer_size(struct portals_worker *worker)
{
	return (uint32_t)worker->send_buffer_size;
}

uint64_t portals_worker_get_core(struct portals_worker *worker)
{
	return (uint64_t)worker->core;
}

pthread_t *portals_worker_get_tid(struct portals_worker *worker)
{
	return (pthread_t *)&worker->tid;
}

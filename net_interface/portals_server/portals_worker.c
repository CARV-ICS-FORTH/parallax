#include "portals_worker.h"
#include "ccqueue.h"
#include "config.h"
#include "portals.h"
#include "portals4.h"
#include "portals4_ext.h"
#include "primitives.h"
#include "queue-stack.h"
#include <bits/pthreadtypes.h>
#include <log.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

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

int portals_worker_poll(struct portals_worker *worker, ptl_event_t **event)
{
	RetVal rawval = CCQueueApplyDequeue(worker->queue_object, worker->th_state, worker->tid);
	if (rawval != EMPTY_QUEUE) {
		*event = (ptl_event_t *)rawval;
		log_debug("got event in thread : %lu", worker->core);
		return 1;
	}
	*event = NULL;
	return 1;
}

void portals_worker_put(struct portals_worker *worker, ptl_event_t *event)
{
	CCQueueApplyEnqueue(worker->queue_object, worker->th_state, (ArgVal)event, worker->tid);
}

struct portals_worker *portals_worker_create(struct server_handle *server_handle, ptl_handle_ni_t nih, uint32_t index,
					     uint32_t threadno)
{
	int ret;
	struct portals_worker *worker = calloc(1, sizeof(struct portals_worker));
	worker->core = index;
	worker->server_handle = server_handle;

	worker->queue_object = synchGetAlignedMemory(S_CACHE_LINE_SIZE, sizeof(CCQueueStruct));
	CCQueueStructInit(worker->queue_object, threadno);
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

void portals_worker_send_reply_buff(struct portals_worker *worker, struct par_net_header *reply_header,
				    uint32_t total_bytes, ptl_handle_ni_t nih, ptl_process_t client)
{
	worker->send_buffer = (char *)reply_header;
	worker->md.start = reply_header;
	worker->md.length = total_bytes;
	worker->md.options = 0;
	worker->md.eq_handle = worker->send_eqh;
	worker->md.ct_handle = PTL_CT_NONE;
	int ret = PtlMDBind(nih, &worker->md, &worker->mdh);
	if (ret != PTL_OK) {
		log_debug("PtlMDBind failed");
		_exit(EXIT_FAILURE);
	}
	ret = PtlPut(worker->mdh, 0, total_bytes, PTL_ACK_REQ, client, 0, 0, 0, NULL, 0);
	if (ret != PTL_OK) {
		log_debug("PtlPut failed");
		_exit(EXIT_FAILURE);
	}

	while (1) {
		ret = PtlEQPoll(&worker->send_eqh, 1, PTL_TIME_FOREVER, &worker->event2, 0);
		if (ret != PTL_OK) {
			log_debug("PtlEQWait failed: %s", PtlToStr(ret, PTL_STR_ERROR));
			_exit(EXIT_FAILURE);
		}
		if (worker->event2.type == PTL_EVENT_SEND) {
			log_debug("PTL_EVENT_SEND received. Data successfully sent.");
			break;
		} else {
			log_debug("Event server interface 1 : %s", PtlToStr(worker->event2.type, PTL_STR_EVENT));
		}
	}
}

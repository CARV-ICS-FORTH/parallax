#include "portals_worker.h"
#include "ccqueue.h"
#include "config.h"
#include "log.h"
#include "par_net.h"
#ifdef USE_PORTALS
#include "portals.h"
#include "portals4.h"
#include "portals4_ext.h"
#endif
#ifdef USE_INFINIBAND
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#endif
#include "primitives.h"
#include "queue-stack.h"
#include "worker_request.h"
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <x86intrin.h>
#include <stdatomic.h>

#define BUDDY_ALLOC_IMPLEMENTATION
#include "buddy_alloc.h"
#undef BUDDY_ALLOC_IMPLEMENTATION

#define EMPTY_WAIT 1000

#ifdef USE_INFINIBAND
#define PRSV_WORKER_BUF_SIZE (63U * 4096)
#define METADATA_SIZE 4096
#endif

struct counter {
	uint32_t counter;
	uint8_t padding[60];
};

struct portals_worker {
	struct counter queuecounter;
	struct counter queuecompletedcounter;
	sem_t empty;
	atomic_int notified;
	pthread_t tid;
	uint64_t start;
	uint64_t end;
	uint64_t core;
	uint32_t send_buffer_size;
	struct server_handle *server_handle;
	pthread_mutex_t *mutex;
	CCQueueStruct *queue_object CACHE_ALIGN;
	CCQueueThreadState *th_state;
	struct buddy *buddy;
	char *send_buffer;
#ifdef USE_PORTALS
	ptl_md_t md;
	ptl_handle_eq_t eqh;
	ptl_handle_md_t mdh;
#endif
#ifdef USE_INFINIBAND
	struct ibv_mr *mr;
    struct rdma_cm_id *id;
    struct ibv_qp *qp;
#endif
};

size_t portals_worker_size(void)
{
	return sizeof(struct portals_worker);
}

void portals_worker_lock(struct portals_worker *worker)
{
	pthread_mutex_lock(worker->mutex);
}

void portals_worker_unlock(struct portals_worker *worker)
{
	pthread_mutex_unlock(worker->mutex);
}

void portals_worker_notify(struct portals_worker *worker)
{
	int expected = 0;
	if (atomic_compare_exchange_strong(&worker->notified, &expected, 1)) {
		sem_post(&worker->empty);
		log_debug("Thread %lu: Notified (Posting semaphore)", worker->core);
	} else {
		log_debug("Thread %lu: Already notified (skipping sem_post)", worker->core);
	}
}

uint32_t portals_worker_get_reqs(struct portals_worker *worker)
{
	__atomic_load_n(&worker->queuecounter.counter, __ATOMIC_RELAXED);
	__atomic_load_n(&worker->queuecompletedcounter.counter, __ATOMIC_RELAXED);
	return worker->queuecounter.counter - worker->queuecompletedcounter.counter;
}

#define CPU_FREQ_HZ 2300

struct portals_worker_request *portals_worker_poll(struct portals_worker *worker)
{
	long elapsed_time = (worker->end - worker->start) / CPU_FREQ_HZ;
	//log_debug("Thread %lu: Elapsed time since last event: %ld usec", worker->core, elapsed_time);

	if (elapsed_time >= EMPTY_WAIT) {
		log_debug("Thread %lu: empty queue for %ld usec, waiting on semaphore", worker->core, elapsed_time);
		sem_wait(&worker->empty);
		atomic_store(&worker->notified, 0);
		worker->start = __rdtsc();
		worker->end = worker->start;
	}

	RetVal rawval = CCQueueApplyDequeue(worker->queue_object, worker->th_state, worker->tid);
	if (EMPTY_QUEUE == rawval) {
		//log_debug("Thread %lu: Queue is empty, nothing to dequeue", worker->core);
		worker->end = __rdtsc();
		return NULL;
	}
	__atomic_fetch_add(&worker->queuecompletedcounter.counter, 1, __ATOMIC_RELAXED);
	worker->start = __rdtsc();
	worker->end = worker->start;
	log_debug("Thread %lu: Successfully dequeued a request. Requests left in queue: %u", worker->core,
		  portals_worker_get_reqs(worker));
	struct portals_worker_request *req = (struct portals_worker_request *)rawval;
	log_debug("got event in thread : %lu", worker->core);
	return req;
}

#ifdef USE_PORTALS
void portals_worker_put(struct portals_worker *worker, struct portals_worker_request *request)
#else
void portals_worker_put(struct portals_worker *worker, struct ib_worker_request *request)
#endif
{
	CCQueueApplyEnqueue(worker->queue_object, worker->th_state, (ArgVal)request, worker->tid);
	__atomic_fetch_add(&worker->queuecounter.counter, 1, __ATOMIC_RELAXED);
}

#ifdef USE_PORTALS
struct portals_worker *portals_worker_create(struct server_handle *server_handle, uint32_t index, uint32_t threadno,
                             ptl_handle_eq_t eqh, pthread_mutex_t *mutex)
#else
struct portals_worker *portals_worker_create(struct server_handle *server_handle, uint32_t index, uint32_t threadno,
                             pthread_mutex_t *mutex)
#endif
{
	int ret;
	struct portals_worker *worker = calloc(1, sizeof(struct portals_worker));
	worker->mutex = mutex;
	worker->core = index;
	worker->server_handle = server_handle;
	sem_init(&worker->empty, 0, 0);
	worker->start = __rdtsc();
	worker->end = worker->start;
	worker->queue_object = synchGetAlignedMemory(S_CACHE_LINE_SIZE, sizeof(CCQueueStruct));
	CCQueueStructInit(worker->queue_object, threadno);
	worker->th_state = synchGetAlignedMemory(CACHE_LINE_SIZE, sizeof(CCQueueThreadState));

	CCQueueThreadStateInit(worker->queue_object, worker->th_state, worker->tid);

	void *raw_memory; // x*a +4096 = y where y is power of 2 and multiple of sizeof(void*) == 8
	if ((PRSV_WORKER_BUF_SIZE + METADATA_SIZE) % 4096 != 0) {
		log_fatal("PRSV_WORKER_BUF_SIZE + METADATA_SIZE is not a multiple of 4KB!");
		exit(EXIT_FAILURE);
	}

	ret = posix_memalign(&raw_memory, PRSV_WORKER_BUF_SIZE + METADATA_SIZE, PRSV_WORKER_BUF_SIZE + METADATA_SIZE);
	worker->send_buffer = (char *)raw_memory + METADATA_SIZE; //0x7ffff6fb3000
	uint32_t *worker_index = (uint32_t *)((uintptr_t)raw_memory);
	*worker_index = index;

	__atomic_store_n(&worker->queuecounter.counter, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&worker->queuecompletedcounter.counter, 0, __ATOMIC_RELAXED);

	if (ret != 0) {
		log_debug("posix_memalign failed");
		return NULL;
	}
	worker->send_buffer_size = PRSV_WORKER_BUF_SIZE;
	worker->buddy = buddy_embed((void *)worker->send_buffer, PRSV_WORKER_BUF_SIZE);
#ifdef USE_PORTALS
    worker->eqh = eqh;
#endif
	return worker;
}

char *portals_worker_get_buffer(struct portals_worker *worker, uint32_t total_bytes)
{
	void *buff = buddy_malloc(worker->buddy, total_bytes);
	if (buff == NULL) {
		log_fatal("buddy_allocator returned NULL buffer");
		exit(EXIT_FAILURE);
	}
	return buff;
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

#ifdef USE_PORTALS
void portals_worker_send_reply_buff(struct portals_worker *worker, struct par_net_header *reply_header,
				    uint32_t total_bytes, ptl_handle_ni_t nih, ptl_process_t client)
#else
void portals_worker_send_reply_buff(struct portals_worker *worker, struct par_net_header *reply_header,
				    uint32_t total_bytes)
#endif
{
	#ifdef USE_PORTALS
	worker->md.start = reply_header;
	worker->md.length = total_bytes;
	worker->md.options = 0;
	worker->md.eq_handle = worker->eqh;
	worker->md.ct_handle = PTL_CT_NONE;

	int ret = PtlMDBind(nih, &worker->md, &worker->mdh);
	if (ret != PTL_OK) {
		log_debug("PtlMDBind failed");
		_exit(EXIT_FAILURE);
	}
	ret = PtlPut(worker->mdh, 0, total_bytes, PTL_ACK_REQ, client, 0, 0, 0, worker->md.start, 0);
	if (ret != PTL_OK) {
		log_debug("PtlPut failed");
		_exit(EXIT_FAILURE);
	}

	PtlMDRelease(worker->mdh);
	#endif

	#ifdef USE_INFINIBAND

	// TODO: Implement InfiniBand logic here

	#endif
}

void portals_worker_free_buf(struct portals_worker *worker, void *buf_start)
{
	buddy_free(worker->buddy, buf_start);
}

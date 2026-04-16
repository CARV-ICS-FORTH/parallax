#include "ccqueue.h"
#include "config.h"
#include "log.h"
#include "par_net.h"
#include "par_net_worker.h"
#ifdef USE_PORTALS
#include "portals.h"
#include "portals4.h"
#include "portals4_ext.h"
#endif
#include "par_net_worker_request.h"
#include "primitives.h"
#include "queue-stack.h"
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <x86intrin.h>

#define BUDDY_ALLOC_IMPLEMENTATION
#include "../portals_server/buddy_alloc.h"
#undef BUDDY_ALLOC_IMPLEMENTATION

#define EMPTY_WAIT 1000

#ifdef USE_INFINIBAND
#define PRSV_WORKER_BUF_SIZE (63U * 4096)
#define METADATA_SIZE 4096
#define N_RESPONSE_BUFFERS 4
#define SECTOR_SIZE 512
#endif

struct counter {
	uint32_t counter;
	uint8_t padding[60];
};

struct response_slot {
	char *buf;
	struct ibv_mr *mr;
	uint32_t buf_size;
};

struct par_net_worker {
	struct counter queuecounter;
	struct counter queuecompletedcounter;
	sem_t empty;
	atomic_int notified;
	pthread_t tid;
	uint64_t start;
	uint64_t end;
	uint64_t core;
	uint64_t send_buffer_size;
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
	CCQueueStruct free_slot_q;
	CCQueueThreadState *free_q_th_state;
	struct response_slot slots[N_RESPONSE_BUFFERS];
#endif
};

size_t par_net_worker_size(void)
{
	return sizeof(struct par_net_worker);
}

void par_net_worker_lock(struct par_net_worker *worker)
{
	pthread_mutex_lock(worker->mutex);
}

void par_net_worker_unlock(struct par_net_worker *worker)
{
	pthread_mutex_unlock(worker->mutex);
}

void par_net_worker_notify(struct par_net_worker *worker)
{
	sem_post(&worker->empty);
}

uint32_t par_net_worker_get_reqs(struct par_net_worker *worker)
{
	__atomic_load_n(&worker->queuecounter.counter, __ATOMIC_RELAXED);
	__atomic_load_n(&worker->queuecompletedcounter.counter, __ATOMIC_RELAXED);
	return worker->queuecounter.counter - worker->queuecompletedcounter.counter;
}

#define CPU_FREQ_HZ 2300

struct par_net_worker_request *par_net_worker_poll(struct par_net_worker *worker)
{
	long elapsed_time = (worker->end - worker->start) / CPU_FREQ_HZ;
	//log_debug("Thread %lu: Elapsed time since last event: %ld usec", worker->core, elapsed_time);

	sem_wait(&worker->empty);

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
		  par_net_worker_get_reqs(worker));
	struct par_net_worker_request *req = (struct par_net_worker_request *)rawval;
	log_debug("got event in thread : %lu", worker->core);
	return req;
}

void par_net_worker_put(struct par_net_worker *worker, struct par_net_worker_request *request)
{
	CCQueueApplyEnqueue(worker->queue_object, worker->th_state, (ArgVal)request, worker->tid);
	__atomic_fetch_add(&worker->queuecounter.counter, 1, __ATOMIC_RELAXED);
}

#ifdef USE_PORTALS
struct par_net_worker *par_net_worker_create(struct server_handle *server_handle, uint32_t index, uint32_t threadno,
					     ptl_handle_eq_t eqh, pthread_mutex_t *mutex)
{
	int ret;
	struct par_net_worker *worker = calloc(1, sizeof(struct par_net_worker));
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
	worker->eqh = eqh;
	return worker;
}
#elif USE_INFINIBAND
struct par_net_worker *par_net_worker_create(struct server_handle *server_handle, uint32_t index, uint32_t threadno,
					     pthread_mutex_t *mutex)
{
	int ret;
	struct par_net_worker *worker = calloc(1, sizeof(struct par_net_worker));
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

	par_net_worker_init_response_buffers(worker, par_ib_server_get_ibv_pd(server_handle),
					     par_ib_server_get_threadno(server_handle));
	worker->free_q_th_state = synchGetAlignedMemory(CACHE_LINE_SIZE, sizeof(CCQueueThreadState));
	CCQueueThreadStateInit(&worker->free_slot_q, worker->free_q_th_state, worker->tid);
	return worker;
}
#endif

#ifdef USE_PORTALS
char *par_net_worker_get_buffer(struct par_net_worker *worker, uint32_t total_bytes)
{
	void *buff = buddy_malloc(worker->buddy, total_bytes);
	if (buff == NULL) {
		log_fatal("buddy_allocator returned NULL buffer");
		exit(EXIT_FAILURE);
	}
	return buff;
}
#endif

struct server_handle *par_net_worker_get_server_handle(struct par_net_worker *worker)
{
	return (struct server_handle *)worker->server_handle;
}

uint32_t par_net_worker_get_buffer_size(struct par_net_worker *worker)
{
	return (uint32_t)worker->send_buffer_size;
}

void par_net_worker_set_buffer_size(struct par_net_worker *worker, uint64_t size)
{
	worker->send_buffer_size = size;
}

uint64_t par_net_worker_get_core(struct par_net_worker *worker)
{
	return (uint64_t)worker->core;
}

pthread_t *par_net_worker_get_tid(struct par_net_worker *worker)
{
	return (pthread_t *)&worker->tid;
}

#ifdef USE_PORTALS
void par_net_worker_send_reply_buff(struct par_net_worker *worker, struct par_net_header *reply_header,
				    uint32_t total_bytes, ptl_handle_ni_t nih, ptl_process_t client)
{
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
}
#elif USE_INFINIBAND
void par_net_worker_init_response_buffers(struct par_net_worker *worker, struct ibv_pd *pd, int nthreads)
{
	const size_t buf_size = KV_MAX_SIZE;
	CCQueueStructInit(&worker->free_slot_q, nthreads);
	CCQueueThreadState init_ts;
	CCQueueThreadStateInit(&worker->free_slot_q, &init_ts, 0);
	for (int i = 0; i < N_RESPONSE_BUFFERS; ++i) {
		if (posix_memalign((void **)&worker->slots[i].buf, SECTOR_SIZE, buf_size) != 0) {
			perror("posix_memalign response_buffer");
			_exit(EXIT_FAILURE);
		}
		worker->slots[i].buf_size = buf_size;
		worker->slots[i].mr = ibv_reg_mr(pd, worker->slots[i].buf, buf_size, IBV_ACCESS_LOCAL_WRITE);
		if (!worker->slots[i].mr) {
			perror("ibv_reg_mr response_buffer");
			_exit(EXIT_FAILURE);
		}

		CCQueueApplyEnqueue(&worker->free_slot_q, &init_ts, (ArgVal)i, 0);
	}
}

void par_net_worker_send_reply_buff(struct par_net_worker *worker, uint32_t total_bytes, struct ibv_qp *qp, int slot)
{
	char *buf = worker->slots[slot].buf;
	struct ibv_mr *response_mr = worker->slots[slot].mr;

	struct ibv_sge sge = {
		.addr = (uintptr_t)buf,
		.length = total_bytes,
		.lkey = response_mr->lkey,
	};

	uint16_t type = 1;
	uint16_t worker_id = worker->core;
	struct ibv_send_wr wr = { 0 }, *bad_wr = NULL;
	wr.wr_id = make_wr_id(type, worker_id, slot);
	wr.opcode = IBV_WR_SEND;
	wr.send_flags = IBV_SEND_SIGNALED;
	wr.sg_list = &sge;
	wr.num_sge = 1;

	if (ibv_post_send(qp, &wr, &bad_wr)) {
		perror("ibv_post_send");
		exit(EXIT_FAILURE);
	}
}

int response_slot_acquire(struct par_net_worker *worker)
{
	RetVal rv = CCQueueApplyDequeue(&worker->free_slot_q, worker->free_q_th_state, worker->tid);
	if (rv == EMPTY_QUEUE)
		return -1;
	return (int)rv;
}

char *par_net_worker_get_response_buffer(struct par_net_worker *worker, int slot)
{
	return worker->slots[slot].buf;
}

uint64_t make_wr_id(uint16_t type, uint16_t worker_id, uint32_t slot)
{
	return ((uint64_t)type << 48) | ((uint64_t)worker_id << 32) | slot;
}

void parse_wr_id(uint64_t wr_id, uint16_t *type, uint16_t *worker_id, uint32_t *slot)
{
	*type = (wr_id >> 48) & 0xFFFF;
	*worker_id = (wr_id >> 32) & 0xFFFF;
	*slot = wr_id & 0xFFFFFFFF;
}

void par_net_worker_put_response_slot(struct par_net_worker *worker, uint32_t slot)
{
	CCQueueApplyEnqueue(&worker->free_slot_q, worker->free_q_th_state, (ArgVal)slot, worker->tid);
}

#endif

void par_net_worker_free_buf(struct par_net_worker *worker, void *buf_start)
{
	buddy_free(worker->buddy, buf_start);
}

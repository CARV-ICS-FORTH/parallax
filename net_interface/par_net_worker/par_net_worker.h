#ifndef PAR_NET_WORKER_H
#define PAR_NET_WORKER_H
#include "../ib_server/ib_client_ctx.h"
#include "../par_net/par_net.h"
#ifdef USE_PORTALS
#include "portals4.h"
#endif
#include "../portals_server/portals_server_handle.h"
struct par_net_worker;

/* Header for par_net_worker api*/

/**
 * Returns the size of the worker structure.
 */
size_t par_net_worker_size(void);

/**
 * Acquires the worker's mutex lock.
 */
void par_net_worker_lock(struct par_net_worker *worker);

/**
 * Releases the worker's mutex lock.
 */
void par_net_worker_unlock(struct par_net_worker *worker);

/**
 * Notifies the worker that new work is available.
 * Posts to the semaphore only if the worker was not already notified.
 * Prevents duplicate wakeups.
 */
void par_net_worker_notify(struct par_net_worker *worker);

/**
 * Returns the number of pending requests in the worker's queue.
 */
uint32_t par_net_worker_get_reqs(struct par_net_worker *worker);

/**
 * Polls the request queue and returns the next request.
 * Waits on a semaphore if the queue is empty for a while.
 * @return Pointer to the dequeued request or NULL if empty.
 */
struct par_net_worker_request *par_net_worker_poll(struct par_net_worker *worker);

/**
 * Enqueues a request into the worker's queue.
 */
void par_net_worker_put(struct par_net_worker *worker, struct par_net_worker_request *request);

/**
 * Creates and initializes a new worker instance.
 * Allocates memory, initializes the queue, state, and buffer.
 * @param server_handle Pointer to the owning server.
 * @param index Worker thread index.
 * @param threadno Total number of worker threads.
 * @param mutex Shared mutex for thread coordination.
 */
#ifdef USE_PORTALS
struct par_net_worker *par_net_worker_create(struct server_handle *server_handle, uint32_t index, uint32_t threadno,
					     ptl_handle_eq_t eqh, pthread_mutex_t *mutex);
#elif USE_INFINIBAND
struct par_net_worker *par_net_worker_create(struct server_handle *server_handle, uint32_t index, uint32_t threadno,
					     pthread_mutex_t *mutex);
#endif

/**
 * Allocates memory from the worker's buddy allocator.
 */
#ifdef USE_PORTALS
char *par_net_worker_get_buffer(struct par_net_worker *worker, uint32_t total_bytes);
#elif USE_INFINIBAND
char *par_net_worker_get_buffer(uint32_t total_bytes);
#endif

/**
 * Returns the server_handle associated with the worker.
 */
struct server_handle *par_net_worker_get_server_handle(struct par_net_worker *worker);

/** 
 * Sets the size of the worker's send buffer.
 */
void par_net_worker_set_buffer_size(struct par_net_worker *worker, uint64_t size);

/**
 * Returns the size of the worker's send buffer.
 */
uint32_t par_net_worker_get_buffer_size(struct par_net_worker *worker);

/**
 * Returns the worker's core index.
 */
uint64_t par_net_worker_get_core(struct par_net_worker *worker);

/**
 * Returns a pointer to the worker's pthread_t.
 */
pthread_t *par_net_worker_get_tid(struct par_net_worker *worker);

/**
 * Sets the worker's send buffer.
 * Ensures the buffer is not NULL.
 */
void par_net_worker_set_send_buffer(struct par_net_worker *worker, char *send_buffer);

/**
 * Returns a pointer to the worker's send buffer.
 */
char *par_net_worker_get_send_buffer(struct par_net_worker *worker);

/**
 * Sends a reply buffer to a client.
 *
 * @param worker Pointer to the par_net_worker instance.
 * @param reply_header Pointer to the response header.
 * @param total_bytes Total number of bytes to send.
 */
#ifdef USE_PORTALS
void par_net_worker_send_reply_buff(struct par_net_worker *worker, struct par_net_header *reply_header,
				    uint32_t total_bytes, ptl_handle_ni_t nih, ptl_process_t client);
#elif USE_INFINIBAND
void par_net_worker_send_reply_buff(struct par_net_header *reply_header, uint32_t total_bytes,
				    struct ib_client_ctx *ctx);
#endif

/**
 * Frees a buffer previously allocated via the buddy allocator.
 */
void par_net_worker_free_buf(struct par_net_worker *worker, void *buf_start);

#endif

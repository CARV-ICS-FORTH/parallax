#ifndef PORTALS_WORKER_H
#define PORTALS_WORKER_H
#include "../par_net/par_net.h"
#ifdef USE_PORTALS
#include "portals4.h"
#endif
#include "portals_server_handle.h"
#include "../ib_server/ib_worker_request.h"
struct portals_worker;

/* Header for portals_worker api*/

/**
 * Returns the size of the worker structure.
 */
size_t portals_worker_size(void);

/**
 * Acquires the worker's mutex lock.
 */
void portals_worker_lock(struct portals_worker *worker);

/**
 * Releases the worker's mutex lock.
 */
void portals_worker_unlock(struct portals_worker *worker);

/**
 * Notifies the worker that new work is available.
 * Posts to the semaphore only if the worker was not already notified.
 * Prevents duplicate wakeups.
 */
void portals_worker_notify(struct portals_worker *worker);

/**
 * Returns the number of pending requests in the worker's queue.
 */
uint32_t portals_worker_get_reqs(struct portals_worker *worker);

/**
 * Polls the request queue and returns the next request.
 * Waits on a semaphore if the queue is empty for a while.
 * @return Pointer to the dequeued request or NULL if empty.
 */
struct portals_worker_request *portals_worker_poll(struct portals_worker *worker);

/**
 * Enqueues a request into the worker's queue.
 */
#ifdef USE_PORTALS
void portals_worker_put(struct portals_worker *worker, struct portals_worker_request *request);
#else
void portals_worker_put(struct portals_worker *worker, struct ib_worker_request *request);
#endif

/**
 * Creates and initializes a new worker instance.
 * Allocates memory, initializes the queue, state, and buffer.
 * @param server_handle Pointer to the owning server.
 * @param index Worker thread index.
 * @param threadno Total number of worker threads.
 * @param mutex Shared mutex for thread coordination.
 */
#ifdef USE_PORTALS
struct portals_worker *portals_worker_create(struct server_handle *server_handle, uint32_t index, uint32_t threadno,
                             ptl_handle_eq_t eqh, pthread_mutex_t *mutex);
#else
struct portals_worker *portals_worker_create(struct server_handle *server_handle, uint32_t index, uint32_t threadno,
                             pthread_mutex_t *mutex);
#endif

/**
 * Allocates memory from the worker's buddy allocator.
 */	 
char *portals_worker_get_buffer(struct portals_worker *worker, uint32_t total_bytes);

/**
 * Returns the server_handle associated with the worker.
 */
struct server_handle *portals_worker_get_server_handle(struct portals_worker *worker);

/**
 * Returns the size of the worker's send buffer.
 */
uint32_t portals_worker_get_buffer_size(struct portals_worker *worker);

/**
 * Returns the worker's core index.
 */
uint64_t portals_worker_get_core(struct portals_worker *worker);

/**
 * Returns a pointer to the worker's pthread_t.
 */
pthread_t *portals_worker_get_tid(struct portals_worker *worker);

/**
 * Sends a reply buffer to a client using Portals 4.
 * Uses PtlMDBind and PtlPut to send the response.
 *
 * @param worker Pointer to the portals_worker instance.
 * @param reply_header Pointer to the response header.
 * @param total_bytes Total number of bytes to send.
 * @param nih Portals network interface handle.
 * @param client Target client process.
 */
#ifdef USE_PORTALS
void portals_worker_send_reply_buff(struct portals_worker *worker, struct par_net_header *reply_header,
				    uint32_t total_bytes, ptl_handle_ni_t nih, ptl_process_t client);
#else
void portals_worker_send_reply_buff(struct portals_worker *worker, struct par_net_header *reply_header,
				    uint32_t total_bytes);
#endif

/**
 * Frees a buffer previously allocated via the buddy allocator.
 */
void portals_worker_free_buf(struct portals_worker *worker, void *buf_start);

#endif

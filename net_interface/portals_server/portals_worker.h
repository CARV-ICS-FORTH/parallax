#ifndef PORTALS_WORKER_H
#define PORTALS_WORKER_H
#include "../par_net/par_net.h"
#include "portals4.h"
#include "portals_server_handle.h"
struct portals_worker;

/* Header for portals_worker api*/
size_t portals_worker_size(void);

void portals_worker_lock(struct portals_worker *worker);

void portals_worker_unlock(struct portals_worker *worker);

int portals_worker_get_sem_val(struct portals_worker *worker);

void portals_worker_sem_post(struct portals_worker *worker);

uint32_t portals_worker_get_reqs(struct portals_worker *worker);

struct portals_worker *portals_worker_create(struct server_handle *server_handle, uint32_t index, uint32_t threadno,
					     ptl_handle_eq_t eqh, pthread_mutex_t *mutex);

struct portals_worker_request *portals_worker_poll(struct portals_worker *worker);

void portals_worker_put(struct portals_worker *worker, struct portals_worker_request *request);

char *portals_worker_get_buffer(struct portals_worker *worker, uint32_t total_bytes);

struct server_handle *portals_worker_get_server_handle(struct portals_worker *worker);

uint32_t portals_worker_get_buffer_size(struct portals_worker *worker);

uint64_t portals_worker_get_core(struct portals_worker *worker);

pthread_t *portals_worker_get_tid(struct portals_worker *worker);

void portals_worker_send_reply_buff(struct portals_worker *worker, struct par_net_header *reply_header,
				    uint32_t total_bytes, ptl_handle_ni_t nih, ptl_process_t client);

void portals_worker_free_buf(struct portals_worker *worker, void *buf_start);

#endif

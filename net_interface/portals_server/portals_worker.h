#include "portals4.h"
#include "portals_server_handle.h"
#include <pthread.h>
#include <stdint.h>
struct portals_worker;

/* Header for portals_worker api*/
size_t portals_worker_size(void);

struct portals_worker *portals_worker_create(struct server_handle *server_handle, ptl_handle_ni_t nih, uint32_t index);

int portals_worker_poll(struct portals_worker *worker, ptl_event_t *event);

void portals_worker_put(struct portals_worker *worker, ptl_event_t *event);

char *portals_worker_get_buffer(struct portals_worker *worker);

struct server_handle *portals_worker_get_server_handle(struct portals_worker *worker);

uint32_t portals_worker_get_buffer_size(struct portals_worker *worker);

uint64_t portals_worker_get_core(struct portals_worker *worker);

pthread_t *portals_worker_get_tid(struct portals_worker *worker);

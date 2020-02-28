#ifndef _TUCANASERVER_STATS_H_
#define _TUCANASERVER_STATS_H_

#include <inttypes.h>

extern volatile uint32_t* sum_scan_length;
extern volatile uint32_t* operations;
extern volatile char stat_reporter_thread_exit;

/* Initialize stastistics module and starts the reporter thread
 * @arg threads: number of worker threads
 */
void stats_init(int threads);

/* Called when a new request has been received by a worker thread
 * @arg thread_id: id of the calling thread
 */
void stats_update(int thread_id);

/* Stop the reporter thread */
void stats_notify_stop_reporter_thread(void);

#endif //_TUCANASERVER_STATS_H_

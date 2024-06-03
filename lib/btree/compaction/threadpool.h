#ifndef THREADPOOL_H
#define THREADPOOL_H
#define BG_THREAD_NUM 4
#define BG_TASK_NUM (BG_THREAD_NUM * 16)
#include "sst.h"
#include <pthread.h>
#include <stdbool.h>

struct compaction {
	struct sst *dest_ssts[32];
	struct sst *src_sst;
	unsigned src_level;
	unsigned dest_level;
	unsigned dest_ssts_num;
};

enum bg_task_type { BG_TASK_NONE = 0, BG_TASK_COMPACTION };

struct bg_task {
	union {
		struct compaction compaction;
	};
	enum bg_task_type type;
};

struct threadpool {
	struct bg_task tasks[BG_TASK_NUM];
	pthread_t threads[BG_THREAD_NUM];
	pthread_mutex_t mutex;
	bool exit_all_threads;
};

/**
 * @brief Returns an initialized thread pool.
 *
 */
struct threadpool *threadpool_init(void);

/**
 * @brief Set the compaction task object
 *
 * @param task An empty task slot from the thread pool.
 * @param src_sst The sst from the source level.
 * @param src_level The source level.
 * @param dest_ssts The ssts from the destination level.
 * @param dest_level The destination level.
 * @param dest_ssts_num The number of ssts in the destination level.
 */
void set_compaction_task(struct bg_task *task, struct sst *src_sst, unsigned src_level, struct sst *dest_ssts[],
			 unsigned dest_level, unsigned dest_ssts_num);
/**
 * @brief Adds a task to the thread pool.
 *
 * @param thread_pool An inititalized thread pool.
 * @param task a filled task
 */
void threadpool_add_task(struct threadpool *thread_pool, const struct bg_task *task);

/**
 * @brief Releases the thread pool resources.
 *
 * @param thread_pool An initialized thread pool.
 */
void threadpool_exit(struct threadpool *thread_pool);

#endif // THREADPOOL_H

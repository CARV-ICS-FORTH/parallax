#define _GNU_SOURCE
#include "threadpool.h"
#include <pthread.h>

void *threadpool_worker(void *arg);

struct threadpool *threadpool_init(void)
{
	struct threadpool *thread_pool = malloc(sizeof(struct threadpool));
	MUTEX_INIT(&thread_pool->mutex, NULL);
	thread_pool->exit_all_threads = false;
	for (int i = 0; i < BG_THREAD_NUM; i++) {
		pthread_create(&thread_pool->threads[i], NULL, threadpool_worker, thread_pool);
	}
	return thread_pool;
}

void *threadpool_worker(void *arg)
{
	pthread_setname_np(pthread_self(), "bg_worker");
	struct threadpool *thread_pool = (struct threadpool *)arg;
	const struct compaction *compaction = NULL;

	while (true) {
		// Enter CS to check the task queue
		MUTEX_LOCK(&thread_pool->mutex);

		// Check if the thread should exit
		if (thread_pool->exit_all_threads) {
			MUTEX_UNLOCK(&thread_pool->mutex);
			break;
		}

		// Check if there are any tasks
		for (int i = 0; i < BG_TASK_NUM; i++) {
			switch (thread_pool->tasks[i].type) {
			case BG_TASK_NONE:
				continue;
			case BG_TASK_COMPACTION:
				compaction = &thread_pool->tasks[i].compaction;
				thread_pool->tasks[i].type = BG_TASK_NONE;
				break;
			}
		}

		MUTEX_UNLOCK(&thread_pool->mutex);

		if (compaction != NULL) {
			// Do the compaction
			compaction = NULL;
		}
	}
	pthread_exit(NULL);
}

void set_compaction_task(struct bg_task *task, struct sst *src_sst, unsigned src_level, struct sst *dest_ssts[],
			 unsigned dest_level, unsigned dest_ssts_num)
{
	task->type = BG_TASK_COMPACTION;
	task->compaction.src_sst = src_sst;
	task->compaction.src_level = src_level;
	task->compaction.dest_level = dest_level;
	task->compaction.dest_ssts_num = dest_ssts_num;
	for (int i = 0; i < dest_ssts_num; i++) {
		task->compaction.dest_ssts[i] = dest_ssts[i];
	}
}

void threadpool_add_task(struct threadpool *thread_pool, const struct bg_task *task)
{
	MUTEX_LOCK(&thread_pool->mutex);
	for (int i = 0; i < BG_TASK_NUM; i++) {
		if (thread_pool->tasks[i].type == BG_TASK_NONE) {
			thread_pool->tasks[i] = *task;
			break;
		}
	}
	MUTEX_UNLOCK(&thread_pool->mutex);
}

void threadpool_exit(struct threadpool *thread_pool)
{
	MUTEX_LOCK(&thread_pool->mutex);
	thread_pool->exit_all_threads = true;
	MUTEX_UNLOCK(&thread_pool->mutex);
	for (int i = 0; i < BG_THREAD_NUM; i++) {
		pthread_join(thread_pool->threads[i], NULL);
	}
	pthread_mutex_destroy(&thread_pool->mutex);
	free(thread_pool);
}

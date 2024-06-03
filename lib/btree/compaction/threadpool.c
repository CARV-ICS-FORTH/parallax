#define _GNU_SOURCE
#include "threadpool.h"
#include "../../common/common.h"
#include "../conf.h"
#include <assert.h>
#include <log.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>

void *threadpool_worker(void *arg);

struct threadpool *threadpool_init(void)
{
	struct threadpool *thread_pool = calloc(1, sizeof(struct threadpool));
	if (thread_pool == NULL) {
		log_fatal("Failed to allocate memory for thread pool");
		BUG_ON();
	}

	MUTEX_INIT(&thread_pool->mutex, NULL);
	thread_pool->exit_all_threads = false;
	for (unsigned i = 0; i < BG_THREAD_NUM; i++) {
		pthread_create(&thread_pool->threads[i], NULL, threadpool_worker, thread_pool);
	}
	return thread_pool;
}

void *threadpool_worker(void *arg)
{
	pthread_setname_np(pthread_self(), "bg_worker");
	struct threadpool *thread_pool = (struct threadpool *)arg;
	struct bg_task *task = NULL;
	bool compaction = false;

	while (true) {
		// Enter CS to check the task queue
		MUTEX_LOCK(&thread_pool->mutex);

		// Check if the thread should exit
		if (thread_pool->exit_all_threads) {
			MUTEX_UNLOCK(&thread_pool->mutex);
			break;
		}

		// Check if there are any tasks
		for (unsigned i = 0; i < BG_TASK_NUM; i++) {
			switch (thread_pool->tasks[i].type) {
			case BG_TASK_NONE:
			case BG_TASK_RESERVED:
				continue;
			case BG_TASK_COMPACTION:
				task = &thread_pool->tasks[i];
				task->type = BG_TASK_RESERVED;
				compaction = true;
				break;
			}
		}

		MUTEX_UNLOCK(&thread_pool->mutex);

		if (compaction) {
			// Do the compaction
			task->type = BG_TASK_NONE;
			compaction = false;
		}
	}
	pthread_exit(NULL);
}

void set_compaction_task(struct bg_task *task, struct sst *src_sst, unsigned src_level, struct sst *dest_ssts[],
			 unsigned dest_level, unsigned dest_ssts_num)
{
	assert(task != NULL);
	assert(task->type == BG_TASK_RESERVED);

	task->compaction.src_sst = src_sst;
	task->compaction.src_level = src_level;
	task->compaction.dest_level = dest_level;
	task->compaction.dest_ssts_num = dest_ssts_num;
	for (unsigned i = 0; i < dest_ssts_num; i++) {
		task->compaction.dest_ssts[i] = dest_ssts[i];
	}

	// Set the task type always as the last step, since
	// the threadpool_worker might pick it up in the middle of the preparation.
	task->type = BG_TASK_COMPACTION;
}

struct bg_task *get_empty_task(struct threadpool *thread_pool)
{
	assert(thread_pool != NULL);

	MUTEX_LOCK(&thread_pool->mutex);

	for (unsigned i = 0; i < BG_TASK_NUM; i++) {
		if (thread_pool->tasks[i].type == BG_TASK_NONE) {
			thread_pool->tasks[i].type = BG_TASK_RESERVED;
			MUTEX_UNLOCK(&thread_pool->mutex);
			return &thread_pool->tasks[i];
		}
	}

	MUTEX_UNLOCK(&thread_pool->mutex);
	return NULL;
}

void threadpool_exit(struct threadpool *thread_pool)
{
	assert(thread_pool != NULL);
	MUTEX_LOCK(&thread_pool->mutex);
	thread_pool->exit_all_threads = true;
	MUTEX_UNLOCK(&thread_pool->mutex);

	for (int i = 0; i < BG_THREAD_NUM; i++) {
		pthread_join(thread_pool->threads[i], NULL);
	}

	pthread_mutex_destroy(&thread_pool->mutex);
	free(thread_pool);
}

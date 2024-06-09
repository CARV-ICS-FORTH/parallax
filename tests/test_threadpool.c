#include <assert.h>
#include <btree/compaction/sst.h>
#include <btree/compaction/threadpool.h>
#include <log.h>
#include <unistd.h>
struct sst;

int main(void)
{
	struct threadpool *thread_pool = threadpool_init();

	struct bg_task *task;
	struct sst *src_sst = NULL;
	struct sst *dest_ssts[32] = { NULL };

	unsigned src_level = 0;
	unsigned dest_level = 0;
	unsigned dest_ssts_num = 0;

	task = get_empty_task(thread_pool);
	if (NULL == task) {
		log_fatal("Failed to get an empty task");
		return 1;
	}

	set_compaction_task(task, src_sst, src_level, dest_ssts, dest_level, dest_ssts_num);

	// check if the task was dequeued by the worker thread
	unsigned count = 3;
	bool success = true;
	while (1) {
		for (unsigned i = 0; i < BG_TASK_NUM; i++) {
			if (thread_pool->tasks[i].type == BG_TASK_COMPACTION)
				success = false;
		}

		if (!success) {
			log_info("Task was not dequeued by the worker thread");
		}

		if (0 == count || success)
			break;

		success = true;
		--count;
		sleep(1);
	}

	if (!success) {
		log_fatal("Timeout task was not dequeued by the worker thread");
		return 1;
	}

	log_info("Task was dequeued by the worker thread successfully");

	threadpool_exit(thread_pool);
	return 0;
}

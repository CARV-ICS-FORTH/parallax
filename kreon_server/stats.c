#include "stats.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#define OUT_FILE "ops.txt"

static pthread_t stats_reporter_thread_id;
static struct timespec SLEEP_DURATION_TIMESPEC = { 5, 0 }; // sec = usec * 10^6
static int THREADS;
static FILE *output_file;
// (Performance) statistics
volatile uint32_t *sum_scan_length;
volatile uint32_t *operations;
volatile char stat_reporter_thread_exit = 0;

static void *stats_reporter_thread(void *);

void stats_init(int worker_threads)
{
	THREADS = worker_threads;
	sum_scan_length = (uint32_t *)malloc(worker_threads * sizeof(uint32_t));
	operations = (uint32_t *)malloc(worker_threads * sizeof(uint32_t));
	memset((void *)operations, 0, worker_threads * sizeof(uint32_t));
	memset((void *)sum_scan_length, 0, worker_threads * sizeof(uint32_t));
	output_file = fopen(OUT_FILE, "w");
	pthread_create(&stats_reporter_thread_id, NULL, stats_reporter_thread, NULL);
}

void stats_update(int thread_id)
{
	++operations[thread_id];
}

void stats_notify_stop_reporter_thread(void)
{
	stat_reporter_thread_exit = 1;
}

static uint32_t sum_uint_array(uint32_t *array, size_t length)
{
	uint32_t sum = 0;
	for (int i = 0; i < length; ++i) {
		sum += array[i];
	}
	return sum;
}

static void *stats_reporter_thread(void *args)
{
	uint32_t ops_at_last_second = sum_uint_array((uint32_t *)operations, THREADS);
	uint32_t ops_at_curr_second;
	struct timespec rem;
	size_t seconds_passed = 0;

	while (!sum_uint_array((uint32_t *)operations, THREADS))
		nanosleep(&SLEEP_DURATION_TIMESPEC, &rem);

	do {
		nanosleep(&SLEEP_DURATION_TIMESPEC, &rem);
		seconds_passed += SLEEP_DURATION_TIMESPEC.tv_sec;

		ops_at_curr_second = sum_uint_array((uint32_t *)operations, THREADS);
		fprintf(stdout, "%lu Sec %.2f Ops/sec\n", seconds_passed,
			(ops_at_curr_second - ops_at_last_second) / (double)SLEEP_DURATION_TIMESPEC.tv_sec);
		fprintf(output_file, "%lu Sec %.2f Ops/sec\n", seconds_passed,
			(ops_at_curr_second - ops_at_last_second) / (double)SLEEP_DURATION_TIMESPEC.tv_sec);
		fflush(output_file);
		ops_at_last_second = ops_at_curr_second;
	} while (!stat_reporter_thread_exit);

	fclose(output_file);

	return NULL;
}

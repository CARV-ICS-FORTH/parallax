#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include "allocator.h"
#define DEV "/dev/kram"

#define NUM_OF_THREADS 1
#define TOTAL_BLOCKS 2097152
#define SCHED

extern uint64_t collisions;
extern uint64_t hits;
extern uint64_t sleep_times;
extern int32_t max_tries;
int count;
int cpu_id = 0;

pthread_t threads[NUM_OF_THREADS];
int ids[NUM_OF_THREADS];
pthread_attr_t attr[NUM_OF_THREADS];
cpu_set_t cpu_set[NUM_OF_THREADS];

pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
unsigned int seeds[NUM_OF_THREADS];

void start(void *id);

int main()
{
	uint64_t duration;
	uint64_t mapped;
	count = 0;
	int i = 0;
	for (i = 0; i < NUM_OF_THREADS; i++) {
		ids[i] = i;
		seeds[i] = get_timestamp() / 1000000;
	}
	mapped = allocator_init(DEV);
	printf("address space starts at %llu\n", mapped);
	printf("Starting %d threads\n", NUM_OF_THREADS);

	for (i = 0; i < NUM_OF_THREADS; i++) {
#ifdef SCHED
		CPU_ZERO(&cpu_set[i]);
		//cpu_id = rand()%4;
		CPU_SET(cpu_id, &cpu_set[i]);
		cpu_id++;
		if (cpu_id > 7)
			cpu_id = 0;
		pthread_attr_init(&attr[i]);
		pthread_attr_setaffinity_np(&attr[i], sizeof(cpu_set_t), &cpu_set[i]);
		pthread_create(&threads[i], &attr[i], &start, &ids[i]);
#else
		pthread_create(&threads[i], NULL, &start, &ids[i]);
#endif
	}
	for (i = 0; i < NUM_OF_THREADS; i++) {
		pthread_join(threads[i], NULL);
	}
	printf("Collisions %llu hits %llu sleep %llu max_tries %d\n", collisions, hits, sleep_times, max_tries);
	return 1;
}

void start(void *id)
{
	int32_t myid = *(int *)id;
	int32_t i;
	uint64_t addr;
	int32_t decision;
	int32_t size;
	int32_t allocations = TOTAL_BLOCKS / NUM_OF_THREADS;
	uint64_t duration;
	cpu_set_t cpuset;
	pthread_attr_getaffinity_np(&attr[myid], sizeof(cpuset), &cpuset);
	printf("Size of cpuset %d\n", sizeof(cpuset));

	pthread_mutex_lock(&mutex);
	count++;
	if (count < NUM_OF_THREADS) {
		//printf("Count is %d wait for the others\n");
		pthread_cond_wait(&cond, &mutex);
	} else {
		//printf("Let's go guys\n");
		pthread_cond_broadcast(&cond);
	}
	pthread_mutex_unlock(&mutex);

	printf("allocations %d\n", allocations);
	duration = get_timestamp();
	for (i = 0; i < allocations; i++) {
		/*decision = rand_r(&seeds[myid])%10;	
		if(decision < 7) 
			size = 4096;
		else 
			size = 131072;*/
		size = 16384;
		addr = allocate(size);
		if (addr == 0) {
			printf("No more space i = %d\n", i);
			exit(-1);
		}
		/*if(i%100 == 0)
			printf("progress for thread %d allocations are %d\n", myid, i);*/
	}
	duration = get_timestamp() - duration;
	printf("duration for thread %d is %llu micro\n", myid, duration);
	return;
}

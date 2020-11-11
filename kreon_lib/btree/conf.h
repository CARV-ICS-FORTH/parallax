/*macros staff*/
#pragma once
#define SPINLOCK_INIT(L, attr) pthread_spin_init(L, attr)
#define SPIN_LOCK(L) pthread_spin_lock(L)
#define SPIN_UNLOCK(L) pthread_spin_unlock(L)

/*Important note Condition variables are not defined*/
#define MUTEX_INIT(L, attr) pthread_mutex_init(L, attr)
#define MUTEX_LOCK(L) pthread_mutex_lock(L)
#define MUTEX_TRYLOCK(L) pthread_mutex_trylock(L)
#define MUTEX_UNLOCK(L) pthread_mutex_unlock(L)

#define RWLOCK_INIT(L, attr) pthread_rwlock_init(L, attr)
#define RWLOCK_WRLOCK(L) pthread_rwlock_wrlock(L)
#define RWLOCK_RDLOCK(L) pthread_rwlock_rdlock(L)
#define RWLOCK_UNLOCK(L) pthread_rwlock_unlock(L)

/*don't use for spin lock for log, critical section contains RDMA communication*/
#define LOG_WITH_MUTEX 1

#define MAX_DB_NAME_SIZE 64
/*hierarchy of trees parameters*/
#define MAX_LEVELS 8
#define NUM_TREES_PER_LEVEL 2
#define TOTAL_TREES (MAX_LEVELS * NUM_TREES_PER_LEVEL)
#define GROUP_SIZE 5
#define NUM_OF_DB_GROUPS 506
#define DEVICE_BLOCK_SIZE 4096

/*for allocator.c*/
#define DATA_PER_BITMAP_BLOCK ((DEVICE_BLOCK_SIZE - 8) * 8) /*Data blocks addressed per bitmap block*/
#define FREE_LOG_SIZE 512000 /*size in 4KB blocks of the log used for marking the free ops*/

#define CLEAN_SIZE 500000

#define SEC (1000000L)

#define CLEAN_INTERVAL (50 * SEC)
#define COMMIT_KV_LOG_INTERVAL (500 * SEC)
#define SNAPSHOT_INTERVAL (1500 * SEC)
#define GC_INTERVAL (50 * SEC)

#define WORD_SIZE 64
#define BREAKPOINT asm volatile("int3;");

#define KEY_BLOCK_SIZE 8192 // 4KB

/*from scan.c*/
#define MAX_SIZE 64

/*various*/
#define LLU long long unsigned

#define GROWTH_FACTOR 4
#define L0_SIZE 2000000
/*Buffering related tunables*/

#define GB(x) (x * 1024LU * 1024LU * 1024LU)
#define MB(x) (x * 1024LU * 1024LU)
#define MAX_LEVEL0_TOTAL_SIZE MB(64)
#define NUMBER_OF_DATABASES (1)
#define GF (4)
#define BUFFER_SEGMENT_SIZE (2 * 1024 * 1024)
#define SEGMENT_MEMORY_THREASHOLD 511 /*Careful, in number of pages -1 used for chaining*/
#define MAX_ALLOCATION_TRIES 2

#define INSERT_TO_INDEX 1

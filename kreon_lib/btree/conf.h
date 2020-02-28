#define OFFSET_IN_KEY 0
/*DEBUG operation FLAGS*/
#define DEBUG_ALLOCATOR_NO
#define DEBUG_CLEANER_NO
#define DEBUG_SNAPSHOT_NO
#define DEBUG_INSERT_NO
#define DEBUG_READ_NO
#define DEBUG_TUCANA_2_NO
#define DEBUG_SCAN_NO
#define DEBUG_DELETE_NO


/*don't use for spin lock for log, critical section contains RDMA communication*/
#define LOG_WITH_MUTEX 1

/*for allocator.c*/
#define DEV_NAME_MAX		512                   /* Length of the device name */
#define DATA_PER_BITMAP_BLOCK  ((DEVICE_BLOCK_SIZE-8)*8)/*Data blocks addressed per bitmap block*/
#define BITSPERBYTE			8
#define SETBITS64				0xFFFFFFFFFFFFFFFF
#define ZEROBITS32			0x00000000
#define SETBITS32				0xFFFFFFFF
#define FREE_LOG_SIZE     512000/*size in 4KB blocks of the log used for marking the free ops*/

#define MAX_HANDLES			5090
#define DEVICE_BLOCK_SIZE 4096
#define CLEAN_SIZE				500000

#define SEC (1000000L)
#define CLEAN_INTERVAL    (5*SEC)
#define COMMIT_KV_LOG_INTERVAL (500*SEC)
#define SNAPSHOT_INTERVAL (1500*SEC)


#define debug
#define nodemo
#define WORD_SIZE 64
#define BREAKPOINT  asm volatile ("int3;");

#define MARK_BLOCK_NO
#define SPINNING
#define no_profile

#define MAPPRIVATE_NO/*to use the MAP_PRIVATE OR NOT?*/
#define MSYNC /* to issue msync or not?*/
#define MMAP/* to mmap a device or use malloc?*/

#define KB (1024)
#define PG (4*KB)
#define MB (KB*KB)


#define   KEY_BLOCK_SIZE 4096		// 4KB

#define	MEMCMP

/*from scan.c*/
#define MAX_SIZE 4096

#define NODE_SIZE 4096
#define COUNTERS_no /*enables counter stats*/

/*various*/
#define LLU long long unsigned

#define LEAF_METADATA_SIZE 4096 //Typically metadata will be 4KB
#define LEAF_INSERT_OK 7
#define MAX_KEY_SIZE 32
#define MAX_DATA_SIZE 128

/*Buffering related tunables*/
#define AGGRESIVE_FREE_POLICY
#define TO_SPILL_KEYS    16384

#define GB(x) (x * 1024LU * 1024LU * 1024LU)
#define LEVEL0_TOTAL_SIZE GB (4)
#define NUMBER_OF_DATABASES (1)
#define ZERO_LEVEL_MEMORY_UPPER_BOUND (LEVEL0_TOTAL_SIZE / NUMBER_OF_DATABASES) /*max total memory of level-0 where clients are throttled*/
#define ZERO_LEVEL_MEMORY_SPILL_THREASHOLD (0.9 * ZERO_LEVEL_MEMORY_UPPER_BOUND) /*max memory of level-0 to start spilling, in bytes*/

#define BUFFER_SEGMENT_SIZE 2097152
#define SEGMENT_MEMORY_THREASHOLD 511 /*Careful, in number of pages -1 used for chaining*/
#define THROTTLE_SLEEP_TIME 200000
#define MAX_ALLOCATION_TRIES 2

#define ENABLE_REORGANIZATION_NO
#define SCAN_REORGANIZATION_NO

#define INSERT_TO_INDEX 1
#define LOG_WITH_MUTEX 1

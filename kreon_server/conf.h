#pragma once
#include <inttypes.h>
#include <semaphore.h>

/*mvard added defines for return when function succeded or failed*/
typedef enum kreon_op_status {
	KREON_SUCCESS = 1,
	KREON_FAILURE,
	KREON_KEY_NOT_FOUND,
	KREON_VALUE_TOO_LARGE
} kreon_op_status;

/*gesalous, priorities and properties regarding the conections*/
#define HIGH_PRIORITY 1203
#define LOW_PRIORITY 9829
/*connection properties for memory sizes of the connections*/
#define DEFAULT_MEMORY_SIZE_OPTION 0xFA
#define CONTROL_CONNECTION_MEMORY_SIZE 1048576

#define TUCANA_DEBUG 0
#define MAX_MAILBOX 1
#define MAX_MAILBOX_LESS_1 (MAX_MAILBOX - 1)
#define CLI_SIGNAL 0 // 1 we are using pthread_kill to wake threads, 0 we are using pthread_cond_broadcast

#define MRQ_SIZES
#define MRQ_ELEMENT_SIZE 1024 //original value was 1024  Size of each element of the memory region: 1k
#define MRQ_MSG_SIZE 1024 // original value was 1024 Size of each element of the memory region: 1k

#define MAX_ID_LENGTH 256
#define MAX_KEY_LENGTH 64

//TODO move properties to a configuration file
#define RDMA_IP_FILTER "192.168.4."

#define TU_SEMAPHORE 1
#define TU_RDMA 1 // 1 RDMA , 0 ZMQ
#define TU_RDMA_SINGLE_MESSAGE                                                                                         \
	1 //1 puts as a single message, 0 puts with several messages, each of 1K, although all sent together

#define TU_FAKE_YCSB 0 //Only YCSB and nothing else is run
#define TU_FAKE_SEND 0 // Request is not send
#define TU_FAKE_RECV 0 //We send but we dont process the received messages
#define TU_FAKE_PAYLOAD 0
#define FAKE_ONLY_HDR 1
#define FAKE_ONLY_PAYLOAD 0

#define TU_FAKE_BTREE 0 //1 if the betree at the server is a fake one

#define SINGLE_REGION 0
#define TU_MEMORY_SEQ 1 // Memory is allocated sequentially, even with MemoryRegions

#define TU_TIMING 0 //We measure the time needed in each phase

#define TU_RDMA_CONN_PER_REGION 0 // 1 RDMA connection per region, 0 RDMA connection per server
#define TU_RDMA_CONN_PER_SERVER (!TU_RDMA_CONN_PER_REGION)

#ifdef TU_RDMA_CONN_PER_SERVER
/*in case of CONN_PER_SERVER*/
#define NUM_OF_CONNECTIONS_PER_SERVER 8
#else
#define NUM_OF_CONNECTIONS_PER_SERVER 1
#endif

#define SIZEUINT32_T (sizeof(uint32_t))
#define SIZEUINT32_T_2 (sizeof(uint32_t) << 1)

//#define WORKER_THREADS_PER_SPINNING_THREAD 4
#define TU_HEADER_SIZE (sizeof(struct msg_header))
#define TU_TAIL_SIZE (sizeof(uint32_t))
#define TU_HEADER_TAIL_SIZE (TU_HEADER_SIZE + TU_TAIL_SIZE)

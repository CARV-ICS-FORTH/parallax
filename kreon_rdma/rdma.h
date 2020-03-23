#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <semaphore.h>
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

#include "../utilities/macros.h"
#include "../kreon_server/conf.h"
#include "../kreon_server/messages.h"
#include "../utilities/queue.h"
#include "../utilities/simple_concurrent_list.h"
#include "../utilities/circular_buffer.h"
#include "memory_region_pool.h"

#define MAX_USEC_BEFORE_SLEEPING 5000000

#define RECORTADO 0

#define RECV_NO_LOCKS 0 // 1 NO LOCKS, 0 LOCKS
#define TU_CONNECTION_RC 1 // 1 -> RC, 0 -> UC

// Allow to perform our own Reliable Connection. It can be used with TU_CONNECTION_RC 1 or 0
//#define TU_CONNECTION_RC_CONTROL 1 // 1 will control time per msg, 0 will not control nothing

#define KEY_MSG_SIZE 76 //(59)   /* Message size without gid. */
#define KEY_MSG_SIZE_GID 116 // (68) //(108)   /* Message size with gid (MGID as well). */

/* The Format of the message we pass through sockets , without passing Gid. */
#define KEY_PRINT_FMT "%04x:%06x:%06x:%08x:%016Lx:%016Lx:"

/* The Format of the message we pass through sockets (With Gid). */
#define KEY_PRINT_FMT_GID                                                                                              \
	"%04x:%06x:%06x:%08x:%016Lx:%016Lx:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"

#define RD_SEMAPHORE 1

#define CONNECTION_BUFFER_WITH_MUTEX_LOCK

#define SPINNING_THREAD 1
#define SPINNING_PER_CHANNEL 1
#define SPINNING_NO_LIST 1

#if (TU_FAKE_SEND || TU_FAKE_RECV || TU_FAKE_YCSB)
#define SPINNING_NUM_TH 1
#define SPINNING_NUM_TH_CLI 1
#else
#define SPINNING_NUM_TH 8 // was 1
#define SPINNING_NUM_TH_CLI 8 // 4
#endif

#define DEFAULT_PORT "5646"
#define DEFAULT_PORT_NUM 5646
//#define DEFAULT_HOST "192.168.2.106"
#define DEFAULT_HOST "192.168.1.126"
#define DEFAULT_DEV_IBV "mlx4_0"

#define MAX_WR 10000
#define MAX_WR_LESS_ONE (MAX_WR - 1)

#define TU_RDMA_MEMORY_REGIONS 1 //We use memory regions, 0 we allocate space for  void *rdma_local_region

#define MESSAGE_SEGMENT_SIZE 1024
typedef enum kr_reply_status { KR_REP_ARRIVED = 430, KR_REP_PENDING = 345 } kr_reply_status;

#define TU_CONTROL_MSG_BY_RDMA 0 //1 the control messages such as TU_RDMA_MRED_MSG will be sent by RDMA messages,
// 0  These control messages will be sent by SEND/RECEIVE messages

#define TU_RDMA_MSG_DONE 0
#define TU_RDMA_REGULAR_MSG_READY 3
#define TU_RDMA_DISCONNECT_MSG_READY 5
#define TU_RDMA_REGULAR_MSG 17
#define CONNECTION_PROPERTIES                                                                                          \
	9 /*not a message type used for recv flags in messages to indicate that either a
																 DISCONNECT, CHANGE_CONNECTION_PROPERTIES_REQUEST,CHANGE_CONNECTION_PROPERTIES_REPLY follows*/
#define TU_RDMA_RECEIVED_MREND_MSG 9 //To inform the spinning thread to go to the beginning
#define TU_RDMA_ACK_RECEIVED_MREND_REPLY_MSG                                                                           \
	12 //To inform the client we received the MREND_REPLY_MSG and can be released

#define TU_RDMA_RECEIVED_ACK_MSG                                                                                       \
	14 //To inform the last message we have received. It should be usually sent from the client to the server.
#define TU_RDMA_DISCONNECT_MSG 99

#define SERVER_MODE 149
#define CLIENT_MODE 189
extern int LIBRARY_MODE; /*two modes for the communication rdma library SERVER and CLIENT*/

#define MAX_IDLE_ITERATIONS 1000000

uint64_t *spinning_threads_core_ids;
uint64_t *worker_threads_core_ids;

uint32_t num_of_spinning_threads;
uint32_t num_of_worker_threads;
uint32_t WORKER_THREADS_PER_SPINNING_THREAD;

/*worker status list*/
#define IDLE_SPINNING 0
#define IDLE_SLEEPING 1
#define BUSY 2
#define WORKER_NOT_RUNNING 3

typedef struct spinning_thread_parameters {
	struct channel_rdma *channel;
	int spinning_thread_id;
} spinning_thread_parameters;

typedef enum connection_type {
	CLIENT_TO_SERVER_CONNECTION = 100,
	SERVER_TO_CLIENT_CONNECTION,
	MASTER_TO_REPLICA_DATA_CONNECTION,
	MASTER_TO_REPLICA_CONTROL_CONNECTION,
	REPLICA_TO_MASTER_DATA_CONNECTION,
	REPLICA_TO_MASTER_CONTROL_CONNECTION,
	H3_CLIENT_TO_SERVER_CONNECTION,
	H3_SERVER_TO_CLIENT_CONNECTION
} connection_type;

typedef enum work_task_status {
	/*put related*/
	APPEND_START = 10000,
	CHECK_FOR_REPLICA_FLUSH_SEGMENT_ACK,
	ALLOCATE_NEW_LOG_BUFFER_WITH_REPLICA,
	PERFORM_SPILL_CHECK,
	WAIT_FOR_SPILL_START,
	APPEND_COMPLETE,
	/*allocation of reply msg related*/
	ALLOCATION_START,
	CHECK_FOR_RESET_BUFFER_ACK,
	CHECK_FOR_PENDING_REQUESTS_TO_COMPLETE,
	ALLOCATION_SUCCESS,
	/*get related*/
	GET_START,
	GET_COMPLETE,
	/*TEST RELATED*/
	TEST_START,
	TEST_COMPLETE,
	/*reset buffer related*/
	RESET_BUFFER_START,
	RESET_BUFFER_COMPLETE,
	/*FLUSH segment related*/
	FLUSH_SEGMENT_START,
	FLUSH_SEGMENT_COMPLETE,
	/*overall_status*/
	TASK_START,
	TASK_COMPLETED,
	/*spill staff codes used for master's spill worker*/
	SEND_SPILL_INIT,
	WAIT_FOR_SPILL_INIT_REPLY,
	INIT_SPILL_BUFFER_SCANNER,
	SPILL_BUFFER_REQ,
	CLOSE_SPILL_BUFFER,
	SEND_SPILL_COMPLETE,
	WAIT_FOR_SPILL_COMPLETE_REPLY,
	SPILL_FINISHED,
	/*codes used for spill status at the replicas*/
	SPILL_INIT_START,
	SPILL_INIT_END,
	SPILL_COMPLETE_START,
	SPILL_COMPLETE_END,
	SPILL_BUFFER_START
} work_task_status;

typedef enum region_status { REGION_OK = 1000, REGION_IN_TRANSITION } region_status;

typedef enum connection_status {
	CONNECTION_OK,
	CONNECTION_RESETTING,
	STOPPED_BY_THE_SERVER,
	WAIT_FOR_SERVER_ACK
} connection_status;

typedef enum rdma_allocation_type {
	BLOCKING = 233,
	ASYNCHRONOUS,
} rdma_allocation_type;

typedef struct work_task {
	struct channel_rdma *channel;
	struct connection_rdma *conn;
	tu_data_message *msg;
	void *region; /*sorry, circular dependency was created so I patched it quickly*/
	void *notification_addr;
	tu_data_message *reply_msg;
	tu_data_message *flush_segment_request;
	/*used for two puproses (keeping state)
	 * 1. For get it keeps the get result if the  server cannot allocate immediately memory to respond to the client.
	 * This save CPU cycles at the server  because it voids entering kreon each time a stall happens.
	 * 2. For puts it keeps the result of a spill task descriptor
	 */
	void *intermediate_buffer;
	int sockfd; /*from accept() for building connections*/
	int thread_id;
	work_task_status kreon_operation_status;
	work_task_status allocation_status;
	work_task_status overall_status;
} work_task;

typedef struct worker_thread {
	work_task job_buffers[UTILS_QUEUE_CAPACITY];
	work_task high_priority_job_buffers[UTILS_QUEUE_CAPACITY];
	/*queue for empty work_task buffers*/
	utils_queue_s empty_job_buffers_queue;
	utils_queue_s empty_high_priority_job_buffers_queue;

	/* queues for normal priority, high priority*/
	utils_queue_s work_queue;
	utils_queue_s high_priority_queue;

	sem_t sem;
	pthread_t thread;
	pthread_spinlock_t work_queue_lock;
	struct channel_rdma *channel;
	uint64_t status;
	struct worker_group *my_group;
	int32_t worker_id;
} worker_thread;

typedef struct worker_group {
	int next_server_worker_to_submit_job;
	int next_client_worker_to_submit_job;
	worker_thread *group;
} worker_group;

void _send_reset_buffer_ack(struct connection_rdma *conn);
void _zero_rendezvous_locations(tu_data_message *msg);
void _update_rendezvous_location(struct connection_rdma *conn, int message_size);

typedef void (*on_connection_created)(void *vconn);

#if TU_CONNECTION_RC_CONTROL
// To control the pending messages, a be able to: 1) re-sent in case something is missing, 2) compute the RTT
struct rdma_sent_queue {
	struct tu_data_message *message; // Message sent
	struct timespec sent_time; // Time in which the message was sent
	struct timespec recv_time; // Time the reply was received.
	int recv_flag; // 1 : The reply message has been received, 0: message sent, but reply not received
	uint64_t ns_rtt;
	int resent;
	int64_t id_msg;
};

#define TU_SIZE_MSG_QUEUE MRQ_MAX_ELEMENTS //512 //4096 //1024
#define TU_BITS_SIZE_MSG_QUEUE 15 //9 //12 //10
#define TU_MASK_SIZE_MSG_QUEUE (MASK(TU_BITS_SIZE_MSG_QUEUE))

#define TU_MSG_FREE 0
#define TU_MSG_SENT 1
#define TU_MSG_RECV 2
#define TU_MSG_RECV_RECV 3

#endif

struct polling_msg {
#if SPINNING_NO_LIST
	void *mem_tail;
	uint64_t tail;
#endif
	uint64_t pos;
	void *mem;
	uint32_t real_pos;
	void *real_mem;
};

struct sr_message {
	enum { MSG_MREND,
	       MSG_RECEIVED_MREND,
	       MSG_ACK,
	       MSG_RECEIVED_ACK,
	       //MSG_ID_CONN,
	       //MSG_REQ
	} type;
	int32_t nsec;
	int64_t id_msg;
	uint32_t pos;
	uint32_t nele;
	uint32_t message_written;
};

struct channel_rdma {
	struct ibv_context *context;
	struct ibv_pd *pd;
	struct ibv_comp_channel *comp_channel; //it will be shared by all the connections created.
	int sockfd;
	memory_region_pool *dynamic_pool;
	memory_region_pool *static_pool;

	/*List of connections open*/
	//SIMPLE_CONCURRENT_LIST * conn_list;
	uint32_t nconn; // Num connections openned
	uint32_t nused; // Num connections used

	pthread_t cmthread; // Thread in charge of the socket for receiving the RDMA remote features (LID, GID, rkey, addr, etc.)
	pthread_t cq_poller_thread; //Thread in charge of the comp_channel //completion channel

#if (SPINNING_THREAD && SPINNING_PER_CHANNEL)
	int spinning_num_th; //Number of spinning threads. Client and server can have a different number
	sem_t sem_spinning[SPINNING_NUM_TH]; //Thread spinning will be waiting here until first connection is added

	pthread_t spinning_thread[SPINNING_NUM_TH]; /* gesalous new staff, spining threads */
	worker_group *spinning_thread_group
		[SPINNING_NUM_TH]; /*gesalous new staff, references to worker threads per spinning thread*/

	//struct klist_head spin_list[SPINNING_NUM_TH];	// List of connections open
	SIMPLE_CONCURRENT_LIST *spin_list[SPINNING_NUM_TH];
	SIMPLE_CONCURRENT_LIST *idle_conn_list[SPINNING_NUM_TH];
	pthread_mutex_t spin_list_conn_lock[SPINNING_NUM_TH]; /*protectes the per spinnign thread connection list*/

	int spin_num[SPINNING_NUM_TH]; // Number of connections open
	long long n_req[SPINNING_NUM_TH]; // Number of connections open
	int spinning_th; // For the id of the threads
	int spinning_conn; // For the conections to figure out which spinning thread should be joined
	pthread_mutex_t spin_th_lock; // Lock for the spin_th
	pthread_mutex_t spin_conn_lock; // Lock for the spin_conn
#endif
	on_connection_created connection_created; //Callback function used for created a thread at
};

struct channel_sock {
	struct channel_rdma *channel;
	int connfd;
};

struct pingpong_dest {
	int lid;
	int qpn;
	int psn;
	union ibv_gid gid;
	int gid_index;
};

typedef struct connection_rdma {
	/*new feature circular_buffer, only clients use it*/
	circular_buffer *send_circular_buf;
	circular_buffer *recv_circular_buf;
	char *control_location;
	char *reset_point;
	uint32_t control_location_length;
	volatile connection_type type;
	/*To add to the list of connections open that handles the channel*/

	SIMPLE_CONCURRENT_LIST *list;
#ifdef CONNECTION_BUFFER_WITH_MUTEX_LOCK
	pthread_mutex_t buffer_lock;
#else
	pthread_spinlock_t buffer_lock;
#endif

	sem_t congestion_control; /*used for congestion control during send rdma operation*/
	volatile uint64_t sleeping_workers;
	volatile uint64_t offset;
	volatile uint64_t pending_received_messages;
	volatile uint64_t pending_sent_messages;
	uint64_t idle_iterations; /*handled only by the spinning thread, shows how many times
														 this connection was idle. After a threashold it will be downgraded to
														 IDLE connection list of the channel*/
	volatile uint64_t FLUSH_SEGMENT_requests_sent;
	volatile uint64_t FLUSH_SEGMENT_acks_received;

	uint32_t priority;
	/*to which worker this connection has been assigned to*/
	uint32_t worker_id;
	/*</gesalous>*/
	void *channel;

	struct rdma_cm_id *rdma_cm_id;
	// FIXME qp, ctx, pd, cq, cq_recv, comp_channel deprecated by rdma_cm_id
	struct ibv_qp *qp;
	struct ibv_context *ctx; //= channel->context
	struct ibv_pd *pd; //= channel->pd
	struct ibv_cq *cq;
	struct ibv_cq *cq_recv;
	struct ibv_comp_channel *comp_channel;
	// struct ibv_mr *ibv_mr_rdma_local;	//This are for sending RDMA messages. Its memory is rmda_local_region
	// struct ibv_mr *ibv_mr_rdma_remote;	//This are for sending RDMA messages. Its memory is rmda_local_region
	struct ibv_mr *peer_mr; // Info of the remote peer: addr y rkey, needed for sending the RRMA messages

	uint32_t connected;
	uint32_t disconnecting;

	/*<gesalous>*/
	volatile void *rendezvous;
	volatile connection_status status; /*normal or resetting?*/
	memory_region *rdma_memory_regions;
	memory_region *next_rdma_memory_regions;
	struct ibv_mr *next_peer_mr;

	struct ibv_mr *recv_mr; //This are for sending regular messages through the RDMA connection.
	struct ibv_mr *send_mr;
	int server; //1 is the server, 0 is not
	int sockfd;
	struct pingpong_dest *my_dest;
	struct pingpong_dest *rem_dest;
	int index;

	//struct polling_msg re_msg[MRQ_N_SECTIONS];

	SIMPLE_CONCURRENT_LIST *responsible_spin_list;
	int32_t responsible_spinning_thread_id;
	/* *
	 * used by the spinning thread to identify cases where a rendezvous may be out of
	 * rdma memory, so that it will wait in for a RESET_BUFFER message
	 * */
	uint32_t remaining_bytes_in_remote_rdma_region;
	pthread_mutex_t spinning_lock; // Lock for the conn_list
#if RD_SEMAPHORE
	sem_t sem_recv; //leave it for now, remove it later
#endif
	//PILAR: Do we need?
	int idconn;

	sem_t sem_disconnect; // To coordinate the reception of messages
	pthread_mutex_t signaled_lock; // Lock for the  send path
	pthread_mutex_t polling_lock; // Lock for the conn_list
	int n_polling;

	//int64_t last_id_msg_seen[MRQ_N_SECTIONS]; //Last value of id_msg seen in a MSG received. Update by spinning thread
	//int64_t last_id_msg_seen_tail[MRQ_N_SECTIONS]; //Last value of id_msg seen in a MSG received. Update by received thread
	//int nlast[MRQ_N_SECTIONS];

	sem_t sem_check_state; // To coordinate the reception of messages
	int recover_state; //To indicate that the QP has been recover. 1 from ERROR to RTR state. 0, no recovery has been done
#if !TU_CONTROL_MSG_BY_RDMA
	//int64_t id_msg_mr_end[MRQ_N_SECTIONS]; //ID of the message that will be the last received
	//int64_t id_msg_mr_end_tail[MRQ_N_SECTIONS]; //ID of the message that will be the last received
	//uint32_t pos_mr_end[MRQ_N_SECTIONS];
	//uint32_t nele_mr_end[MRQ_N_SECTIONS];
	//int mr_end_received; // 0 not received, set to 2 when MR_END is received , it will be decremented by update_pos_spinning and update_tail_spinning
	//pthread_mutex_t id_msg_mr_end_lock[MRQ_N_SECTIONS];
#endif
} connection_rdma;

static inline void Set_OnConnection_Create_Function(struct channel_rdma *channel, on_connection_created function)
{
	channel->connection_created = function;
}

void crdma_put_message_from_MR(struct connection_rdma *conn, void **mr);
void *crdma_receive_rdma_message(struct connection_rdma *conn, void **payload);

void crdma_init_generic_create_channel(struct channel_rdma *channel);
void crdma_init_client_connection(struct connection_rdma *conn, const char *host, const char *port,
				  struct channel_rdma *channel);
void crdma_init_server_channel(struct channel_rdma *channel);
struct channel_rdma *crdma_server_create_channel(void);
struct channel_rdma *crdma_client_create_channel(void);
uint32_t crdma_free_RDMA_conn(struct connection_rdma **ardma_conn);

struct connection_rdma *crdma_client_create_connection_list_hosts(struct channel_rdma *channel, char **hosts,
								  int num_hosts, connection_type type);

void crdma_init_client_connection_list_hosts(struct connection_rdma *conn, char **hosts, const int num_hosts,
					     struct channel_rdma *channel, connection_type type);

void crdma_put_message_from_remote_MR(struct connection_rdma *conn, uint64_t ooffset, int32_t N);
int64_t crdma_get_message_consecutive_from_remote_MR(struct connection_rdma *conn, uint32_t length);

tu_data_message *allocate_rdma_message(connection_rdma *conn, int message_payload_size, int message_type);
void init_rdma_message(connection_rdma *conn, tu_data_message *msg, uint32_t message_type, uint32_t message_size,
		       uint32_t message_payload_size, uint32_t padding);
tu_data_message *__allocate_rdma_message(connection_rdma *conn, int message_payload_size, int message_type,
					 int rdma_allocation_type, int priority, work_task *task);

int send_rdma_message(connection_rdma *conn, tu_data_message *msg);
void async_send_rdma_message(connection_rdma *conn, tu_data_message *msg, void (*callback_function)(void *args),
			     void *args);
tu_data_message *get_message_reply(connection_rdma *conn, tu_data_message *msg);
void free_rdma_local_message(connection_rdma *conn);
void free_rdma_received_message(connection_rdma *conn, tu_data_message *msg);

void client_free_rpc_pair(connection_rdma *conn, tu_data_message *msg);
/*replica specific functions*/
int rdma_kv_entry_to_replica(connection_rdma *conn, tu_data_message *data_message, uint64_t segment_log_offset,
			     void *source, uint32_t kv_length, uint32_t client_buffer_key);
int wake_up_replica_to_flush_segment(connection_rdma *conn, tu_data_message *msg, int wait);

static inline uint32_t cdrma_IsDisconnecting_Connection(struct connection_rdma *conn)
{
	return conn->disconnecting;
}

static inline uint32_t cdrma_IsConnected_Connection(struct connection_rdma *conn)
{
	return conn->connected;
}

struct connection_rdma *crdma_client_create_connection(struct channel_rdma *channel);
void close_and_free_RDMA_connection(struct channel_rdma *channel, struct connection_rdma *conn);
void crdma_generic_free_connection(struct connection_rdma **ardma_conn);
uint32_t crdma_get_channel_connection_number(struct channel_rdma *channel);

/*gesalous, signature here implementation in tu_rdma.c*/
void disconnect_and_close_connection(connection_rdma *conn);


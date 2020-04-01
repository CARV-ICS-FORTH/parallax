#include "rdma.h"
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#define _GNU_SOURCE /* See feature_test_macros(7) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <immintrin.h>

#include "get_clock.h"
#include "../kreon_server/messages.h"
#include "../kreon_server/globals.h"
#include "../kreon_server/server_regions.h"
#include "../utilities/simple_concurrent_list.h"
#include "../utilities/spin_loop.h"
#include "../utilities/circular_buffer.h"
#include "../build/external-deps/log/src/log.h"

#define CTX_HANDSHAKE_SUCCESS 0
#define CTX_HANDSHAKE_FAILURE 1
#define MAX_COMPLETION_ENTRIES 32

#define WORKER_THREAD_PRIORITIES_NUM 4
#define WORKER_THREAD_HIGH_PRIORITY_TASKS_PER_TURN 1
#define WORKER_THREAD_NORMAL_PRIORITY_TASKS_PER_TURN 1

int LIBRARY_MODE = SERVER_MODE; /*two modes for the communication rdma library SERVER and CLIENT*/
int assign_job_to_worker(struct channel_rdma *channel, struct connection_rdma *conn, msg_header *msg,
			 int spinning_thread_id, int sockfd);
uint64_t wake_up_workers_operations = 0;

/*gesalous, helper functions for spinning thread*/
uint32_t _wait_for_payload_arrival(msg_header *hdr);
void _update_connection_score(int spinning_list_type, connection_rdma *conn);
/*one port for waiitng client connections, another for waiting connections from other servers*/

void crdma_server_create_connection_inuse(struct connection_rdma *connection, struct channel_rdma *channel,
					  connection_type type);

void crdma_add_connection_channel(struct channel_rdma *channel, struct connection_rdma *conn);

void check_pending_ack_message(struct connection_rdma *conn);
void force_send_ack(struct connection_rdma *conn);

void rdma_thread_events_ctx(void *args);

static void *poll_cq(void *arg);
void on_completion_server(struct ibv_wc *wc, struct connection_rdma *conn);

/*gesalous new stuff*/
static int __send_rdma_message(connection_rdma *conn, msg_header *msg);
static msg_header *_client_allocate_rdma_message(connection_rdma *conn, int message_payload_size, int message_type);

#if SPINNING_THREAD
#if SPINNING_PER_CHANNEL
static void *client_spinning_thread_kernel(void *arg);
static void *server_spinning_thread_kernel(void *arg);
#endif
#endif
void *worker_thread_kernel(void *args);

static void _wait_for_reset_buffer_ack(connection_rdma *conn)
{
	int dummy = 1;
	size_t payload_end = conn->rdma_memory_regions->memory_region_length - MESSAGE_SEGMENT_SIZE;
	/*wait for RESET_BUFER_ACK*/
	msg_header *reset_buffer_ack =
		(msg_header *)((uint64_t)conn->rdma_memory_regions->remote_memory_buffer + payload_end);
	while (reset_buffer_ack->receive != RESET_BUFFER_ACK) {
		++dummy;
		if (dummy % 1000000000 == 0) {
			DPRINT("\t Waiting for RESET_BUFFER_ACK\n");
			dummy = 1;
		}
	}
	reset_buffer_ack->receive = 0;
}

void _send_reset_buffer_ack(connection_rdma *conn)
{
	struct ibv_send_wr *bad_wr_header;
	struct ibv_send_wr wr_header;
	struct ibv_sge sge_header;
	msg_header *msg;
	size_t payload_end = conn->rdma_memory_regions->memory_region_length - MESSAGE_SEGMENT_SIZE;
	//while(conn->pending_received_messages != 0){
	//	if(++a%1000000000 == 0){
	//		DPRINT("\tWaiting for processing of received messages to send RESET_BUFFER_ACK pending messages %llu\n",(LLU)conn->pending_received_messages);
	//	}
	//}

	msg = (msg_header *)((uint64_t)conn->rdma_memory_regions->local_memory_buffer + payload_end);
	memset(msg, 0, sizeof(msg_header));
	msg->type = RESET_BUFFER_ACK;
	msg->receive = RESET_BUFFER_ACK;
	msg->pay_len = 0;
	msg->padding_and_tail = 0;

	memset(&wr_header, 0, sizeof(wr_header));
	memset(&sge_header, 0, sizeof(sge_header));
	wr_header.wr_id = (uint64_t)msg;
	wr_header.opcode = IBV_WR_RDMA_WRITE;
	wr_header.sg_list = &sge_header;
	wr_header.num_sge = 1;
	wr_header.send_flags = IBV_SEND_SIGNALED;
	wr_header.wr.rdma.remote_addr = ((uint64_t)conn->peer_mr->addr + payload_end);
	wr_header.wr.rdma.rkey = conn->peer_mr->rkey;

	sge_header.addr = (uint64_t)msg;
	sge_header.length = TU_HEADER_SIZE;
	sge_header.lkey = conn->rdma_memory_regions->local_memory_region->lkey;

	if (ibv_post_send(conn->qp, &wr_header, &bad_wr_header) != 0) {
		DPRINT("FATAL RDMA write failed, reason follows-->\n");
		perror("Reason: ");
		DPRINT("payload length of failed wr is %d and local addr %llu msg len %d\n",
		       bad_wr_header->sg_list->length, (LLU)bad_wr_header->sg_list->addr, msg->pay_len);
		raise(SIGINT);
		exit(EXIT_FAILURE);
	}
	return;
}

void init_rdma_message(connection_rdma *conn, msg_header *msg, uint32_t message_type, uint32_t message_size,
		       uint32_t message_payload_size, uint32_t padding)
{
	if (message_payload_size > 0) {
		msg->pay_len = message_payload_size;
		msg->padding_and_tail = padding + TU_TAIL_SIZE;
		msg->data = (void *)((uint64_t)msg + TU_HEADER_SIZE);
		msg->next = msg->data;
		/*set the tail to the proper value*/
		*(uint32_t *)(((uint64_t)msg + TU_HEADER_SIZE + msg->pay_len + msg->padding_and_tail) -
			      sizeof(uint32_t)) = TU_RDMA_REGULAR_MSG;
	} else {
		msg->pay_len = 0;
		msg->padding_and_tail = 0;
		msg->data = NULL;
		msg->next = NULL;
	}

	msg->type = message_type;
	msg->receive = TU_RDMA_REGULAR_MSG;
	msg->local_offset = (uint64_t)msg - (uint64_t)conn->send_circular_buf->memory_region;
	msg->remote_offset = (uint64_t)msg - (uint64_t)conn->send_circular_buf->memory_region;

	//DPRINT("\t Sending to remote offset %llu\n", msg->remote_offset);
	msg->ack_arrived = KR_REP_PENDING;
	msg->callback_function = NULL;
	msg->request_message_local_addr = NULL;
	//conn->offset += message_size;
}

msg_header *allocate_rdma_message(connection_rdma *conn, int message_payload_size, int message_type)
{
	msg_header *msg;
#ifdef CONNECTION_BUFFER_WITH_MUTEX_LOCK
	pthread_mutex_lock(&conn->buffer_lock);
#else
	pthread_spin_lock(&conn->buffer_lock);
#endif

	msg = _client_allocate_rdma_message(conn, message_payload_size, message_type);

#ifdef CONNECTION_BUFFER_WITH_MUTEX_LOCK
	pthread_mutex_unlock(&conn->buffer_lock);
#else
	pthread_spin_unlock(&conn->buffer_lock);
#endif
	return msg;
}

static msg_header *_client_allocate_rdma_message(connection_rdma *conn, int message_payload_size, int message_type)
{
	uint32_t message_size;
	uint32_t padding = 0;
	uint32_t ack_arrived;
	uint32_t receive_type;
	uint32_t i = 0;
	char *addr = NULL;
	msg_header *msg;
	circular_buffer *c_buf;
	circular_buffer_op_status stat;
	uint8_t reset_rendezvous = 0;
	switch (message_type) {
	case PUT_REQUEST:
	case TU_GET_QUERY:
	case MULTI_GET_REQUEST:
		c_buf = conn->send_circular_buf;
		ack_arrived = KR_REP_PENDING;
		receive_type = TU_RDMA_REGULAR_MSG;
		reset_rendezvous = 1;
		break;
	case PUT_REPLY:
	case TU_GET_REPLY:
	case MULTI_GET_REPLY:
		c_buf = conn->recv_circular_buf;
		ack_arrived = KR_REP_DONT_CARE;
		receive_type = TU_RDMA_REGULAR_MSG;
		break;
	case DISCONNECT:
		c_buf = conn->send_circular_buf;
		ack_arrived = KR_REP_DONT_CARE;
		receive_type = CONNECTION_PROPERTIES;
		break;
	case I_AM_CLIENT:
	case SERVER_I_AM_READY:
	case RESET_RENDEZVOUS:
		c_buf = conn->send_circular_buf;
		ack_arrived = KR_REP_DONT_CARE;
		receive_type = TU_RDMA_REGULAR_MSG;
		receive_type = CONNECTION_PROPERTIES;
		break;
	default:
		log_fatal("unknown message type %d", message_type);
		exit(EXIT_FAILURE);
	}

	if (message_payload_size > 0) {
		message_size = TU_HEADER_SIZE + message_payload_size + TU_TAIL_SIZE;
		if (message_size % MESSAGE_SEGMENT_SIZE != 0) {
			/*need to pad */
			padding += (MESSAGE_SEGMENT_SIZE - (message_size % MESSAGE_SEGMENT_SIZE));
			message_size += padding;
			assert(message_size % MESSAGE_SEGMENT_SIZE == 0);
		}
	} else {
		message_size = MESSAGE_SEGMENT_SIZE;
		padding = 0;
	}

	addr = NULL;

	while (1) {
		stat = allocate_space_from_circular_buffer(c_buf, message_size, &addr);
		switch (stat) {
		case ALLOCATION_IS_SUCCESSFULL:
		case BITMAP_RESET:
			goto init_message;

		case NOT_ENOUGH_SPACE_AT_THE_END:
			if (reset_rendezvous) {
				/*inform remote side that to reset the rendezvous*/
				if (allocate_space_from_circular_buffer(c_buf, MESSAGE_SEGMENT_SIZE,
									&addr) != ALLOCATION_IS_SUCCESSFULL) {
					log_fatal("cannot send reset rendezvous");
					exit(EXIT_FAILURE);
				}
				msg = (msg_header *)addr;
				msg->pay_len = 0;
				msg->padding_and_tail = 0;
				msg->data = NULL;
				msg->next = NULL;

				msg->receive = RESET_RENDEZVOUS;
				msg->type = RESET_RENDEZVOUS;
				msg->local_offset = addr - c_buf->memory_region;
				msg->remote_offset = addr - c_buf->memory_region;
				//log_info("Sending to remote offset %llu\n", msg->remote_offset);
				msg->ack_arrived = ack_arrived;
				msg->callback_function = NULL;
				msg->request_message_local_addr = NULL;
				msg->reply = NULL;
				msg->reply_length = 0;
				__send_rdma_message(conn, msg);
				//log_info("CLIENT: Informing server to reset the rendezvous");
			}
			addr = NULL;
			reset_circular_buffer(c_buf);

			break;
		case SPACE_NOT_READY_YET:
			if (++i % 10000000 == 0) {
				for (i = 0; i < c_buf->bitmap_size; i++) {
					if (c_buf->bitmap[i] != (int)0xFFFFFFFF) {
						// if (++k % 100000000 == 0)
						// DPRINT("bitmap[%d] = 0x%x waiting for reply at %llu\n",i,conn->send_circular_buf->bitmap[i], (char*)conn->rendezvous - conn->rdma_memory_regions->remote_memory_buffer);
					}
				}
			}
			break;
		}
	}

init_message:
	msg = (msg_header *)addr;
	if (message_payload_size > 0) {
		msg->pay_len = message_payload_size;
		msg->padding_and_tail = padding + TU_TAIL_SIZE;
		msg->data = (void *)((uint64_t)msg + TU_HEADER_SIZE);
		msg->next = msg->data;
		/*set the tail to the proper value*/
		*(uint32_t *)(((uint64_t)msg + TU_HEADER_SIZE + msg->pay_len + msg->padding_and_tail) -
			      sizeof(uint32_t)) = TU_RDMA_REGULAR_MSG;
	} else {
		msg->pay_len = 0;
		msg->padding_and_tail = 0;
		msg->data = NULL;
		msg->next = NULL;
	}

	msg->type = message_type;
	msg->receive = receive_type;
	msg->local_offset = (uint64_t)msg - (uint64_t)c_buf->memory_region;
	msg->remote_offset = (uint64_t)msg - (uint64_t)c_buf->memory_region;


	//log_info("\t Sending to remote offset %llu\n", msg->remote_offset);
	msg->ack_arrived = ack_arrived;
	msg->callback_function = NULL;
	msg->request_message_local_addr = NULL;

	return msg;
}

/* *
 * This function allocates space from local mrq to prepare and send a message to
 * the remote size of connection conn. Messages are allocated in a contiguous
 * fashion. When the end of the memory region is reached the protocol sends a
 * message to the remote side of the connection to reset the buffer. Message
 * sizes are rounded to MEMORY_REGION_SEGMENT_SIZE so message  headers are
 * aligned to MEMORY_REGION_SEGMENT_SIZE. When a message is freed we zero the
 * HEADERS of each memory region segment to avoid the case where a newly
 * allocated message has its header's recv flag to a random value rather than 0.
 *
 * priority argument is dead please remover it*/
msg_header *__allocate_rdma_message(connection_rdma *conn, int message_payload_size, int message_type,
				    int allocation_type, int priority, work_task *task)
{
	msg_header *msg;
	msg_header *reset_buffer_ack;
	uint64_t local_offset = 0;
	uint32_t message_size;
	uint32_t padding = 0;
	int receive;
	int tries;
	size_t payload_end;

	assert(allocation_type == ASYNCHRONOUS && task != NULL);

	switch (message_type) {
	case PUT_REQUEST:
	case PUT_REPLY:
	case MULTI_PUT:
	case TU_GET_QUERY:
	case TU_GET_REPLY:
	case TU_UPDATE:
	case TU_UPDATE_REPLY:
	case TEST_REQUEST:
	case TEST_REQUEST_FETCH_PAYLOAD:
	case TEST_REPLY:
	case TEST_REPLY_FETCH_PAYLOAD:
	case SCAN_REQUEST:
	case SCAN_REPLY:
		receive = TU_RDMA_REGULAR_MSG;
		break;
	case DISCONNECT:
	case CHANGE_CONNECTION_PROPERTIES_REQUEST:
	case CHANGE_CONNECTION_PROPERTIES_REPLY:
		receive = CONNECTION_PROPERTIES;
		break;

	case SPILL_INIT:
	case SPILL_BUFFER_REQUEST:
	case SPILL_COMPLETE:
	case SPILL_INIT_ACK:
	case SPILL_COMPLETE_ACK:
	case FLUSH_SEGMENT:
	case FLUSH_SEGMENT_ACK:
	case SYNC_SEGMENT:
	case SYNC_SEGMENT_ACK:
		receive = TU_RDMA_REGULAR_MSG;
		break;

	case RESET_BUFFER:
		receive = RESET_BUFFER;
		break;
	case RESET_BUFFER_ACK:
		receive = RESET_BUFFER_ACK;
		break;

	default:
		DPRINT("FATAL unknown message type %d\n", message_type);
		raise(SIGINT);
		exit(EXIT_FAILURE);
	}

	/*check here for returning fast (optimization)*/
	if (task->allocation_status == ALLOCATION_START && conn->status == CONNECTION_RESETTING) {
		//DPRINT("Backoff at allocate for message %d\n",message_type);
		return NULL;
	}

#ifdef CONNECTION_BUFFER_WITH_MUTEX_LOCK
	pthread_mutex_lock(&conn->buffer_lock);
#else
	pthread_spin_lock(&conn->buffer_lock);
#endif

	if (task->allocation_status == ALLOCATION_START && conn->status == CONNECTION_RESETTING) {
	//DPRINT("Backoff at allocate for message %d\n",message_type);

#ifdef CONNECTION_BUFFER_WITH_MUTEX_LOCK
		pthread_mutex_unlock(&conn->buffer_lock);
#else
		pthread_spin_unlock(&conn->buffer_lock);
#endif

		return NULL;
	}
	/**
	 * new logic to avoid two messages per requests:
	 * all messages must be multiples of MESSAGE_SEGMENT_SIZE
	 **/

	if (message_payload_size > 0) {
	message_size = TU_HEADER_SIZE + message_payload_size + TU_TAIL_SIZE;
		if (message_size % MESSAGE_SEGMENT_SIZE != 0) {
			/*need to pad */
			padding += (MESSAGE_SEGMENT_SIZE - (message_size % MESSAGE_SEGMENT_SIZE));
			message_size += padding;
			assert(message_size % MESSAGE_SEGMENT_SIZE == 0);
		}
	} else {
		message_size = MESSAGE_SEGMENT_SIZE;
		padding = 0;
	}

	local_offset = conn->offset;

	/*fsm logic follows*/
	while (1) {
		switch (task->allocation_status) {
		case ALLOCATION_START:

			local_offset = conn->offset;
			if ((local_offset + message_size) >
			    conn->rdma_memory_regions->memory_region_length - MESSAGE_SEGMENT_SIZE) {
				//DPRINT("Time to reset buffer\n");
				conn->status = CONNECTION_RESETTING;
				/*reset protocol follows, first wait every pending message to finish*/
				local_offset = conn->offset;
				/*fits exactly one header*/
				msg = (msg_header *)((uint64_t)conn->rdma_memory_regions->local_memory_buffer +
						     local_offset);

				msg->pay_len = 0;
				msg->padding_and_tail = 0;
				msg->callback_function = NULL;
				msg->local_offset = local_offset;
				msg->remote_offset = local_offset;
				msg->type = RESET_BUFFER;

				msg->receive = RESET_BUFFER;
				msg->pay_len = 0;
				msg->callback_function = NULL;
				msg->callback_function_args = NULL;
				__send_rdma_message(conn, msg);

				task->allocation_status = CHECK_FOR_RESET_BUFFER_ACK;
				break;
			} else {
				goto allocate;
			}

		case CHECK_FOR_RESET_BUFFER_ACK:
			//DPRINT("CHECK_FOR_RESET_BUFFER_ACK\n");
			/*wait for RESET_BUFER_ACK*/
			tries = 0;
			payload_end = conn->rdma_memory_regions->memory_region_length - MESSAGE_SEGMENT_SIZE;
			reset_buffer_ack =
				(msg_header *)((uint64_t)conn->rdma_memory_regions->remote_memory_buffer + payload_end);
			while (reset_buffer_ack->receive != RESET_BUFFER_ACK) {
				++tries;
				if (tries >= NUM_OF_TRIES) {
#ifdef CONNECTION_BUFFER_WITH_MUTEX_LOCK
					pthread_mutex_unlock(&conn->buffer_lock);
#else
					pthread_spin_unlock(&conn->buffer_lock);
#endif
					return NULL;
				}
			}
			reset_buffer_ack->receive = 0;
			task->allocation_status = CHECK_FOR_PENDING_REQUESTS_TO_COMPLETE;
			break;
		case CHECK_FOR_PENDING_REQUESTS_TO_COMPLETE:
			//DPRINT("CHECK_FOR_PENDING_REQUESTS_TO_COMPLETE\n");
			tries = 0;
			while (conn->pending_sent_messages != 0) {
				local_offset = conn->offset;
				if (++tries >= NUM_OF_TRIES) {
#ifdef CONNECTION_BUFFER_WITH_MUTEX_LOCK
					pthread_mutex_unlock(&conn->buffer_lock);
#else
					pthread_spin_unlock(&conn->buffer_lock);
#endif
					return NULL;
				}
			}
			assert(conn->pending_sent_messages == 0);
			conn->offset = 0;
			task->allocation_status = ALLOCATION_START;
			conn->status = CONNECTION_OK;
			break;

		case APPEND_START:
		case CHECK_FOR_REPLICA_FLUSH_SEGMENT_ACK:
		case ALLOCATE_NEW_LOG_BUFFER_WITH_REPLICA:
		case APPEND_COMPLETE:
		case ALLOCATION_SUCCESS:
			assert(0);
		default:
			DPRINT("FATAL entered faulty state\n");
			assert(0);
			break;
		}
	}

allocate:
	msg = (msg_header *)((uint64_t)conn->rdma_memory_regions->local_memory_buffer + local_offset);

	if (message_payload_size > 0) {
		msg->pay_len = message_payload_size;
		msg->padding_and_tail = padding + TU_TAIL_SIZE;
		msg->data = (void *)((uint64_t)msg + TU_HEADER_SIZE);
		msg->next = msg->data;
		/*set the tail to the proper value*/
		*(uint32_t *)(((uint64_t)msg + TU_HEADER_SIZE + msg->pay_len + msg->padding_and_tail) -
			      sizeof(uint32_t)) = TU_RDMA_REGULAR_MSG;
	} else {
		msg->pay_len = 0;
		msg->padding_and_tail = 0;
		msg->data = NULL;
		msg->next = NULL;
	}

	msg->type = message_type;
	msg->receive = receive;
	msg->local_offset = local_offset; /*local offset taken from mr*/
	msg->remote_offset = local_offset;
	//DPRINT("\t Sending to remote offset %llu\n", msg->remote_offset);
	msg->ack_arrived = KR_REP_PENDING;
	msg->callback_function = NULL;
	msg->request_message_local_addr = NULL;

	conn->offset += message_size;

	__sync_fetch_and_add(&conn->pending_sent_messages, 1);
	assert(conn->offset % MESSAGE_SEGMENT_SIZE == 0);
#ifdef CONNECTION_BUFFER_WITH_MUTEX_LOCK
	pthread_mutex_unlock(&conn->buffer_lock);
#else
	pthread_spin_unlock(&conn->buffer_lock);
#endif
	if (allocation_type == ASYNCHRONOUS) {
		task->allocation_status = ALLOCATION_SUCCESS;
	}
	return msg;
}

int send_rdma_message_busy_wait(connection_rdma *conn, msg_header *msg)
{
	msg->callback_function = NULL;
	msg->callback_function_args = NULL;
	msg->receive_options = BUSY_WAIT;
	return __send_rdma_message(conn, msg);
}

int send_rdma_message(connection_rdma *conn, msg_header *msg)
{
	sem_init(&msg->sem, 0, 0);
	msg->callback_function = NULL;
	msg->callback_function_args = NULL;
	msg->receive_options = SYNC_REQUEST;
	return __send_rdma_message(conn, msg);
}

void async_send_rdma_message(connection_rdma *conn, msg_header *msg, void (*callback_function)(void *args), void *args)
{
	msg->callback_function = callback_function;
	msg->callback_function_args = args;
	msg->receive_options = ASYNC_REQUEST;
	__send_rdma_message(conn, msg);
}

static int __send_rdma_message(connection_rdma *conn, msg_header *msg)
{
	int i = 0;
	while (conn->pending_sent_messages >= MAX_WR) {
		__sync_fetch_and_add(&conn->sleeping_workers, 1);
		DPRINT("Congestion in the write path throttling... %llu\n", (LLU)conn->pending_sent_messages);
		sem_wait(&conn->congestion_control);
		__sync_fetch_and_sub(&conn->sleeping_workers, 1);
		if (++i % 100000 == 0) {
			DPRINT("Congestion in the write path throttling... %llu\n", (LLU)conn->pending_sent_messages);
		}
	}

	// FIXME Is the while loop needed at all?
	size_t msg_len;
	if (msg->pay_len) // FIXME This if shouldn't be necessary
		msg_len = TU_HEADER_SIZE + msg->pay_len + msg->padding_and_tail;
	else
		msg_len = TU_HEADER_SIZE;

	int ret;
	int tries = 0;
	while (tries < 100) {
		ret = rdma_post_write(conn->rdma_cm_id, msg, msg, msg_len,
				      conn->rdma_memory_regions->local_memory_region, IBV_SEND_SIGNALED,
				      ((uint64_t)conn->peer_mr->addr + msg->remote_offset), conn->peer_mr->rkey);
		if (!ret) {
			break;
		}
		++tries;
		if (++tries == 100) {
			ERRPRINT("rdma_post_write: %s\n", strerror(errno));
			raise(SIGINT);
			exit(EXIT_FAILURE);
		}
	}

	return KREON_SUCCESS;
}

msg_header *get_message_reply(connection_rdma *conn, msg_header *msg)
{
	if (!msg->reply_message)
		sem_wait(&msg->sem);

	assert(msg->reply_message);
	return msg->reply_message;
}

void client_free_rpc_pair(connection_rdma *conn, msg_header *reply)
{
	uint32_t size;
	msg_header *request;
	request = (msg_header *)reply->request_message_local_addr;
	assert(request->reply_length != 0);
	free_space_from_circular_buffer(conn->recv_circular_buf, (char *)reply, request->reply_length);

	if (request->pay_len == 0) {
		size = MESSAGE_SEGMENT_SIZE;
	} else {
		size = TU_HEADER_SIZE + request->pay_len + request->padding_and_tail;
		assert(size % MESSAGE_SEGMENT_SIZE == 0);
	}
	free_space_from_circular_buffer(conn->send_circular_buf, (char *)request, size);
	return;
}

void free_rdma_received_message(connection_rdma *conn, msg_header *msg)
{
	assert(conn->pending_received_messages > 0);
	_zero_rendezvous_locations(msg);
	__sync_fetch_and_sub(&conn->pending_received_messages, 1);
}

void free_rdma_local_message(connection_rdma *conn)
{
	assert(conn->pending_sent_messages > 0);
	__sync_fetch_and_sub(&conn->pending_sent_messages, 1);
	if (conn->sleeping_workers > 0) {
		sem_post(&conn->congestion_control);
	}
	return;
}

/*gesalous, disconnect*/
void disconnect_and_close_connection(connection_rdma *conn)
{
	msg_header *disconnect_request = allocate_rdma_message(conn, 0, DISCONNECT);
	send_rdma_message(conn, disconnect_request);
	DPRINT("Successfully sent disconnect message, bye bye Caution! Missing deallocation of resources follows...\n");
	close_and_free_RDMA_connection(conn->channel, conn);
	DPRINT("Success\n");
}

/*Caution not a thread safe function, Kreon handles this*/
int rdma_kv_entry_to_replica(connection_rdma *conn, msg_header *data_message, uint64_t segment_log_offset, void *source,
			     uint32_t kv_length, uint32_t client_buffer_key)
{
	struct ibv_send_wr wr;
	struct ibv_sge sge;
	struct ibv_send_wr *bad_wr = NULL;
	int ret = 0;
	assert(data_message != NULL);

	/*prepare the RDMA*/
	memset(&wr, 0, sizeof(wr));
	memset(&sge, 0, sizeof(sge));
	wr.wr_id = 0;
	wr.opcode = IBV_WR_RDMA_WRITE;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.wr.rdma.rkey = conn->peer_mr->rkey;

	wr.send_flags = IBV_SEND_SIGNALED;
	wr.wr.rdma.remote_addr = (uint64_t)(conn->peer_mr->addr + (uint64_t)data_message->local_offset +
					    TU_HEADER_SIZE + 4096 + segment_log_offset);
	sge.addr = (uint64_t)source;
	sge.length = kv_length;
	sge.lkey = client_buffer_key;
	ret = ibv_post_send(conn->qp, &wr, &bad_wr);

	if (ret != 0) {
		DPRINT("ERROR rdma failed reason follows--->\n");
		perror("Reason: \n");
		exit(EXIT_FAILURE);
	}
	return KREON_SUCCESS;
}

int wake_up_replica_to_flush_segment(connection_rdma *conn, msg_header *msg, int wait)
{
	struct ibv_send_wr wr_segment_metadata;
	struct ibv_sge sge_segment_metadata;
	struct ibv_send_wr *bad_wr_segment_metadata = NULL;
	struct ibv_send_wr wr_header;
	struct ibv_sge sge_header;
	struct ibv_send_wr *bad_wr_header = NULL;
	int32_t length;
	/*sent metadata of segment via an RDMA write operation*/
	msg->callback_function = NULL;
	msg->callback_function_args = NULL;
	sem_init(&msg->sem, 0, 0);

	/*calculate length of metadata*/
	length = (4 * sizeof(uint64_t)) + sizeof(uint32_t) + *(uint32_t *)(msg->data + (4 * sizeof(uint64_t)));
	memset(&wr_segment_metadata, 0, sizeof(wr_segment_metadata));
	memset(&sge_segment_metadata, 0, sizeof(sge_segment_metadata));
	wr_segment_metadata.wr_id = 0;
	wr_segment_metadata.opcode = IBV_WR_RDMA_WRITE;
	wr_segment_metadata.sg_list = &sge_segment_metadata;
	wr_segment_metadata.num_sge = 1;
	wr_segment_metadata.send_flags = IBV_SEND_SIGNALED;
	wr_segment_metadata.wr.rdma.remote_addr = (uintptr_t)(conn->peer_mr->addr + msg->local_offset + TU_HEADER_SIZE);
	wr_segment_metadata.wr.rdma.rkey = conn->peer_mr->rkey;

	sge_segment_metadata.addr = (uint64_t)((uintptr_t)conn->rdma_memory_regions->local_memory_buffer +
					       msg->local_offset + TU_HEADER_SIZE);
	sge_segment_metadata.length = length;
	sge_segment_metadata.lkey = conn->rdma_memory_regions->local_memory_region->lkey;
	//DPRINT("Metadata of LOG Buffer length %d from offset %llu to offset %llu\n",length,(LLU)msg->local_offset+TU_HEADER_SIZE, (LLU)msg->local_offset+TU_HEADER_SIZE);
	if (ibv_post_send(conn->qp, &wr_segment_metadata, &bad_wr_segment_metadata) != 0) {
		DPRINT("FATAL RDMA write failed, reason follows-->\n");
		perror("Reason: ");
		DPRINT("payload length of failed wr is %d and local addr %llu msg len %d\n",
		       bad_wr_segment_metadata->sg_list->length, (LLU)bad_wr_segment_metadata->sg_list->addr,
		       msg->pay_len);
		raise(SIGINT);
		exit(EXIT_FAILURE);
	}

	/*then sent header*/
	memset(&wr_header, 0, sizeof(wr_header));
	memset(&sge_header, 0, sizeof(sge_header));
	wr_header.wr_id = (uint64_t)msg;
	wr_header.opcode = IBV_WR_RDMA_WRITE;
	wr_header.sg_list = &sge_header;
	wr_header.num_sge = 1;
	wr_header.send_flags = IBV_SEND_SIGNALED;
	wr_header.wr.rdma.remote_addr = ((uint64_t)conn->peer_mr->addr + msg->remote_offset);
	wr_header.wr.rdma.rkey = conn->peer_mr->rkey;

	sge_header.addr = (uint64_t)((uintptr_t)conn->rdma_memory_regions->local_memory_buffer + msg->local_offset);
	sge_header.length = TU_HEADER_SIZE;
	sge_header.lkey = conn->rdma_memory_regions->local_memory_region->lkey;

	msg->reply_message = NULL;
	if (wait == WAIT_REPLICA_TO_COMMIT) {
		msg->request_message_local_addr = msg;
	} else {
		msg->request_message_local_addr = NULL;
	}

	//DPRINT("HEADER  of LOG Buffer length %d from offset %llu to offset %llu\n",TU_HEADER_SIZE,(LLU)msg->local_offset, (LLU)msg->remote_offset);
	if (ibv_post_send(conn->qp, &wr_header, &bad_wr_header) != 0) {
		DPRINT("FATAL RDMA write failed, reason follows-->\n");
		perror("Reason: ");
		DPRINT("payload length of failed wr is %d and local addr %llu msg len %d\n",
		       bad_wr_header->sg_list->length, (LLU)bad_wr_header->sg_list->addr, msg->pay_len);
		raise(SIGINT);
		exit(EXIT_FAILURE);
	}
	return KREON_SUCCESS;
}

struct ibv_device *ctx_find_dev(const char *ib_devname)
{
	int num_of_device;
	struct ibv_device **dev_list;
	struct ibv_device *ib_dev = NULL;

	dev_list = ibv_get_device_list(&num_of_device);

	if (num_of_device <= 0) {
		fprintf(stderr, " Did not detect devices \n");
		fprintf(stderr, " If device exists, check if driver is up\n");
		return NULL;
	}

	if (!ib_devname) {
		ib_dev = dev_list[0];
		if (!ib_dev) {
			fprintf(stderr, "No IB devices found\n");
			exit(1);
		}
	} else {
		for (; (ib_dev = *dev_list); ++dev_list) {
			if (!strcmp(ibv_get_device_name(ib_dev), ib_devname))
				break;
		}
		if (!ib_dev)
			fprintf(stderr, "IB device %s not found\n", ib_devname);
	}
	return ib_dev;
}

struct ibv_context *open_ibv_device(char *devname)
{
	struct ibv_context **dev_list = rdma_get_devices(NULL);
	assert(dev_list[0]);
	return dev_list[0];
}

/*
 * gesalous new staff
 * each spin thread has a group of worker threads. Spin threads detects that a
 * request has arrived and it assigns the task to one of its worker threads
 * */
void *worker_thread_kernel(void *args)
{
	int num_of_processed_requests_per_priority[WORKER_THREAD_PRIORITIES_NUM];

	utils_queue_s pending_tasks_queue;
	utils_queue_s pending_high_priority_tasks_queue;
	//struct timeval t0,t1;
	work_task *job = NULL;
	worker_thread *worker_descriptor;
	//uint64_t time_elapsed;

	int turn = 0;

	pthread_setname_np(pthread_self(), "worker_thread");
	worker_descriptor = (worker_thread *)args;
	worker_descriptor->status = BUSY;

	utils_queue_init(&pending_high_priority_tasks_queue);
	utils_queue_init(&pending_tasks_queue);

	memset(num_of_processed_requests_per_priority, 0x00, sizeof(int) * WORKER_THREAD_PRIORITIES_NUM);
	turn = 0;

	while (1) {
		//gettimeofday(&t0, 0);

		while (job == NULL) {
			if (turn == 0) {
				/*pending tasks*/
				if (++num_of_processed_requests_per_priority[turn] >=
				    WORKER_THREAD_HIGH_PRIORITY_TASKS_PER_TURN) {
					num_of_processed_requests_per_priority[turn] = 0;
					++turn;
				}
				job = utils_queue_pop(&pending_high_priority_tasks_queue);
				if (job != NULL) {
					//DPRINT("Pending High priority job of type %d\n",job->msg->type);
					break;
				}
			}

			else if (turn == 1) {
				/*high priority tasks*/
				if (++num_of_processed_requests_per_priority[turn] >=
				    WORKER_THREAD_HIGH_PRIORITY_TASKS_PER_TURN) {
					num_of_processed_requests_per_priority[turn] = 0;
					++turn;
				}
				job = utils_queue_pop(&worker_descriptor->high_priority_queue);
				if (job != NULL) {
					//DPRINT("High priority job of type %d\n",job->msg->type);
					break;
				}
			} else if (turn == 2) {
				if (++num_of_processed_requests_per_priority[turn] >=
				    WORKER_THREAD_NORMAL_PRIORITY_TASKS_PER_TURN) {
					num_of_processed_requests_per_priority[turn] = 0;
					++turn;
				}
				job = utils_queue_pop(&pending_tasks_queue);
				if (job != NULL) {
					//DPRINT("Pending Low priority job of type %d\n",job->msg->type);
					break;
				}
			}

			else if (turn == 3) {
				if (++num_of_processed_requests_per_priority[turn] >=
				    WORKER_THREAD_NORMAL_PRIORITY_TASKS_PER_TURN) {
					num_of_processed_requests_per_priority[turn] = 0;
					turn = 0;
				}
				job = utils_queue_pop(&worker_descriptor->work_queue);
				if (job != NULL) {
					//DPRINT("Low priority job of type %d\n",job->msg->type);
					break;
				}
			}
			//gettimeofday(&t1, 0);
			//time_elapsed = ((t1.tv_sec-t0.tv_sec)*1000000) + (t1.tv_usec-t0.tv_usec);
			if (0 /*time_elapsed >= MAX_USEC_BEFORE_SLEEPING*/) {
				/*go to sleep, no job*/

				pthread_spin_lock(&worker_descriptor->work_queue_lock);
				/*double check*/

				job = utils_queue_pop(&pending_high_priority_tasks_queue);

				if (job == NULL) {
					job = utils_queue_pop(&worker_descriptor->high_priority_queue);
				}

				if (job == NULL) {
					job = utils_queue_pop(&pending_tasks_queue);
				}

				if (job == NULL) {
					job = utils_queue_pop(&worker_descriptor->work_queue);
				}

				if (job == NULL) {
					worker_descriptor->status = IDLE_SLEEPING;
					pthread_spin_unlock(&worker_descriptor->work_queue_lock);
					DPRINT("Sleeping...\n");
					sem_wait(&worker_descriptor->sem);
					DPRINT("Woke up\n");
					worker_descriptor->status = BUSY;
					continue;
				} else {
					pthread_spin_unlock(&worker_descriptor->work_queue_lock);
					continue;
				}
			}
		}

		//DPRINT("SERVER worker: new regular msg, reply will be send at %llu  length %d type %d\n",
		//		(LLU)job->msg->reply,job->msg->reply_length, job->msg->type);
		/*process task*/
		job->channel->connection_created((void *)job);
		if (job->overall_status == TASK_COMPLETED) {
			if (job->msg->type != RESET_BUFFER && job->msg->type != SPILL_BUFFER_REQUEST) {
				//free_rdma_received_message(job->conn, job->msg);
				_zero_rendezvous_locations(job->msg);
				__send_rdma_message(job->conn, job->reply_msg);
			}

			/*return the buffer to its appropriate pool*/
			if (job->msg->type == FLUSH_SEGMENT_AND_RESET || job->msg->type == FLUSH_SEGMENT ||
			    job->msg->type == SPILL_INIT || job->msg->type == SPILL_COMPLETE ||
			    job->msg->type == SPILL_BUFFER_REQUEST) {
				assert(utils_queue_push(&worker_descriptor->empty_high_priority_job_buffers_queue,
							job) != NULL);
			} else {
				assert(utils_queue_push(&worker_descriptor->empty_job_buffers_queue, job) != NULL);
			}
		}

		else {
			if (job->msg->type == FLUSH_SEGMENT_AND_RESET || job->msg->type == FLUSH_SEGMENT ||
			    job->kreon_operation_status == ALLOCATE_NEW_LOG_BUFFER_WITH_REPLICA ||
			    job->msg->type == SPILL_INIT || job->msg->type == SPILL_COMPLETE ||
			    job->msg->type == SPILL_BUFFER_REQUEST) {
				//DPRINT("High priority Task interrupted allocation status %d\n",job->allocation_status);
				assert(utils_queue_push(&pending_high_priority_tasks_queue, job) != NULL);
			} else {
				//DPRINT("Low priority Task interrupted allocation status %d\n",job->allocation_status);
				assert(utils_queue_push(&pending_tasks_queue, job) != NULL);
			}
		}
		job = NULL;
	}
	DPRINT("worker thread exited ended per connection thread\n");
	return NULL;
}

/**
 * Pick a connection to steal memory from. For the first implementation, a lower priority connection will be picked
 * randomly.
 * @param connections_list A pointer to the connections list to search in for the candidate connection
 * @return A pointer to a candidate connection from where to steal memory
 */
connection_rdma *find_memory_steal_candidate(SIMPLE_CONCURRENT_LIST *connections_list)
{
	SIMPLE_CONCURRENT_LIST_NODE *node = NULL;
	//SIMPLE_CONCURRENT_LIST_NODE*	node_max = NULL;
	connection_rdma *ret = NULL;
	//int i;
	// pthread_mutex_lock(&sch->list_lock);
	node = connections_list->first;
	ret = NULL;
	while (node) {
		if (!((connection_rdma *)node->data)->next_rdma_memory_regions &&
		    (ret == NULL || ret->rdma_memory_regions->memory_region_length <
					    ((connection_rdma *)node->data)->rdma_memory_regions->memory_region_length))
			ret = (connection_rdma *)node->data;
		node = node->next;
	}

	if (ret) {
		assert(!ret->next_rdma_memory_regions);
	} else {
		DPRINT("No candidate connection found!\n");
	}
	DPRINT("id = %d, ret = %p, ret->mrsize = %zu\n", ret->idconn, ret,
	       ret->rdma_memory_regions->memory_region_length);
	// pthread_mutex_unlock(&sch->list_lock);
	return ret;
}

//TODO [mvard] Change ethernet_server_connect to use a free port number and add
//it to zookeeper so the clients can get that info

sem_t memory_steal_sem; // used to block the socket thread if there's no available memory to allocate to an incoming connection
volatile memory_region *backup_region = NULL;

static void __stop_client(connection_rdma *conn);

/*This is the main entry poinf of the kreonR server. Here it waits for new
 * incoming connections*/
static void *socket_thread(void *args)
{
	struct channel_rdma *channel;
	connection_rdma *conn;

	pthread_setname_np(pthread_self(), "connection_listener");

	channel = (struct channel_rdma *)args;
	log_info("Starting listener for new connections thread at port %d", globals_get_RDMA_connection_port());
	sem_init(&memory_steal_sem, 0, 1); // sem_wait when using backup_region, spinning_thread will sem_post
	/*backup_region = mrpool_allocate_memory_region(channel->static_pool);*/
	/*assert(backup_region);*/

	struct ibv_qp_init_attr qp_init_attr;
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.cap.max_send_wr = qp_init_attr.cap.max_recv_wr = MAX_WR;
	qp_init_attr.cap.max_send_sge = qp_init_attr.cap.max_recv_sge = 1;
	qp_init_attr.cap.max_inline_data = 16;
	qp_init_attr.sq_sig_all = 1;
	qp_init_attr.qp_type = IBV_QPT_RC;

	struct rdma_addrinfo hints, *res;
	char port[16];
	sprintf(port, "%d", globals_get_RDMA_connection_port());

	memset(&hints, 0, sizeof hints);
	hints.ai_flags = RAI_PASSIVE; // Passive side, awaiting incoming connections
	hints.ai_port_space = RDMA_PS_TCP; // Supports Reliable Connections
	int ret = rdma_getaddrinfo(NULL, port, &hints, &res);
	if (ret) {
		log_fatal("rdma_getaddrinfo: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct rdma_cm_id *rdma_cm_id;
	ret = rdma_create_ep(&rdma_cm_id, res, NULL, NULL);
	if (ret) {
		log_fatal("rdma_create_ep: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Listen for incoming connections on available RDMA devices
	ret = rdma_listen(rdma_cm_id, 0); // called with backlog = 0
	if (ret) {
		log_fatal("rdma_listen: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	while (1) {
		/* Block until a new connection request arrives
		 * Because pd and qp_init_attr were set in rdma_create_ep, a ap is
		 * automatically created for the new rdma_cm_id
		 */
		struct rdma_cm_id *request_id, *new_conn_id;
		ret = rdma_get_request(rdma_cm_id, &request_id);
		if (ret) {
			log_fatal("rdma_get_request: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		new_conn_id = request_id->event->id;
		conn = (connection_rdma *)malloc(sizeof(connection_rdma));
		qp_init_attr.send_cq = qp_init_attr.recv_cq =
			ibv_create_cq(channel->context, MAX_WR, (void *)conn, channel->comp_channel, 0);
		ibv_req_notify_cq(qp_init_attr.send_cq, 0);
		assert(qp_init_attr.send_cq);

		ret = rdma_create_qp(new_conn_id, NULL, &qp_init_attr);
		if (ret) {
			log_fatal("rdma_create_qp: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}

		connection_type incoming_connection_type = -1;
		struct ibv_mr *recv_mr = rdma_reg_msgs(new_conn_id, &incoming_connection_type, sizeof(connection_type));
		ret = rdma_post_recv(new_conn_id, &incoming_connection_type, &incoming_connection_type,
				     sizeof(connection_type), recv_mr);
		if (ret) {
			log_fatal("rdma_post_recv: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}

		// Accept incomming connection TODO look into rdma_conn_param a bit more
		ret = rdma_accept(new_conn_id, NULL);
		if (ret) {
			log_fatal("rdma_accept: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}

		while (incoming_connection_type == -1)
			; // Wait for message to arrive
		rdma_dereg_mr(recv_mr);

		if (incoming_connection_type == CLIENT_TO_SERVER_CONNECTION) {
			incoming_connection_type = SERVER_TO_CLIENT_CONNECTION;
			log_info("We have a new client connection request\n");
		} else if (incoming_connection_type == MASTER_TO_REPLICA_DATA_CONNECTION) {
			incoming_connection_type = REPLICA_TO_MASTER_DATA_CONNECTION;
			DPRINT("We have a new replica connection request\n");
		} else {
			DPRINT("FATAL bad connection type");
			exit(EXIT_FAILURE);
		}
		/*
		 * Important note to future self: klist.h used for keeping
		 * channels and connections used by spinning thread is NOT thread
		 * safe. Patch: all operations adding new connections and
		 * removing connections take place from the context of the
		 * spinning thread
		 */

		/* I assume global state for the connections is already kept in the system?*/
		/*!!! follow this path to add this connection to the appropriate connection list !!!*/
		crdma_server_create_connection_inuse(
			conn, channel, incoming_connection_type); // TODO not sure if it's needed with rdma_cm
		conn->rdma_cm_id = new_conn_id;

		switch (conn->type) {
		case SERVER_TO_CLIENT_CONNECTION:
			conn->rdma_memory_regions = mrpool_allocate_memory_region(channel->dynamic_pool, new_conn_id);
			break;
		case MASTER_TO_REPLICA_DATA_CONNECTION:
			assert(0);
			break;
		case MASTER_TO_REPLICA_CONTROL_CONNECTION:
			assert(0);
			break;
		default:
			log_fatal("bad connection type %d", conn->type);
			exit(EXIT_FAILURE);
		}
#if 0
		memory_region * mr, *other_half, *halved_mr;
		connection_rdma *candidate = NULL;
		if (conn->type == SERVER_TO_CLIENT_CONNECTION && !conn->rdma_memory_regions) { /*{{{*/
			// Run out of memory, need to steal from a connection
			// FIXME Need to figure out how destroying these half memory regions will work since
			// calling free on the second half buffer will fail. I'm not sure ibv_dereg_mr will
			// work either
			DPRINT("Run out of memory regions!\n");
			candidate = find_memory_steal_candidate(channel->spin_list[0]);
			assert(candidate);

			sem_wait(&memory_steal_sem);
			// changed from NULL to something != NULL
			assert(backup_region);
			mr = (struct memory_region *)backup_region;
			backup_region = NULL;

			halved_mr = (memory_region *)malloc(sizeof(memory_region));
			halved_mr->mrpool = mr->mrpool;
			halved_mr->memory_region_length = mr->memory_region_length / 2;

			halved_mr->local_memory_region = (struct ibv_mr *)malloc(sizeof(struct ibv_mr));
			memcpy(halved_mr->local_memory_region, mr->local_memory_region, sizeof(memory_region));
			halved_mr->local_memory_region->length = halved_mr->memory_region_length;
			halved_mr->local_memory_buffer = mr->local_memory_buffer;
			assert(halved_mr->local_memory_buffer == halved_mr->local_memory_region->addr);

			halved_mr->remote_memory_region = (struct ibv_mr *)malloc(sizeof(struct ibv_mr));
			memcpy(halved_mr->remote_memory_region, mr->remote_memory_region, sizeof(memory_region));
			halved_mr->remote_memory_region->length = halved_mr->memory_region_length;
			halved_mr->remote_memory_buffer = mr->remote_memory_buffer;
			assert(halved_mr->remote_memory_buffer == halved_mr->remote_memory_region->addr);

			candidate->next_rdma_memory_regions = halved_mr;

			other_half = (memory_region *)malloc(sizeof(memory_region));
			other_half->mrpool = mr->mrpool;
			other_half->memory_region_length = mr->memory_region_length / 2;

			other_half->local_memory_region = (struct ibv_mr *)malloc(sizeof(struct ibv_mr));
			memcpy(other_half->local_memory_region, mr->local_memory_region, sizeof(memory_region));
			other_half->local_memory_region->addr += other_half->memory_region_length;
			other_half->local_memory_region->length = other_half->memory_region_length;
			other_half->local_memory_buffer = mr->local_memory_buffer + other_half->memory_region_length;
			assert(other_half->local_memory_buffer == other_half->local_memory_region->addr);

			other_half->remote_memory_region = (struct ibv_mr *)malloc(sizeof(struct ibv_mr));
			memcpy(other_half->remote_memory_region, mr->remote_memory_region, sizeof(memory_region));
			other_half->remote_memory_region->addr += other_half->memory_region_length;
			other_half->remote_memory_region->length = other_half->memory_region_length;
			other_half->remote_memory_buffer = mr->remote_memory_buffer + other_half->memory_region_length;
			assert(other_half->remote_memory_buffer == other_half->remote_memory_region->addr);
			DPRINT("SERVER: length = %llu\n", (LLU)other_half->memory_region_length);

			conn->rdma_memory_regions = other_half;

			// TODO replace assign_job_to_worker with __stop_client. Add new mr info in the
			// stop client message's payload
			// assign_job_to_worker(candidate->channel, candidate, (msg_header*)577, 0, -1);
			__stop_client(candidate);
			candidate = NULL;
		} /*}}}*/
#endif
		assert(conn->rdma_memory_regions);

		struct ibv_mr *send_mr = rdma_reg_msgs(new_conn_id, conn->rdma_memory_regions->remote_memory_region,
						       sizeof(struct ibv_mr));

		// Receive memory region information
		conn->peer_mr = (struct ibv_mr *)malloc(sizeof(struct ibv_mr));
		memset(conn->peer_mr, 0, sizeof(struct ibv_mr));
		recv_mr = rdma_reg_msgs(new_conn_id, conn->peer_mr, sizeof(struct ibv_mr));
		ret = rdma_post_recv(new_conn_id, NULL, conn->peer_mr, sizeof(struct ibv_mr), recv_mr);
		if (ret) {
			log_fatal("rdma_post_recv: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}

		// Send memory region information
		ret = rdma_post_send(new_conn_id, NULL, conn->rdma_memory_regions->remote_memory_region,
				     sizeof(struct ibv_mr), send_mr, 0);
		if (ret) {
			log_fatal("rdma_post_send: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		while (!conn->peer_mr->rkey)
			; // Wait for message to arrive
		rdma_dereg_mr(send_mr);
		rdma_dereg_mr(recv_mr);

		conn->connected = 1;
		conn->qp = conn->rdma_cm_id->qp;
		conn->rendezvous = conn->rdma_memory_regions->remote_memory_buffer;
		/*zerop all rdma memory*/
		memset(conn->rdma_memory_regions->local_memory_buffer, 0x00,
		       conn->rdma_memory_regions->memory_region_length);

		if (sem_init(&conn->congestion_control, 0, 0) != 0) {
			log_fatal("failed to initialize semaphore reason follows");
			perror("Reason: ");
		}
		conn->sleeping_workers = 0;

		conn->pending_sent_messages = 0;
		conn->pending_received_messages = 0;
		conn->offset = 0;
		conn->worker_id = -1;
#ifdef CONNECTION_BUFFER_WITH_MUTEX_LOCK
		pthread_mutex_init(&conn->buffer_lock, NULL);
#else
		pthread_spin_init(&conn->buffer_lock, PTHREAD_PROCESS_PRIVATE);
#endif
		crdma_add_connection_channel(channel, conn);
		log_info("****** Built new connection successfully  ********");
	}
	return NULL;
}

uint16_t ctx_get_local_lid(struct ibv_context *context, int port, struct ibv_port_attr *attr)
{
	if (ibv_query_port(context, port, attr))
		return 0;
	return attr->lid;
}

static inline int ipv6_addr_v4mapped(const struct in6_addr *a)
{
	return ((a->s6_addr32[0] | a->s6_addr32[1]) | (a->s6_addr32[2] ^ htonl(0x0000ffff))) == 0UL ||
	       /* IPv4 encoded multicast addresses */
	       (a->s6_addr32[0] == htonl(0xff0e0000) &&
		((a->s6_addr32[1] | (a->s6_addr32[2] ^ htonl(0x0000ffff))) == 0UL));
}

void tu_rdma_init_connection(struct connection_rdma *conn)
{
	memset(conn, 0, sizeof(struct connection_rdma));

	conn->server = 0;
	conn->index = 0;

	/*gesalous staff initialization*/
	conn->idle_iterations = 0;
	sem_init(&conn->sem_disconnect, 0, 0);
	conn->FLUSH_SEGMENT_requests_sent = 0;
	conn->FLUSH_SEGMENT_acks_received = 0;
}

void crdma_init_client_connection_list_hosts(connection_rdma *conn, char **hosts, const int num_hosts,
					     struct channel_rdma *channel, connection_type type)
{
	struct ibv_qp_init_attr qp_init_attr;
	msg_header *msg;
	if (!strcmp(hosts[0], "127.0.0.1")) {
		log_warn("Connection with local host?");
		return;
	}

	conn->channel = channel;
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.cap.max_send_wr = qp_init_attr.cap.max_recv_wr = MAX_WR;
	qp_init_attr.cap.max_send_sge = qp_init_attr.cap.max_recv_sge = 1;
	qp_init_attr.cap.max_inline_data = 16;
	qp_init_attr.sq_sig_all = 1;
	qp_init_attr.send_cq = qp_init_attr.recv_cq =
		ibv_create_cq(channel->context, MAX_WR, (void *)conn, channel->comp_channel, 0);
	ibv_req_notify_cq(qp_init_attr.send_cq, 0);
	assert(qp_init_attr.send_cq);
	// to use both in client's and server's initialization
	struct rdma_addrinfo hints, *res;
	char *ip;
	char *port;
	char host_copy[512];
	char *strtok_state;
	strncpy(host_copy, hosts[0], 512);
	memset(&hints, 0, sizeof hints);
	hints.ai_port_space = RDMA_PS_TCP;
	ip = strtok_r(host_copy, ":", &strtok_state);
	port = strtok_r(NULL, ":", &strtok_state);

	log_info("Connecting to %s:%s\n", ip, port);

	int ret = rdma_getaddrinfo(ip, port, &hints, &res);
	if (ret) {
		log_fatal("rdma_getaddrinfo: %s, %s\n", hosts[0], strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct rdma_cm_id *rdma_cm_id;
	// FIXME Need to use channel->pd here instead of NULL
	ret = rdma_create_ep(&rdma_cm_id, res, NULL, &qp_init_attr);
	if (ret) {
		log_fatal("rdma_create_ep: %s", strerror(errno));
		raise(SIGINT);
		exit(EXIT_FAILURE);
	}
	conn->rdma_cm_id = rdma_cm_id;

	// TODO Check the private data functionality of the connection parameters!!!
	struct rdma_conn_param conn_param;
	memset(&conn_param, 0, sizeof(conn_param));
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	conn_param.flow_control = 1;
	conn_param.retry_count = 7;
	conn_param.rnr_retry_count = 7;
	ret = rdma_connect(rdma_cm_id, &conn_param);
	if (ret) {
		log_fatal("rdma_connect: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	conn->peer_mr = (struct ibv_mr *)malloc(sizeof(struct ibv_mr));
	memset(conn->peer_mr, 0, sizeof(struct ibv_mr));
	struct ibv_mr *recv_mr = rdma_reg_msgs(rdma_cm_id, conn->peer_mr, sizeof(struct ibv_mr));
	ret = rdma_post_recv(rdma_cm_id, NULL, conn->peer_mr, sizeof(struct ibv_mr), recv_mr);
	if (ret) {
		log_fatal("rdma_post_recv: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct ibv_mr *send_mr = rdma_reg_msgs(rdma_cm_id, &type, sizeof(type));
	ret = rdma_post_send(rdma_cm_id, NULL, &type, sizeof(type), send_mr, 0);
	if (ret) {
		log_fatal("rdma_post_send: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	switch (type) {
	case MASTER_TO_REPLICA_DATA_CONNECTION:
		DPRINT("Remote side accepted created a new MASTER_TO_REPLICA_CONNECTION\n");
		conn->type = MASTER_TO_REPLICA_DATA_CONNECTION;
		conn->rdma_memory_regions =
			mrpool_get_static_buffer(rdma_cm_id, sizeof(se_rdma_buffer) * SE_REPLICA_NUM_SEGMENTS);
		break;
	case MASTER_TO_REPLICA_CONTROL_CONNECTION:
		assert(0);
	case CLIENT_TO_SERVER_CONNECTION:
		log_info("Remote side accepted created a new CLIENT_TO_SERVER_CONNECTION");
		conn->type = CLIENT_TO_SERVER_CONNECTION;
		conn->rdma_memory_regions = mrpool_allocate_memory_region(channel->dynamic_pool, rdma_cm_id);
		break;
	case REPLICA_TO_MASTER_DATA_CONNECTION:
	case SERVER_TO_CLIENT_CONNECTION:
		log_warn("Should not handle this kind of connection here");
	default:
		log_fatal("BAD connection type\n");
		exit(EXIT_FAILURE);
	}
	conn->remaining_bytes_in_remote_rdma_region = conn->rdma_memory_regions->memory_region_length;
	conn->priority = LOW_PRIORITY; //FIXME I don't think I use this anymore
	conn->rendezvous = conn->rdma_memory_regions->remote_memory_buffer;

	// Receive server's memory region information
	while (conn->peer_mr->rkey == 0)
		; // Wait for message to arrive
	rdma_dereg_mr(send_mr);
	rdma_dereg_mr(recv_mr);

	send_mr = rdma_reg_msgs(rdma_cm_id, conn->rdma_memory_regions->remote_memory_region, sizeof(struct ibv_mr));

	// Send memory region information
	ret = rdma_post_send(rdma_cm_id, NULL, conn->rdma_memory_regions->remote_memory_region, sizeof(struct ibv_mr),
			     send_mr, 0);
	if (ret) {
		log_fatal("rdma_post_send: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	conn->connected = 1;
	/*zero all memory*/
	memset(conn->rdma_memory_regions->local_memory_buffer, 0x00, conn->rdma_memory_regions->memory_region_length);
	if (sem_init(&conn->congestion_control, 0, 0) != 0) {
		log_fatal("failed to initialize semaphore reason follows");
		perror("Reason: ");
	}
	conn->sleeping_workers = 0;
	conn->pending_sent_messages = 0;
	conn->pending_received_messages = 0;
	conn->offset = 0;
	conn->qp = conn->rdma_cm_id->qp;

#ifdef CONNECTION_BUFFER_WITH_MUTEX_LOCK
	pthread_mutex_init(&conn->buffer_lock, NULL);
#else
	pthread_spin_init(&conn->buffer_lock, PTHREAD_PROCESS_PRIVATE);
#endif
	if (LIBRARY_MODE == CLIENT_MODE) {
		log_info("CLIENT: Initializing client circular buffer *** NEW feature ****\n");

		conn->send_circular_buf =
			create_and_init_circular_buffer(conn->rdma_memory_regions->local_memory_buffer,
							conn->peer_mr->length, MESSAGE_SEGMENT_SIZE, SEND_BUFFER);
		conn->recv_circular_buf =
			create_and_init_circular_buffer(conn->rdma_memory_regions->remote_memory_buffer,
							conn->peer_mr->length, MESSAGE_SEGMENT_SIZE, RECEIVE_BUFFER);
		conn->reset_point = 0;
		/*Inform the server that you are a client, patch but now I am in a hurry*/
		DPRINT("CLIENT: Informing server that I am a clienti and about my control location\n");
		msg = allocate_rdma_message(conn, 0, I_AM_CLIENT);
		/*control info*/
		msg->reply =
			(char *)(conn->recv_circular_buf->bitmap_size * BITS_PER_BITMAP_WORD * MESSAGE_SEGMENT_SIZE);
		msg->reply -= MESSAGE_SEGMENT_SIZE;
		msg->reply_length = MESSAGE_SEGMENT_SIZE;
		conn->control_location = (char *)msg->reply;
		conn->control_location_length = msg->reply_length;
		msg->receive = I_AM_CLIENT;

		__send_rdma_message(conn, msg);
	} else {
		conn->send_circular_buf = NULL;
		conn->recv_circular_buf = NULL;
		conn->reset_point = 0;
	}

	crdma_add_connection_channel(channel, conn);
	log_info("Client Connection build successfully");
	log_info("*** Added connection successfully ***");
	__sync_fetch_and_add(&channel->nused, 1);
}

uint32_t crdma_get_channel_connection_number(struct channel_rdma *channel)
{
	int i;
	uint32_t n_conn = 0;
	for (i = 0; i < channel->spinning_num_th; i++) {
		n_conn += channel->spin_num[i];
	}
	if (n_conn > 0) {
		for (i = 0; i < channel->spinning_num_th; i++) {
			DPRINT("n_conn %d %d\n", i, channel->spin_num[i]);
		}
		DPRINT("num_connections %d\n", n_conn);
	}
	return n_conn;
}

void crdma_init_generic_create_channel(struct channel_rdma *channel)
{
	int i, j, k, start;
	cpu_set_t spinning_thread_affinity_mask;
	cpu_set_t worker_threads_affinity_mask;
	int status;

	channel->sockfd = 0;
	channel->context = open_ibv_device(DEFAULT_DEV_IBV);

	channel->comp_channel = ibv_create_comp_channel(channel->context);
	if (channel->comp_channel == 0) {
		DPRINT("Error building context reason follows:\n");
		perror("Reason: \n");
		exit(EXIT_FAILURE);
	}

	channel->pd = ibv_alloc_pd(channel->context);
	channel->nconn = 0;
	channel->nused = 0;
	channel->connection_created = NULL;

	if (LIBRARY_MODE == SERVER_MODE) {
		/*channel->static_pool = mrpool_create(channel->pd, -1, PREALLOCATED,0); // FIXME the max_allocated_memory argument is ignored for now*/
		/*channel->dynamic_pool = mrpool_create(channel->pd, -1, DYNAMIC, REPLICA_BUFFER_SIZE);*/
		channel->dynamic_pool = mrpool_create(channel->pd, -1, DYNAMIC, MEM_REGION_BASE_SIZE);
	} else {
		channel->static_pool = NULL;
		channel->dynamic_pool = mrpool_create(channel->pd, -1, DYNAMIC, MEM_REGION_BASE_SIZE);
	}

#if (SPINNING_THREAD & SPINNING_PER_CHANNEL)
	pthread_mutex_init(&channel->spin_conn_lock, NULL); // Lock for the conn_list
	channel->spinning_th = 0;
	channel->spinning_conn = 0;

	if (LIBRARY_MODE == CLIENT_MODE) {
		DPRINT("\t *** Client: setting spinning threads number to 1 ***\n");
		channel->spinning_num_th = 1;
	} else {
		DPRINT("\t *** Server: setting spinning threads number to %d ***\n", num_of_spinning_threads);
		channel->spinning_num_th = num_of_spinning_threads;
	}

	assert(channel->spinning_num_th <= SPINNING_NUM_TH);

	DPRINT("\t **** Initializing connection lists per spinning thread **** \n");
	for (i = 0; i < channel->spinning_num_th; i++) {
		pthread_mutex_init(&channel->spin_list_conn_lock[i], NULL);
		channel->spin_list[i] = init_simple_concurrent_list();
		channel->idle_conn_list[i] = init_simple_concurrent_list();
	}

	for (i = 0; i < channel->spinning_num_th; i++) {
		//INIT_LIST_HEAD( &channel->spin_list[i] );
		DPRINT("\t initializing spin list per channel\n");
		channel->spin_list[i] = init_simple_concurrent_list();
		channel->spin_num[i] = 0;
		sem_init(&channel->sem_spinning[i], 0, 0);
		spinning_thread_parameters *params =
			(spinning_thread_parameters *)malloc(sizeof(spinning_thread_parameters));
		params->channel = channel;
		params->spinning_thread_id = i;

		if (LIBRARY_MODE == SERVER_MODE) {
			if (pthread_create(&channel->spinning_thread[i], NULL, server_spinning_thread_kernel, params) !=
			    0) {
				free(channel);
				DPRINT("FATAL failed to spawn server spinning thread reason follows\n");
				perror("Reason: \n");
				exit(EXIT_FAILURE);
			}
		} else if (LIBRARY_MODE == CLIENT_MODE) {
			if (globals_spawn_client_spinning_thread() &&
			    pthread_create(&channel->spinning_thread[i], NULL, client_spinning_thread_kernel, params) !=
				    0) {
				free(channel);
				DPRINT("FATAL failed to spawn client spinning thread reason follows\n");
				perror("Reason: \n");
				exit(EXIT_FAILURE);
			}
		} else {
			DPRINT("FATAL unkown library mode\n");
			exit(EXIT_FAILURE);
		}

		if (LIBRARY_MODE == SERVER_MODE) {
			CPU_ZERO(&spinning_thread_affinity_mask);
			CPU_SET(spinning_threads_core_ids[i], &spinning_thread_affinity_mask);
			status = pthread_setaffinity_np(channel->spinning_thread[i], sizeof(cpu_set_t),
							&spinning_thread_affinity_mask);
			if (status != 0) {
				DPRINT("FATAL failed to pin spinning thread\n");
				exit(EXIT_FAILURE);
			}

			DPRINT("pinned successfully spinning thread to core %llu\n", (LLU)spinning_threads_core_ids[i]);

			channel->spinning_thread_group[i] = (worker_group *)malloc(
				sizeof(worker_group) + (WORKER_THREADS_PER_SPINNING_THREAD * sizeof(worker_thread)));
			channel->spinning_thread_group[i]->group =
				(worker_thread *)((uint64_t)channel->spinning_thread_group[i] + sizeof(worker_group));
			channel->spinning_thread_group[i]->next_server_worker_to_submit_job = 0;
			channel->spinning_thread_group[i]->next_client_worker_to_submit_job =
				WORKER_THREADS_PER_SPINNING_THREAD / 2;

			/*now create the worker group thread for the above spinning thread*/
			for (j = 0; j < WORKER_THREADS_PER_SPINNING_THREAD; j++) {
				/*init worker group vars*/

				utils_queue_init(&channel->spinning_thread_group[i]->group[j].empty_job_buffers_queue);
				utils_queue_init(&channel->spinning_thread_group[i]
							  ->group[j]
							  .empty_high_priority_job_buffers_queue);
				utils_queue_init(&channel->spinning_thread_group[i]->group[j].work_queue);
				utils_queue_init(&channel->spinning_thread_group[i]->group[j].high_priority_queue);

				for (k = 0; k < UTILS_QUEUE_CAPACITY; k++) {
					utils_queue_push(
						&channel->spinning_thread_group[i]->group[j].empty_job_buffers_queue,
						&channel->spinning_thread_group[i]->group[j].job_buffers[k]);

					utils_queue_push(&channel->spinning_thread_group[i]
								  ->group[j]
								  .empty_high_priority_job_buffers_queue,
							 &channel->spinning_thread_group[i]
								  ->group[j]
								  .high_priority_job_buffers[k]);
				}
				pthread_spin_init(&channel->spinning_thread_group[i]->group[j].work_queue_lock,
						  PTHREAD_PROCESS_PRIVATE);
				channel->spinning_thread_group[i]->group[j].worker_id = j;
				channel->spinning_thread_group[i]->group[j].my_group =
					channel->spinning_thread_group[i];
				channel->spinning_thread_group[i]->group[j].status = WORKER_NOT_RUNNING;
				sem_init(&channel->spinning_thread_group[i]->group[j].sem, 0, 0);
			}

			CPU_ZERO(&worker_threads_affinity_mask);
			/*set the proper affinity for this worker group*/
			start = i * (num_of_worker_threads / num_of_spinning_threads);
			for (j = start; j < start + (num_of_worker_threads / num_of_spinning_threads); j++) {
				CPU_SET(worker_threads_core_ids[j], &worker_threads_affinity_mask);
				DPRINT("Pinning worker threads (belonging to spinning thread core id %llu) to core id %llu\n",
				       (LLU)spinning_threads_core_ids[i], (LLU)worker_threads_core_ids[j]);
			}

			for (j = 0; j < WORKER_THREADS_PER_SPINNING_THREAD; j++) {
				pthread_create(&channel->spinning_thread_group[i]->group[j].thread, NULL,
					       worker_thread_kernel, &channel->spinning_thread_group[i]->group[j]);
				/*set affinity for this group*/
				status = pthread_setaffinity_np(channel->spinning_thread_group[i]->group[j].thread,
								sizeof(cpu_set_t), &worker_threads_affinity_mask);
				if (status != 0) {
					DPRINT("FATAL failed to pin worker thread group %d\n", i);
					exit(EXIT_FAILURE);
				}
				DPRINT("Pinned worker group thread successfully\n");
			}
		}
		/*Creating the thread in charge of the completion channel*/
		if (pthread_create(&channel->cq_poller_thread, NULL, poll_cq, channel) != 0) {
			DPRINT("Failed to create thread reason follows: \n");
			perror("Reason: \n");
			exit(EXIT_FAILURE);
		}
		if (LIBRARY_MODE == SERVER_MODE) {
			status = pthread_setaffinity_np(channel->cq_poller_thread, sizeof(cpu_set_t),
							&worker_threads_affinity_mask);
			if (status != 0) {
				DPRINT("FATAL failed to pin spinning thread\n");
				exit(EXIT_FAILURE);
			}
			DPRINT("***** opened channel in SERVER MODE -- successfully created %d spinning threads %d workers per spinner set affinity of poller\n",
			       channel->spinning_num_th, WORKER_THREADS_PER_SPINNING_THREAD);
		} else
			DPRINT("***** opened channel in CLIENT MODE-- successfully created %d\n",
			       channel->spinning_num_th);
	}
#endif
}

struct channel_rdma *crdma_client_create_channel(void)
{
	struct channel_rdma *channel;

	channel = malloc(sizeof(*channel));
	if (channel == NULL) {
		perror("ERROR crdma_alloc_init_channel_rdma: memory problem, malloc failed\n");
		exit(-1);
	}
#if (SPINNING_THREAD & SPINNING_PER_CHANNEL)
	if (SPINNING_NUM_TH_CLI > SPINNING_NUM_TH)
		channel->spinning_num_th = SPINNING_NUM_TH;
	else
		channel->spinning_num_th = SPINNING_NUM_TH_CLI;
#endif
	crdma_init_generic_create_channel(channel);

	return channel;
}

struct channel_rdma *crdma_generic_create_channel(void)
{
	struct channel_rdma *channel;

	channel = malloc(sizeof(*channel));
	if (channel == NULL) {
		perror("ERROR crdma_alloc_init_channel_rdma: memory problem, malloc failed\n");
		exit(-1);
	}

	return channel;
}
/******************************************************************************
 *
 ******************************************************************************/
struct channel_rdma *crdma_server_create_channel(void)
{
	struct channel_rdma *channel;

	channel = malloc(sizeof(*channel));
	if (channel == NULL) {
		perror("ERROR crdma_alloc_init_channel_rdma: memory problem, malloc failed\n");
		exit(-1);
	}

	crdma_init_server_channel(channel);
	return channel;
}

void crdma_init_server_channel(struct channel_rdma *channel)
{
#if (SPINNING_THREAD & SPINNING_PER_CHANNEL)
	channel->spinning_num_th = SPINNING_NUM_TH;
#endif
	crdma_init_generic_create_channel(channel);
	if (pthread_create(&channel->cmthread, NULL, socket_thread, channel) != 0) {
		DPRINT("FATAL failed to spawn thread reason follows:\n");
		perror("Reason: \n");
		exit(EXIT_FAILURE);
	}
}

connection_rdma *crdma_client_create_connection_list_hosts(struct channel_rdma *channel, char **hosts, int num_hosts,
							   connection_type type)
{
	connection_rdma *conn;
	/*allocate memory for connection*/
	conn = malloc(sizeof(connection_rdma));
	if (conn == NULL) {
		log_fatal("FATAL ERROR malloc failed\n");
		exit(EXIT_FAILURE);
	}
	tu_rdma_init_connection(conn);
	crdma_init_client_connection_list_hosts(conn, hosts, num_hosts, channel, type);
	return conn;
}

void crdma_server_create_connection_inuse(struct connection_rdma *conn, struct channel_rdma *channel,
					  connection_type type)
{
	/*gesalous, This is the path where it creates the useless memory queues*/
	tu_rdma_init_connection(conn);
	conn->type = type;
	conn->server = 1;
	conn->channel = channel;
}

void crdma_add_connection_channel(struct channel_rdma *channel, struct connection_rdma *conn)
{
	conn->idconn = channel->nconn;
	//conn->local_mrq->idconn =  conn->idconn;
	channel->nconn++;
#if (SPINNING_THREAD & SPINNING_PER_CHANNEL)
	int idx;
	channel->spinning_conn++;
	idx = channel->spinning_conn % channel->spinning_num_th;
	pthread_mutex_lock(&channel->spin_list_conn_lock[idx]);
	/*gesalous new policy*/
	add_last_in_simple_concurrent_list(channel->spin_list[idx], conn);
	conn->responsible_spin_list = channel->spin_list[idx];
	conn->responsible_spinning_thread_id = idx;
	channel->spin_num[idx]++; /*WTF is this? gesalous*/

	pthread_mutex_unlock(&channel->spin_list_conn_lock[idx]);
	sem_post(&channel->sem_spinning[idx]);
	DPRINT(" *** Added connection with ID %d to spinning thread %d of total spinning threads %d ***\n",
	       conn->idconn, idx, channel->spinning_num_th);
#endif
}

#if SPINNING_THREAD
#if SPINNING_PER_CHANNEL
static void ec_sig_handler(int signo)
{
	struct sigaction sa = {};

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = ec_sig_handler;
	sigaction(SIGINT, &sa, 0);
}

int assign_job_to_worker(struct channel_rdma *channel, struct connection_rdma *conn, msg_header *msg,
			 int spinning_thread_id, int sockfd)
{
	work_task *job = NULL;
	//int i = 0;
	//int semaphore_value = 1;
	int worker_id = 0;
	//DPRINT("Spinning thread id %d\n",spinning_thread_id);

	if (conn->worker_id == -1) {
		/*unassigned connection*/
		if (++channel->spinning_thread_group[spinning_thread_id]->next_server_worker_to_submit_job >=
		    WORKER_THREADS_PER_SPINNING_THREAD) {
			channel->spinning_thread_group[spinning_thread_id]->next_server_worker_to_submit_job = 0;
		}
		conn->worker_id = channel->spinning_thread_group[spinning_thread_id]->next_server_worker_to_submit_job;
	}

	if (msg->type == FLUSH_SEGMENT_AND_RESET || msg->type == FLUSH_SEGMENT || msg->type == SPILL_INIT ||
	    msg->type == SPILL_COMPLETE || msg->type == SPILL_BUFFER_REQUEST) {
		/*to ensure FIFO processing , vital for these protocol operations*/

		worker_id = conn->worker_id;
		job = (work_task *)utils_queue_pop(&channel->spinning_thread_group[spinning_thread_id]
							    ->group[worker_id]
							    .empty_high_priority_job_buffers_queue);
		if (job == NULL) {
			//assert(0);
			return KREON_FAILURE;
		}
	} else {
		/*just in case we want to perform different assignment policy based on the priority level*/
		worker_id = conn->worker_id;
		/*DPRINT("Adding job to thread id %d\n",worker_id);*/
		job = (work_task *)utils_queue_pop(
			&channel->spinning_thread_group[spinning_thread_id]->group[worker_id].empty_job_buffers_queue);
		if (job == NULL) {
			//assert(0);
			return KREON_FAILURE;
		}
	}

	memset(job, 0x0, sizeof(work_task));
	job->channel = channel;
	job->conn = conn;
	job->msg = msg;
	job->sockfd = sockfd;

	/*initialization of various fsm*/
	job->thread_id = worker_id;
	job->overall_status = TASK_START;
	job->notification_addr = job->msg->request_message_local_addr;
	job->allocation_status = ALLOCATION_START;
	switch (job->msg->type) {
	case PUT_REQUEST:
	case TU_UPDATE:
		job->kreon_operation_status = APPEND_START;
		break;
	case TU_GET_QUERY:
	case MULTI_GET_REQUEST:
		job->kreon_operation_status = GET_START;
		break;
	case FLUSH_SEGMENT:
	case FLUSH_SEGMENT_AND_RESET:
		job->kreon_operation_status = FLUSH_SEGMENT_START;
		break;

	case RESET_BUFFER:
		job->kreon_operation_status = RESET_BUFFER_START;
		break;

	case SPILL_INIT:
		job->kreon_operation_status = SPILL_INIT_START;
		break;
	case SPILL_BUFFER_REQUEST:
		job->kreon_operation_status = SPILL_BUFFER_START;
		break;
	case SPILL_COMPLETE:
		job->kreon_operation_status = SPILL_COMPLETE_START;
		break;
	case TEST_REQUEST:
	case TEST_REPLY_FETCH_PAYLOAD:
		job->kreon_operation_status = TEST_START;
		break;
	default:
		DPRINT("FATAL unhandled type\n");
		assert(0);
	}

	if (msg->type == FLUSH_SEGMENT_AND_RESET || msg->type == FLUSH_SEGMENT || msg->type == SPILL_INIT ||
	    msg->type == SPILL_COMPLETE || msg->type == SPILL_BUFFER_REQUEST) {
		if (utils_queue_push(
			    &channel->spinning_thread_group[spinning_thread_id]->group[worker_id].high_priority_queue,
			    (void *)job) == NULL) {
			DPRINT("\tFailed to add CONTROL job of type: %d to queue tried worker %d its status is %llu retrying\n",
			       job->msg->type, worker_id,
			       (LLU)channel->spinning_thread_group[spinning_thread_id]->group[worker_id].status);
			utils_queue_push(&channel->spinning_thread_group[spinning_thread_id]
						  ->group[worker_id]
						  .empty_high_priority_job_buffers_queue,
					 (void *)job);
			assert(0);
			return KREON_FAILURE;
		}
	} else {
		/*normal priority*/
		if (utils_queue_push(&channel->spinning_thread_group[spinning_thread_id]->group[worker_id].work_queue,
				     (void *)job) == NULL) {
			DPRINT("\tFailed to add job of type: %d to queue tried worker %d its status is %llu retrying\n",
			       job->msg->type, worker_id,
			       (LLU)channel->spinning_thread_group[spinning_thread_id]->group[worker_id].status);
			utils_queue_push(&channel->spinning_thread_group[spinning_thread_id]
						  ->group[worker_id]
						  .empty_job_buffers_queue,
					 (void *)job);
			//assert(0);
			return KREON_FAILURE;
		}
	}
	pthread_spin_lock(&channel->spinning_thread_group[spinning_thread_id]->group[worker_id].work_queue_lock);
	if (channel->spinning_thread_group[spinning_thread_id]->group[worker_id].status == IDLE_SLEEPING) {
		/*wake him up */
		// DPRINT("Boom\n");
		++wake_up_workers_operations;
		sem_post(&channel->spinning_thread_group[spinning_thread_id]->group[worker_id].sem);
	}
	pthread_spin_unlock(&channel->spinning_thread_group[spinning_thread_id]->group[worker_id].work_queue_lock);
	return KREON_SUCCESS;
}

/************************************************************
 ***************** spinning thread helper functions ********/
void _zero_rendezvous_locations(msg_header *msg)
{
	void *start_memory;
	void *end_memory;
	/*for acks that fit entirely in a header pay_len and padding_and_tail could be 0.
	 * This is ok because we want to ommit sending extra useless bytes. However we need to
	 * zero their virtual tail which the initiator has allocated for safety
	 */

	assert((msg->pay_len == 0 && msg->padding_and_tail == 0) ||
	       (TU_HEADER_SIZE + msg->pay_len + msg->padding_and_tail) % MESSAGE_SEGMENT_SIZE == 0);

	start_memory = (void *)msg;
	if (msg->pay_len > 0 || msg->padding_and_tail > 0) {
		end_memory = (void *)((uint64_t)msg + TU_HEADER_SIZE + msg->pay_len + msg->padding_and_tail);
	} else {
		end_memory = start_memory + MESSAGE_SEGMENT_SIZE;
	}

	while (start_memory < end_memory) {
		((msg_header *)start_memory)->receive = 0;
		//((msg_header *)start_memory)->reply = (void *)0xF40F2;
		//((msg_header *)start_memory)->reply_length = 0;
		*(uint32_t *)((start_memory + MESSAGE_SEGMENT_SIZE) - TU_TAIL_SIZE) = 999;
		start_memory = start_memory + MESSAGE_SEGMENT_SIZE;
	}
}

uint32_t _wait_for_payload_arrival(msg_header *hdr)
{
	int message_size;
	uint32_t *tail;
	if (hdr->pay_len > 0) {
		message_size = TU_HEADER_SIZE + hdr->pay_len + hdr->padding_and_tail;
		tail = (uint32_t *)(((uint64_t)hdr + TU_HEADER_SIZE + hdr->pay_len + hdr->padding_and_tail) -
				    sizeof(uint32_t));
		/*Dont wait for FLUSH_SEGMENT data are already there*/
		if (hdr->type != FLUSH_SEGMENT && hdr->type != FLUSH_SEGMENT_AND_RESET) {
			/*calculate the address of the tail*/
			//blocking style
			//wait_for_value(tail, TU_RDMA_REGULAR_MSG);
			//non-blocking style
			if (*tail != TU_RDMA_REGULAR_MSG) {
				return 0;
			}
		}
		hdr->data = (void *)((uint64_t)hdr + TU_HEADER_SIZE);
		hdr->next = hdr->data;
	} else {
		/*it's only a header*/
		message_size = MESSAGE_SEGMENT_SIZE;
		hdr->data = NULL;
		hdr->next = NULL;
	}
	return message_size;
}

static void __stop_client(connection_rdma *conn)
{
	if (conn->status == STOPPED_BY_THE_SERVER) {
		ERRPRINT("connection is already stopped!\n");
		return;
	}

	conn->status = STOPPED_BY_THE_SERVER;
	DPRINT("SERVER: Sending stop at offset %llu\n", (LLU)conn->control_location);
	msg_header *msg = (msg_header *)((uint64_t)conn->rdma_memory_regions->local_memory_buffer +
					 (uint64_t)conn->control_location);
	msg->pay_len = sizeof(struct ibv_mr);
	msg->padding_and_tail = 0;
	msg->data = (char *)(uint64_t)msg + TU_HEADER_SIZE;
	msg->next = msg->data;
	msg->type = CLIENT_STOP_NOW;
	msg->receive = TU_RDMA_REGULAR_MSG;
	msg->local_offset = (uint64_t)conn->control_location;
	msg->remote_offset = (uint64_t)conn->control_location;
	msg->ack_arrived = KR_REP_PENDING;
	msg->callback_function = NULL;
	msg->request_message_local_addr = NULL;

	struct ibv_mr *new_mr = (struct ibv_mr *)msg->data;
	memset(new_mr, 0x00, sizeof(struct ibv_mr));
	new_mr->addr = conn->next_rdma_memory_regions->remote_memory_region->addr;
	new_mr->length = conn->next_rdma_memory_regions->remote_memory_region->length;
	new_mr->rkey = conn->next_rdma_memory_regions->remote_memory_region->rkey;
	DPRINT("addr = %p, length = %lu KB, rkey = %u\n", new_mr->addr, new_mr->length / 1024, new_mr->rkey);
	__send_rdma_message(conn, msg);
}

void _update_client_rendezvous_location(connection_rdma *conn, int message_size)
{
	if (message_size < MESSAGE_SEGMENT_SIZE) {
		message_size = MESSAGE_SEGMENT_SIZE;
	}
	assert(message_size % MESSAGE_SEGMENT_SIZE == 0);
	if ((uint64_t)conn->rendezvous + message_size >= (uint64_t)conn->rdma_memory_regions->remote_memory_buffer +
								 (conn->peer_mr->length - MESSAGE_SEGMENT_SIZE)) {
		conn->rendezvous = conn->rdma_memory_regions->remote_memory_buffer;
	} else {
		conn->rendezvous = (void *)((uint64_t)conn->rendezvous + message_size);
	}
}

void _update_rendezvous_location(connection_rdma *conn, int message_size)
{
	assert(message_size % MESSAGE_SEGMENT_SIZE == 0);

	if (conn->type == SERVER_TO_CLIENT_CONNECTION) {
		if (message_size < MESSAGE_SEGMENT_SIZE) {
			message_size = MESSAGE_SEGMENT_SIZE;
		}
		if (((uint64_t)conn->rendezvous + message_size) >=
		    ((uint64_t)conn->rdma_memory_regions->remote_memory_buffer +
		     conn->rdma_memory_regions->memory_region_length)) {
			conn->rendezvous = (void *)conn->rdma_memory_regions->remote_memory_buffer;

		} else {
			conn->rendezvous = (void *)((uint64_t)conn->rendezvous + (uint32_t)message_size);
		}
	} else {
		//assert(0);
		if (message_size > 0) {
			if (conn->remaining_bytes_in_remote_rdma_region >= message_size) {
				conn->remaining_bytes_in_remote_rdma_region -= message_size;
				conn->rendezvous = (void *)((uint64_t)conn->rendezvous + message_size);
			} else {
				DPRINT("Just waiting for a RESET_BUFFER\n");
				/*the next message will surely be a RESET_BUFFER*/
				conn->rendezvous =
					conn->rdma_memory_regions->remote_memory_buffer +
					(conn->rdma_memory_regions->memory_region_length - MESSAGE_SEGMENT_SIZE);
			}
		} else {
			/*RESET rendezvous location after a RESET_BUFFER message*/
			conn->remaining_bytes_in_remote_rdma_region = conn->rdma_memory_regions->memory_region_length;
			conn->rendezvous = conn->rdma_memory_regions->remote_memory_buffer;
		}
	}
}

void _update_connection_score(int spinning_list_type, connection_rdma *conn)
{
	if (spinning_list_type == HIGH_PRIORITY)
		conn->idle_iterations = 0;
	else
		++conn->idle_iterations;
}

static void *client_spinning_thread_kernel(void *args)
{
	struct msg_header *hdr;

	SIMPLE_CONCURRENT_LIST_NODE *node;
	SIMPLE_CONCURRENT_LIST_NODE *prev_node;
	SIMPLE_CONCURRENT_LIST_NODE *next_node;

	struct sigaction sa = {};
	struct channel_rdma *channel;
	spinning_thread_parameters *params = (spinning_thread_parameters *)args;
	struct connection_rdma *conn;

	uint32_t message_size;
	volatile uint32_t recv;

	int spinning_thread_id = params->spinning_thread_id;
	int i;
	int all_requests_completed = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = ec_sig_handler;

	pthread_t self;
	self = pthread_self();
	pthread_setname_np(self, "CLIENT_SPINNING_THREAD");
	channel = params->channel;

	while (1) {
		/*in cases where there are no connections stop spinning (optimization)*/
		if (!channel->spin_num[spinning_thread_id])
			sem_wait(&channel->sem_spinning[spinning_thread_id]);

		node = channel->spin_list[spinning_thread_id]->first;
		prev_node = NULL;

		while (node != NULL) {
			conn = (connection_rdma *)node->data;
			if (conn->connected != 1) {
				prev_node = node;
				node = node->next;
				continue;
			}

			if (conn->status == STOPPED_BY_THE_SERVER) {
				all_requests_completed = 0;
				__sync_synchronize();
				/*check send buffer first*/
				for (i = 0; i < conn->send_circular_buf->bitmap_size; i++) {
					if (conn->send_circular_buf->bitmap[i] != 0xFFFFFFFF) {
						//DPRINT("Ooops bitmap[0] = %x rendezvous at %llu\n",conn->send_circular_buf->bitmap[0], conn->rendezvous - conn->rdma_memory_regions->remote_memory_buffer);
						goto check_done;
					}
				}
				/*check receive now*/
				for (i = 0; i < conn->recv_circular_buf->bitmap_size - 1; i++) {
					if (conn->recv_circular_buf->bitmap[i] != 0xFFFFFFFF) {
						goto check_done;
					}
				}
				if ((conn->recv_circular_buf->bitmap[conn->recv_circular_buf->bitmap_size - 1]) !=
				    0x7FFFFFFF) {
					//DPRINT("Ooops bitmap[0] = %x\n",conn->recv_circular_buf->bitmap[0]);
					goto check_done;
				}
				all_requests_completed = 1;
				__sync_synchronize();

			check_done:
				if (all_requests_completed == 1) {
					// TODO insert code to switch from current peer_mr to next_peer_mr

					msg_header *reset = _client_allocate_rdma_message(conn, 0, SERVER_I_AM_READY);
					DPRINT("CLIENT: offset of I AM READY at %llu\n", (LLU)reset->local_offset);
					reset->receive = SERVER_I_AM_READY;
					// FIXME reset->data = new control location
					int bitmap_size = conn->next_peer_mr->length / MESSAGE_SEGMENT_SIZE /
							  BITS_PER_BITMAP_WORD;
					reset->data = bitmap_size * BITS_PER_BITMAP_WORD * MESSAGE_SEGMENT_SIZE -
						      MESSAGE_SEGMENT_SIZE;
					conn->control_location = reset->data;
					__send_rdma_message(conn, reset);

					DPRINT("CLIENT: waiting for server ack!\n");
					conn->status = WAIT_FOR_SERVER_ACK;
				}
				//else{
				//	DPRINT("CLIENT: Still pending staff\n");
				//}
			} else {
				/*Do we have any control message?*/
				hdr = (msg_header *)((uint64_t)conn->rdma_memory_regions->remote_memory_buffer +
						     (uint64_t)conn->control_location);
				recv = hdr->receive;
				int stat;
				int spin_counter = 0;
				//DPRINT("conn control location = %llu\n",conn->control_location);
				if (recv == TU_RDMA_REGULAR_MSG) {
					switch (hdr->type) {
					case CLIENT_STOP_NOW:
						if (++spin_counter % 1000000 == 0)
							DPRINT("CLIENT: Trying to stop\n");
						stat = pthread_mutex_trylock(&conn->buffer_lock);
						if (stat == 0) {
							// TODO destroy and then recreate the circular buffer for the new peer_mr length
							DPRINT("old_mr: addr = %p. length = %lu, rkey = %u\n",
							       conn->peer_mr->addr, conn->peer_mr->length,
							       conn->peer_mr->rkey);
							conn->next_peer_mr = malloc(sizeof(struct ibv_mr));
							memcpy(conn->next_peer_mr, (char *)hdr + sizeof(msg_header),
							       sizeof(struct ibv_mr));
							DPRINT("new_mr: addr = %p. length = %lu, rkey = %u\n",
							       conn->next_peer_mr->addr, conn->next_peer_mr->length,
							       conn->next_peer_mr->rkey);
							/*intentionally we do not unlock*/
							conn->status = STOPPED_BY_THE_SERVER;
							DPRINT("CLIENT: Server orders me to STOP!\n");
							hdr->receive = 0;
						}
						break;
					case CLIENT_RECEIVED_READY:
						assert(conn->status == WAIT_FOR_SERVER_ACK);
						hdr->receive = 0;
						struct ibv_mr *old_peer_mr = conn->peer_mr;
						conn->peer_mr = conn->next_peer_mr;
						conn->next_peer_mr = NULL;
						free(old_peer_mr);
						free(conn->send_circular_buf);
						free(conn->recv_circular_buf);
						//FIXME check mem leak for bitmap
						conn->send_circular_buf = create_and_init_circular_buffer(
							conn->rdma_memory_regions->local_memory_buffer,
							conn->peer_mr->length, MESSAGE_SEGMENT_SIZE, SEND_BUFFER);
						conn->recv_circular_buf = create_and_init_circular_buffer(
							conn->rdma_memory_regions->remote_memory_buffer,
							conn->peer_mr->length, MESSAGE_SEGMENT_SIZE, RECEIVE_BUFFER);
						conn->rendezvous = conn->rdma_memory_regions->remote_memory_buffer;
#ifdef CONNECTION_BUFFER_WITH_MUTEX_LOCK
						pthread_mutex_unlock(&conn->buffer_lock);
#else
						pthread_spin_unlock(&conn->buffer_lock);
#endif
						DPRINT("CLIENT: Ready again!\n");

						conn->status = CONNECTION_OK;
						break;
					default:
						DPRINT("CLIENT: FATAL unknown control message\n");
						exit(EXIT_FAILURE);
					}
				}
			}

			/*regular messages, regular path*/
			//DPRINT("CLIENT: Checking at %llu for conn %x\n",(LLU)(uint64_t)conn->rendezvous - (uint64_t)conn->rdma_memory_regions->remote_memory_buffer,conn);
			hdr = (msg_header *)conn->rendezvous;
			recv = hdr->receive;
			/*messages belonging to data path category*/
			if (recv == TU_RDMA_REGULAR_MSG) {
				message_size = _wait_for_payload_arrival(hdr);
				/*This should be removed! XXX TODO XXX*/
				__sync_fetch_and_add(&conn->pending_received_messages, 1);
				channel = (struct channel_rdma *)conn->channel;
				/*
				 * In client mode spinning thread performs two operations:
				 * 1) For SYNC_REQUESTS it wakes up the corresponing thread through the semaphore.
				 * 2) For ASYNC_REQUESTS it performs the receive path
				 **/
				if (hdr->request_message_local_addr != NULL) {
					/*tell him where the reply is*/
					msg_header *request = (msg_header *)hdr->request_message_local_addr;
					request->reply_message = hdr;
					request->ack_arrived = KR_REP_ARRIVED;
					switch (request->receive_options) {
					case SYNC_REQUEST:
						/*wake him up*/
						sem_post(&((msg_header *)hdr->request_message_local_addr)->sem);
						break;
					case ASYNC_REQUEST:
						//log_debug("REPLY FOR ASYNC REQ for request %llu value %d\n", request->reply, request->ack_arrived);
						request->ack_arrived = KR_REP_ARRIVED;
						(*request->callback_function)(request->callback_function_args);
						//free_rdma_local_message(conn);
						hdr->receive = 0;
						_zero_rendezvous_locations(hdr);
						client_free_rpc_pair(conn, hdr);
						break;
					case BUSY_WAIT:
						/*do nothing*/
						break;
					default:
						log_fatal(
							"unknown flags request addr: %llu of type %d reply is %d flags %d recv is %d\n",
							(LLU)request, request->type, hdr->type,
							request->receive_options, hdr->receive);
						raise(SIGINT);
						exit(EXIT_FAILURE);
						break;
					}
				} else {
					log_fatal("where is the address of the request's message of type %d addr %llu",
						  hdr->type, hdr->request_message_local_addr);
					raise(SIGINT);
					exit(EXIT_FAILURE);
				}

				/**
				 * Set the new rendezvous point, be careful for the case that the rendezvous is
				 * outsize of the rdma_memory_regions->remote_memory_buffer
				 * */
				_update_client_rendezvous_location(conn, message_size);
			}
#if 0
			else if(recv == RESET_BUFFER ){
				/*
				 * send RESET_BUFFER_ACK properties are
				 * 1. Only one thread per connection initiates RESET_BUFFER operation
				 * 2. RESET_BUFFER_ACK is sent at a special location (last_header of the header section in the memory region)
				 * Why? To avoid deadlocks, spinning thread acknowledges.
				 * Who sends it? A special worker thread because spinning thread should never block
				 */
				_send_reset_buffer_ack(conn);
				_zero_rendezvous_locations(hdr);
				_update_rendezvous_location(conn,0);
				goto iterate_next_element;
			}
#endif
			if (node->marked_for_deletion) {
				DPRINT("CLIENT: garbage collection of dead connection\n");
				pthread_mutex_lock(&channel->spin_list_conn_lock[spinning_thread_id]);
				next_node = node->next; /*Caution prev_node remains intact*/
				delete_element_from_simple_concurrent_list(channel->spin_list[spinning_thread_id],
									   prev_node, node);
				node = next_node;
				pthread_mutex_unlock(&channel->spin_list_conn_lock[spinning_thread_id]);
			} else {
				prev_node = node;
				node = node->next;
			}
		}
#endif
	}
	DPRINT("Spinning thread %d exiting\n", spinning_thread_id);
	return NULL;
}

static void *server_spinning_thread_kernel(void *args)
{
	struct msg_header *hdr;

	SIMPLE_CONCURRENT_LIST_NODE *node;
	SIMPLE_CONCURRENT_LIST_NODE *prev_node;
	SIMPLE_CONCURRENT_LIST_NODE *next_node;

	struct sigaction sa = {};
	struct channel_rdma *channel;
	spinning_thread_parameters *params = (spinning_thread_parameters *)args;
	struct connection_rdma *conn;

	uint32_t message_size;
	volatile uint32_t recv;

	int spinning_thread_id = params->spinning_thread_id;
	int spinning_list_type;
	int rc;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = ec_sig_handler;

	pthread_t self;
	self = pthread_self();
	pthread_setname_np(self, "SPINNING_THREAD");
	channel = params->channel;

	int count = 0;

	while (1) {
		/*in cases where there are no connections stop spinning (optimization)*/
		if (!channel->spin_num[spinning_thread_id])
			sem_wait(&channel->sem_spinning[spinning_thread_id]);

		/*gesalous, iterate the connection list of this channel for new messages*/
		if (count < 10) {
			node = channel->spin_list[spinning_thread_id]->first;
			spinning_list_type = HIGH_PRIORITY;
		} else {
			node = channel->idle_conn_list[spinning_thread_id]->first;
			spinning_list_type = LOW_PRIORITY;
			count = 0;
		}

		prev_node = NULL;

		while (node != NULL) {
			conn = (connection_rdma *)node->data;

			if (conn->connected != 1)
				goto iterate_next_element;

			hdr = (msg_header *)conn->rendezvous;
			recv = hdr->receive;

			/*messages belonging to data path category*/
			if (recv == TU_RDMA_REGULAR_MSG) {
				_update_connection_score(spinning_list_type, conn);
				message_size = _wait_for_payload_arrival(hdr);
				if (message_size == 0) {
					/*payload have not arrived yet check next connection*/
					goto iterate_next_element;
				}
				__sync_fetch_and_add(&conn->pending_received_messages, 1);
				channel = (struct channel_rdma *)conn->channel;

				if (hdr->type == FLUSH_SEGMENT_ACK || hdr->type == FLUSH_SEGMENT_ACK_AND_RESET) {
					if (hdr->request_message_local_addr == NULL) {
						//DPRINT("Boom! Replica  - * A C K E D * -\n");
						free_rdma_received_message(conn, hdr);
						++conn->FLUSH_SEGMENT_acks_received;
						if (hdr->type == FLUSH_SEGMENT_ACK_AND_RESET) {
							conn->rendezvous =
								conn->rdma_memory_regions->remote_memory_buffer;
						} else {
							conn->rendezvous += MESSAGE_SEGMENT_SIZE;
						}
						goto iterate_next_element;
						/*calculate here the new rendezous with replica since we do not use RESET_BUFFER for FLUSH*/
					} else {
						DPRINT("wake up thread FLUSH_SEGMENT_ACK arrived\n");
						msg_header *request = (msg_header *)hdr->request_message_local_addr;
						request->reply_message = hdr;
						request->ack_arrived = KR_REP_ARRIVED;
						/*wake him up*/
						sem_post(&((msg_header *)hdr->request_message_local_addr)->sem);
					}
				} else if (hdr->type == SPILL_INIT_ACK || hdr->type == SPILL_COMPLETE_ACK) {
					msg_header *request = (msg_header *)hdr->request_message_local_addr;
					request->reply_message = hdr;
					request->ack_arrived = KR_REP_ARRIVED;
					/*No more waking ups, spill thread will poll (with yield) to see the message*/
					//sem_post(&((msg_header *)hdr->request_message_local_addr)->sem);
				} else {
					/*normal messages*/
					hdr->receive = 0;
					rc = assign_job_to_worker(channel, conn, hdr, spinning_thread_id, -1);
					if (rc == KREON_FAILURE) {
						/*all workers are busy let's see messages from other connections*/
						__sync_fetch_and_sub(&conn->pending_received_messages, 1);
						/*Caution! message not consumed leave the rendezvous points as is*/
						hdr->receive = recv;
						goto iterate_next_element;
					}

					if (hdr->type == FLUSH_SEGMENT_AND_RESET) {
						//DPRINT("REPLICA: MASTER instructed me to FLUSH SEGMENT and reset setting rendevous to 0");
						conn->rendezvous = conn->rdma_memory_regions->remote_memory_buffer;
						goto iterate_next_element;
					} else if (hdr->type == FLUSH_SEGMENT) {
						conn->rendezvous = conn->rendezvous + RDMA_TOTAL_LOG_BUFFER_SIZE;
						//DPRINT("REPLICA: Just a normal FLUSH_SEGMENT waiting at offset %llu\n", (LLU)(uint64_t)conn->rendezvous - (uint64_t)conn->rdma_memory_regions->remote_memory_buffer);
						goto iterate_next_element;
					}
				}

				/**
				 * Set the new rendezvous point, be careful for the case that the rendezvous is
				 * outsize of the rdma_memory_regions->remote_memory_buffer
				 * */
				_update_rendezvous_location(conn, message_size);
			} else if (recv == RESET_BUFFER) {
				_update_connection_score(spinning_list_type, conn);
				/*
				 * send RESET_BUFFER_ACK properties are
				 * 1. Only one thread per connection initiates RESET_BUFFER operation
				 * 2. RESET_BUFFER_ACK is sent at a special location (last_header of the header section in the memory region)
				 * Why? To avoid deadlocks, spinning thread acknowledges.
				 * Who sends it? A special worker thread because spinning thread should never block
				 */

				rc = assign_job_to_worker(channel, conn, hdr, spinning_thread_id, -1);
				/*all workers are busy returns KREON_FAILURE*/
				if (rc != KREON_FAILURE) {
					hdr->receive =
						0; /*responsible worker will zero and update rendevous locations*/
				}
				goto iterate_next_element;
				/*rendezvous will by changed by the worker!*/
			} else if (recv == CONNECTION_PROPERTIES) {
				message_size = _wait_for_payload_arrival(hdr);
				if (message_size == 0) {
					/*payload have not arrived yet check next connection*/
					goto iterate_next_element;
				}

				if (hdr->type == DISCONNECT) {
					// Warning! the guy that consumes/handles the message is responsible for zeroing
					// the message's segments for possible future rendezvous points. This is done
					// inside free_rdma_received_message function

					DPRINT("\t * Disconnect operation bye bye mr Client garbage collection follows\n");
					// FIXME these operations might need to be atomic with more than one spinning threads
					struct channel_rdma *channel = conn->channel;
					//Decrement spinning thread's connections and total connections
					--channel->spin_num[channel->spinning_conn % channel->spinning_num_th];
					--channel->spinning_conn;
					_zero_rendezvous_locations(hdr);
					_update_rendezvous_location(conn, message_size);
					close_and_free_RDMA_connection(channel, conn);
					goto iterate_next_element;
				} else if (hdr->type == CHANGE_CONNECTION_PROPERTIES_REQUEST) {
					DPRINT("Remote side wants to change its connection properties\n");
					set_connection_property_req *req = (set_connection_property_req *)hdr->data;

					if (req->desired_priority_level == HIGH_PRIORITY) {
						DPRINT("Remote side wants to pin its connection\n");
						/*pin this conn bitches!*/
						conn->priority = HIGH_PRIORITY;
						msg_header *reply = allocate_rdma_message(
							conn, 0, CHANGE_CONNECTION_PROPERTIES_REPLY);
						reply->request_message_local_addr = hdr->request_message_local_addr;
						send_rdma_message(conn, reply);

						if (spinning_list_type == LOW_PRIORITY) {
							DPRINT("Upgrading its connection\n");
							_zero_rendezvous_locations(hdr);
							_update_rendezvous_location(conn, message_size);
							goto upgrade_connection;
						} else {
							_zero_rendezvous_locations(hdr);
							_update_rendezvous_location(conn, message_size);
						}
					}
				} else if (hdr->type == CHANGE_CONNECTION_PROPERTIES_REPLY) {
					assert(0);
					((msg_header *)hdr->request_message_local_addr)->ack_arrived = KR_REP_ARRIVED;
					/*do nothing for now*/
					_zero_rendezvous_locations(hdr);
					_update_rendezvous_location(conn, message_size);
					goto iterate_next_element;
				} else {
					DPRINT("FATAL unknown message type for connetion properties unknown type is %d\n",
					       hdr->type);
					assert(0);
					exit(EXIT_FAILURE);
				}
			} else if (recv == RESET_RENDEZVOUS) {
				//DPRINT("SERVER: Clients wants a reset ... D O N E\n");
				_zero_rendezvous_locations(hdr);
				conn->rendezvous = conn->rdma_memory_regions->remote_memory_buffer;
				goto iterate_next_element;
			} else if (recv == I_AM_CLIENT) {
				assert(conn->type == SERVER_TO_CLIENT_CONNECTION);
				conn->control_location = hdr->reply;
				conn->control_location_length = hdr->reply_length;
				hdr->receive = 0;
				DPRINT("SERVER: We have a new client control location %llu\n",
				       (LLU)conn->control_location);
				_zero_rendezvous_locations(hdr);
				_update_rendezvous_location(conn, MESSAGE_SEGMENT_SIZE);
				goto iterate_next_element;
			} else if (recv == SERVER_I_AM_READY) {
				conn->status = CONNECTION_OK;
				hdr->receive = 0;
				conn->control_location = hdr->data;

				DPRINT("Received SERVER_I_AM_READY at %llu\n", (LLU)conn->rendezvous);
				if (!backup_region) {
					backup_region = conn->rdma_memory_regions;
					conn->rdma_memory_regions = NULL;
					sem_post(&memory_steal_sem);
				} else {
					mrpool_free_memory_region(&conn->rdma_memory_regions);
				}
				assert(backup_region);

				conn->rdma_memory_regions = conn->next_rdma_memory_regions;
				conn->next_rdma_memory_regions = NULL;
				conn->rendezvous = conn->rdma_memory_regions->remote_memory_buffer;

				msg_header *msg =
					(msg_header *)((uint64_t)conn->rdma_memory_regions->local_memory_buffer +
						       (uint64_t)conn->control_location);
				msg->pay_len = 0;
				msg->padding_and_tail = 0;
				msg->data = NULL;
				msg->next = NULL;
				msg->type = CLIENT_RECEIVED_READY;
				msg->receive = TU_RDMA_REGULAR_MSG;
				msg->local_offset = (uint64_t)conn->control_location;
				msg->remote_offset = (uint64_t)conn->control_location;
				msg->ack_arrived = KR_REP_PENDING;
				msg->callback_function = NULL;
				msg->request_message_local_addr = NULL;
				__send_rdma_message(conn, msg);

				//DPRINT("SERVER: Client I AM READY reply will be send at %llu  length %d type %d message size %d id %llu\n",
				//(LLU)hdr->reply,hdr->reply_length, hdr->type,message_size,hdr->MR);
				goto iterate_next_element;
			} else {
				if (spinning_list_type == HIGH_PRIORITY)
					++conn->idle_iterations;
				else if (conn->idle_iterations > 0)
					--conn->idle_iterations;
				goto iterate_next_element;
			}

#endif

		iterate_next_element:
			if (node->marked_for_deletion) {
				DPRINT("\t garbage collection\n");
				pthread_mutex_lock(&channel->spin_list_conn_lock[spinning_thread_id]);
				next_node = node->next; /*Caution prev_node remains intact*/
				if (spinning_list_type == HIGH_PRIORITY)
					delete_element_from_simple_concurrent_list(
						channel->spin_list[spinning_thread_id], prev_node, node);
				else
					delete_element_from_simple_concurrent_list(
						channel->idle_conn_list[spinning_thread_id], prev_node, node);
				node = next_node;
				pthread_mutex_unlock(&channel->spin_list_conn_lock[spinning_thread_id]);
			}

			else if (0
				 /*spinning_list_type == HIGH_PRIORITY &&
						conn->priority != HIGH_PRIORITY &&//we don't touch high priority connections
						conn->idle_iterations > MAX_IDLE_ITERATIONS*/) {
				DPRINT("***** Downgrading connection...*****\n");
				pthread_mutex_lock(&channel->spin_list_conn_lock[spinning_thread_id]);
				next_node = node->next; /*Caution prev_node remains intact*/
				remove_element_from_simple_concurrent_list(channel->spin_list[spinning_thread_id],
									   prev_node, node);
				add_node_in_simple_concurrent_list(channel->idle_conn_list[spinning_thread_id], node);
				conn->responsible_spin_list = channel->idle_conn_list[spinning_thread_id];
				conn->idle_iterations = 0;
				node = next_node;
				pthread_mutex_unlock(&channel->spin_list_conn_lock[spinning_thread_id]);
				DPRINT("***** Downgrading connection...D O N E *****\n");

			}

			else if (spinning_list_type == LOW_PRIORITY && conn->idle_iterations > MAX_IDLE_ITERATIONS) {
			upgrade_connection:
				DPRINT("***** Upgrading connection...*****\n");
				pthread_mutex_lock(&channel->spin_list_conn_lock[spinning_thread_id]);
				next_node = node->next; /*Caution prev_node remains intact*/
				remove_element_from_simple_concurrent_list(channel->idle_conn_list[spinning_thread_id],
									   prev_node, node);
				add_node_in_simple_concurrent_list(channel->spin_list[spinning_thread_id], node);
				conn->responsible_spin_list = channel->spin_list[spinning_thread_id];
				conn->idle_iterations = 0;
				node = next_node;
				pthread_mutex_unlock(&channel->spin_list_conn_lock[spinning_thread_id]);
				DPRINT("***** Upgrading connection...D O N E *****\n");
			} else {
				prev_node = node;
				node = node->next;
			}
		}
	}
	DPRINT("Server Spinning thread %d exiting\n", spinning_thread_id);
	return NULL;
}

void close_and_free_RDMA_connection(struct channel_rdma *channel, struct connection_rdma *conn)
{
	conn->connected = 0;

	mrpool_free_memory_region(&conn->rdma_memory_regions);

	/*remove connection from its corresponding list*/
	pthread_mutex_lock(&channel->spin_list_conn_lock[conn->responsible_spinning_thread_id]);
	mark_element_for_deletion_from_simple_concurrent_list(conn->responsible_spin_list, conn);
	DPRINT("\t * Removed connection form list successfully :-) \n");
	channel->nconn--;
	channel->nused--;
	pthread_mutex_unlock(&channel->spin_list_conn_lock[conn->responsible_spinning_thread_id]);
	conn->channel = NULL;
	sem_post(&conn->sem_disconnect);

	ibv_destroy_cq(conn->rdma_cm_id->qp->send_cq);
	rdma_destroy_qp(conn->rdma_cm_id);
	rdma_destroy_id(conn->rdma_cm_id);

	free(conn);
	DPRINT("\t*Destroyed RDMA connection successfully\n");
}

/* helper function to print the content of the async event */
static void print_async_event(struct ibv_context *ctx, struct ibv_async_event *event)
{
	switch (event->event_type) {
	/* QP events */
	case IBV_EVENT_QP_FATAL:
		printf("EVENT QP fatal event for QP with handle %p\n", event->element.qp);
		break;
	case IBV_EVENT_QP_REQ_ERR:
		printf("EVENT QP Requestor error for QP with handle %p\n", event->element.qp);
		break;
	case IBV_EVENT_QP_ACCESS_ERR:
		printf("EVENT QP access error event for QP with handle %p\n", event->element.qp);
		break;
	case IBV_EVENT_COMM_EST:
		printf("EVENT QP communication established event for QP with handle %p\n", event->element.qp);
		break;
	case IBV_EVENT_SQ_DRAINED:
		printf("EVENT QP Send Queue drained event for QP with handle %p\n", event->element.qp);
		break;
	case IBV_EVENT_PATH_MIG:
		printf("EVENT QP Path migration loaded event for QP with handle %p\n", event->element.qp);
		break;
	case IBV_EVENT_PATH_MIG_ERR:
		printf("EVENT QP Path migration error event for QP with handle %p\n", event->element.qp);
		break;
	case IBV_EVENT_QP_LAST_WQE_REACHED:
		printf("EVENT QP last WQE reached event for QP with handle %p\n", event->element.qp);
		break;

		/* CQ events */
	case IBV_EVENT_CQ_ERR:
		printf("EVENT CQ error for CQ with handle %p\n", event->element.cq);
		break;

		/* SRQ events */
	case IBV_EVENT_SRQ_ERR:
		printf("EVENT SRQ error for SRQ with handle %p\n", event->element.srq);
		break;
	case IBV_EVENT_SRQ_LIMIT_REACHED:
		printf("EVENT SRQ limit reached event for SRQ with handle %p\n", event->element.srq);
		break;

		/* Port events */
	case IBV_EVENT_PORT_ACTIVE:
		printf("EVENT Port active event for port number %d\n", event->element.port_num);
		break;
	case IBV_EVENT_PORT_ERR:
		printf("EVENT Port error event for port number %d\n", event->element.port_num);
		break;
	case IBV_EVENT_LID_CHANGE:
		printf("EVENT LID change event for port number %d\n", event->element.port_num);
		break;
	case IBV_EVENT_PKEY_CHANGE:
		printf("EVENT P_Key table change event for port number %d\n", event->element.port_num);
		break;
	case IBV_EVENT_GID_CHANGE:
		printf("EVENT GID table change event for port number %d\n", event->element.port_num);
		break;
	case IBV_EVENT_SM_CHANGE:
		printf("EVENT SM change event for port number %d\n", event->element.port_num);
		break;
	case IBV_EVENT_CLIENT_REREGISTER:
		printf("EVENT Client reregister event for port number %d\n", event->element.port_num);
		break;

		/* RDMA device events */
	case IBV_EVENT_DEVICE_FATAL:
		printf("EVENT Fatal error event for device %s\n", ibv_get_device_name(ctx->device));
		break;

	default:
		printf("EVENT Unknown event (%d)\n", event->event_type);
	}
}

void rdma_thread_events_ctx(void *args)
{
	struct channel_rdma *channel;
	int ret;
	struct ibv_async_event event;
	pthread_t self;
	self = pthread_self();
	pthread_setname_np(self, "rdma_events");

	//printf("Thread Events CTX\n");fflush(stdout);

	channel = (struct channel_rdma *)args;

	while (1) {
		//printf("Thread Events CTX\n");fflush(stdout);
		/* wait for the next async event */
		ret = ibv_get_async_event(channel->context, &event);
		if (ret) {
			fprintf(stderr, "EVENT Error, ibv_get_async_event() failed\n");
			return;
		}
		/* print the event */
		print_async_event(channel->context, &event);

		/* ack the event */
		ibv_ack_async_event(&event);
	}
	return;
}

static void *poll_cq(void *arg)
{
	struct sigaction sa = {};
	struct channel_rdma *channel;
	struct connection_rdma *conn;
	struct ibv_cq *cq;
	struct ibv_wc wc[MAX_COMPLETION_ENTRIES];
	void *ev_ctx;
	int rc;
	int i;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = ec_sig_handler;
	rc = sigaction(SIGINT, &sa, 0);

	pthread_setname_np(pthread_self(), "poll_cq thread");
	channel = (struct channel_rdma *)arg;

	while (1) {
		if (ibv_get_cq_event(channel->comp_channel, &cq, &ev_ctx) != 0) {
			DPRINT("polling cq failure reason follows-->\n");
			perror("Reason: \n");
			exit(EXIT_FAILURE);
		}
		/*DPRINT("Got new competion event!\n");*/
		ibv_ack_cq_events(cq, 1);
		if (ibv_req_notify_cq(cq, 0) != 0) {
			perror("ERROR poll_cq: ibv_req_notify_cq\n");
			exit(-1);
		}

		while (1) {
			rc = ibv_poll_cq(cq, MAX_COMPLETION_ENTRIES, wc);
			if (rc < 0) {
				DPRINT("FATAL poll of completion queue failed!\n");
				exit(EXIT_FAILURE);
			} else if (rc > 0) {
				conn = (connection_rdma *)cq->cq_context;
				for (i = 0; i < rc; i++) {
					on_completion_server(&wc[i], conn);
					memset(&wc[i], 0x00, sizeof(struct ibv_wc));
				}
			} else
				break;
		}
	}
	return NULL;
}

void on_completion_server(struct ibv_wc *wc, struct connection_rdma *conn)
{
	msg_header *msg;
	if (wc->status == IBV_WC_SUCCESS) {
		switch (wc->opcode) {
		case IBV_WC_SEND:
			log_info("IBV_WC_SEND code id of connection %d", conn->idconn);
			break;
		case IBV_WC_RECV:
			log_info("IBV_WC_RECV code id of connection %d", conn->idconn);
			break;
		case IBV_WC_RDMA_WRITE:
			if (wc->wr_id != 0) {
				msg = (msg_header *)wc->wr_id;
				switch (msg->type) {
				/*server to client messages*/
				case PUT_REPLY:
				case TU_UPDATE_REPLY:
				case TU_GET_REPLY:
				case MULTI_GET_REPLY:
				case TEST_REPLY:
				case TEST_REPLY_FETCH_PAYLOAD:
				case SCAN_REQUEST:
				case CLIENT_STOP_NOW:
				case CLIENT_RECEIVED_READY:
					/*do nothing, client handles them*/
					break;

				/*server to server*/
				case SPILL_INIT_ACK:
				case SPILL_COMPLETE_ACK:
				case FLUSH_SEGMENT_ACK:
				case FLUSH_SEGMENT_ACK_AND_RESET:
				case SPILL_INIT:
				case SPILL_BUFFER_REQUEST:
				case SPILL_COMPLETE:
				case FLUSH_SEGMENT:
				case FLUSH_SEGMENT_AND_RESET:
				case FLUSH_SEGMENT_TEST:
					free_rdma_local_message(conn);
					break;
				/*client to server RPCs*/
				case PUT_REQUEST:
				case MULTI_PUT:
				case TU_GET_QUERY:
				case TU_UPDATE:
				case MULTI_GET_REQUEST:
				case SCAN_REPLY:
				case TEST_REQUEST:
				case TEST_REQUEST_FETCH_PAYLOAD:
				case SERVER_I_AM_READY:
					break;
				case I_AM_CLIENT:
				case RESET_RENDEZVOUS:
				case DISCONNECT:
					/*client staff, app will decide when staff arrives*/
					free_space_from_circular_buffer(conn->send_circular_buf, (char *)msg,
									MESSAGE_SEGMENT_SIZE);
					break;

				case CHANGE_CONNECTION_PROPERTIES_REQUEST:
				case CHANGE_CONNECTION_PROPERTIES_REPLY:
					free_rdma_local_message(conn);
					break;

				case RESET_BUFFER:
				case RESET_BUFFER_ACK:
					break;

				default:
					log_fatal("Entered unplanned state FATAL for message type %d", msg->type);
					raise(SIGINT);
					exit(EXIT_FAILURE);
				}
			}
			break;
		case IBV_WC_RDMA_READ:
			DPRINT("IBV_WC_RDMA_READ code\n");
			break;
		case IBV_WC_COMP_SWAP:
			DPRINT("IBV_WC_COMP_SWAP code\n");
			break;
		case IBV_WC_FETCH_ADD:
			DPRINT("IBV_WC_FETCH_ADD code\n");
			break;
		case IBV_WC_BIND_MW:
			DPRINT("IBV_WC_BIND_MW code\n");
			break;
		case IBV_WC_RECV_RDMA_WITH_IMM:
			DPRINT("IBV_WC_RECV_RDMA_WITH_IMM code\n");
			break;
		default:
			DPRINT("FATAL unknown code\n");
			exit(EXIT_FAILURE);
		}
	} else { /*error handling*/
		ERRPRINT("%s\n", ibv_wc_status_str(wc->status));
		raise(SIGINT);
		exit(KREON_FAILURE);
	}
}

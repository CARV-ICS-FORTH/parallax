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
#include "../kreon_server/metadata.h"
#include "../kreon_server/messages.h"
#include "../kreon_server/globals.h"

#include "../utilities/simple_concurrent_list.h"
#include "../utilities/spin_loop.h"
#include "../utilities/circular_buffer.h"
#include <log.h>

#define CTX_HANDSHAKE_SUCCESS 0
#define CTX_HANDSHAKE_FAILURE 1
#define MAX_COMPLETION_ENTRIES 32

uint32_t RDMA_TOTAL_LOG_BUFFER_SIZE;
int LIBRARY_MODE = SERVER_MODE; /*two modes for the communication rdma library
                                   SERVER and CLIENT*/
int assign_job_to_worker(struct channel_rdma *channel, struct connection_rdma *conn, msg_header *msg,
			 int spinning_thread_id, int sockfd);
uint64_t wake_up_workers_operations = 0;

uint64_t *spinning_threads_core_ids;
uint64_t *worker_threads_core_ids;
uint32_t num_of_spinning_threads;
uint32_t num_of_worker_threads;

/*one port for waiitng client connections, another for waiting connections from
 * other servers*/

void crdma_add_connection_channel(struct channel_rdma *channel, struct connection_rdma *conn);

void check_pending_ack_message(struct connection_rdma *conn);
void force_send_ack(struct connection_rdma *conn);

void rdma_thread_events_ctx(void *args);

static void *poll_cq(void *arg);
void on_completion_server(struct rdma_message_context *msg_ctx);

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

	// DPRINT("\t Sending to remote offset %llu\n", msg->remote_offset);
	msg->ack_arrived = KR_REP_PENDING;
	// conn->offset += message_size;
}

msg_header *allocate_rdma_message(connection_rdma *conn, int message_payload_size, int message_type)
{
	log_fatal("dead function");
	raise(SIGINT);
	exit(EXIT_FAILURE);
#if 0
	msg_header *msg;
	pthread_mutex_t *lock;
	switch (message_type) {
	case PUT_REQUEST:
	case GET_REQUEST:
	case MULTI_GET_REQUEST:
	case PUT_OFFT_REQUEST:
	case DELETE_REQUEST:
	case I_AM_CLIENT:
	case SERVER_I_AM_READY:
	case DISCONNECT:
	case RESET_RENDEZVOUS:
		lock = &conn->send_buffer_lock;
		break;
	case PUT_REPLY:
	case TU_GET_REPLY:
	case MULTI_GET_REPLY:
	case PUT_OFFT_REPLY:
	case DELETE_REPLY:
		lock = &conn->recv_buffer_lock;
		break;
	default:
		log_fatal("faulty message type %d", message_type);
		exit(EXIT_FAILURE);
	}
#ifdef CONNECTION_BUFFER_WITH_MUTEX_LOCK
	pthread_mutex_lock(lock);
#else
	pthread_spin_lock(lock);
#endif

	msg = _client_allocate_rdma_message(conn, message_payload_size, message_type);

#ifdef CONNECTION_BUFFER_WITH_MUTEX_LOCK
	pthread_mutex_unlock(lock);
#else
	pthread_spin_unlock(lock);
#endif
return msg;
#endif
	return NULL;
}

msg_header *client_allocate_rdma_message(connection_rdma *conn, int message_payload_size, int message_type)
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
	case GET_REQUEST:
	case MULTI_GET_REQUEST:
	case PUT_OFFT_REQUEST:
	case DELETE_REQUEST:
	case TEST_REQUEST:
		c_buf = conn->send_circular_buf;
		ack_arrived = KR_REP_PENDING;
		receive_type = TU_RDMA_REGULAR_MSG;
		reset_rendezvous = 1;
		break;
	case TEST_REPLY:
	case PUT_REPLY:
	case GET_REPLY:
	case MULTI_GET_REPLY:
	case PUT_OFFT_REPLY:
	case DELETE_REPLY:
		c_buf = conn->recv_circular_buf;
		ack_arrived = KR_REP_DONT_CARE;
		receive_type = 0;
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
			padding = (MESSAGE_SEGMENT_SIZE - (message_size % MESSAGE_SEGMENT_SIZE));
			message_size += padding;
			assert(message_size % MESSAGE_SEGMENT_SIZE == 0);
		} else
			padding = 0;
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
				if (allocate_space_from_circular_buffer(c_buf, MESSAGE_SEGMENT_SIZE, &addr) !=
				    ALLOCATION_IS_SUCCESSFULL) {
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
				// log_info("Sending to remote offset %llu\n", msg->remote_offset);
				msg->ack_arrived = ack_arrived;
				msg->request_message_local_addr = NULL;
				msg->reply = NULL;
				msg->reply_length = 0;
				if (client_send_rdma_message(conn, msg) != KREON_SUCCESS) {
					log_fatal("RDMA Write error");
					exit(EXIT_FAILURE);
				}
				free_space_from_circular_buffer(conn->send_circular_buf, (char *)msg,
								MESSAGE_SEGMENT_SIZE);
				// log_info("CLIENT: Informing server to reset the rendezvous");
			}
			addr = NULL;
			reset_circular_buffer(c_buf);

			break;
		case SPACE_NOT_READY_YET:
			if (++i % 10000000 == 0) {
				for (i = 0; i < c_buf->bitmap_size; i++) {
					if (c_buf->bitmap[i] != (int)0xFFFFFFFF) {
						// if (++k % 100000000 == 0)
						// DPRINT("bitmap[%d] = 0x%x waiting for reply at
						// %llu\n",i,conn->send_circular_buf->bitmap[i],
						// (char*)conn->rendezvous -
						// conn->rdma_memory_regions->remote_memory_buffer);
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
			      sizeof(uint32_t)) = receive_type;
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

	// log_info("\t Sending to remote offset %llu\n", msg->remote_offset);
	msg->ack_arrived = ack_arrived;
	msg->request_message_local_addr = NULL;

	return msg;
}

/* FIXME this function is mostly a copy of client_allocate_rdma_message.
 * A possible fix would be to split into smaller functions, shared between both
 * and use __attribute__((flatten)) to
 * avoid the incurred performance overheads by inlining them.
 * Useful link from gxanth:
 * https://awesomekling.github.io/Smarter-C++-inlining-with-attribute-flatten/
 */
msg_header *client_try_allocate_rdma_message(connection_rdma *conn, int message_payload_size, int message_type)
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
	case GET_REQUEST:
	case MULTI_GET_REQUEST:
	case TEST_REQUEST:
		c_buf = conn->send_circular_buf;
		ack_arrived = KR_REP_PENDING;
		receive_type = TU_RDMA_REGULAR_MSG;
		reset_rendezvous = 1;
		break;
	case TEST_REPLY:
	case PUT_REPLY:
	case GET_REPLY:
	case MULTI_GET_REPLY:
		c_buf = conn->recv_circular_buf;
		ack_arrived = KR_REP_DONT_CARE;
		receive_type = 0;
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
			padding = (MESSAGE_SEGMENT_SIZE - (message_size % MESSAGE_SEGMENT_SIZE));
			message_size += padding;
			assert(message_size % MESSAGE_SEGMENT_SIZE == 0);
		} else
			padding = 0;
	} else {
		message_size = MESSAGE_SEGMENT_SIZE;
		padding = 0;
	}

	addr = NULL;

	// while (1) {
	stat = allocate_space_from_circular_buffer(c_buf, message_size, &addr);
	switch (stat) {
	case ALLOCATION_IS_SUCCESSFULL:
	case BITMAP_RESET:
		goto init_message;

	case NOT_ENOUGH_SPACE_AT_THE_END:
		if (reset_rendezvous) {
			/*inform remote side that to reset the rendezvous*/
			if (allocate_space_from_circular_buffer(c_buf, MESSAGE_SEGMENT_SIZE, &addr) !=
			    ALLOCATION_IS_SUCCESSFULL) {
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
			// log_info("Sending to remote offset %llu\n", msg->remote_offset);
			msg->ack_arrived = ack_arrived;
			msg->request_message_local_addr = NULL;
			msg->reply = NULL;
			msg->reply_length = 0;
			if (client_send_rdma_message(conn, msg) != KREON_SUCCESS) {
				log_fatal("RDMA Write error");
				exit(EXIT_FAILURE);
			}
			free_space_from_circular_buffer(conn->send_circular_buf, (char *)msg, MESSAGE_SEGMENT_SIZE);
			// log_info("CLIENT: Informing server to reset the rendezvous");
		}
		addr = NULL;
		reset_circular_buffer(c_buf);

		break;
	case SPACE_NOT_READY_YET:
		if (++i % 10000000 == 0) {
			for (i = 0; i < c_buf->bitmap_size; i++) {
				if (c_buf->bitmap[i] != (int)0xFFFFFFFF) {
					// if (++k % 100000000 == 0)
					// DPRINT("bitmap[%d] = 0x%x waiting for reply at
					// %llu\n",i,conn->send_circular_buf->bitmap[i],
					// (char*)conn->rendezvous -
					// conn->rdma_memory_regions->remote_memory_buffer);
				}
			}
		}
		break;
	}
	// }
	return NULL;
init_message:
	msg = (msg_header *)addr;
	if (message_payload_size > 0) {
		msg->pay_len = message_payload_size;
		msg->padding_and_tail = padding + TU_TAIL_SIZE;
		msg->data = (void *)((uint64_t)msg + TU_HEADER_SIZE);
		msg->next = msg->data;
		/*set the tail to the proper value*/
		*(uint32_t *)(((uint64_t)msg + TU_HEADER_SIZE + msg->pay_len + msg->padding_and_tail) -
			      sizeof(uint32_t)) = receive_type;
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

	// log_info("\t Sending to remote offset %llu\n", msg->remote_offset);
	msg->ack_arrived = ack_arrived;
	msg->request_message_local_addr = NULL;

	return msg;
}

int send_rdma_message_busy_wait(connection_rdma *conn, msg_header *msg)
{
	msg->receive_options = BUSY_WAIT;
	return __send_rdma_message(conn, msg, NULL);
}

int send_rdma_message(connection_rdma *conn, msg_header *msg)
{
	// sem_init(&msg->sem, 0, 0);
	msg->receive_options = SYNC_REQUEST;
	return __send_rdma_message(conn, msg, NULL);
}

void on_completion_client(struct rdma_message_context *msg_ctx);

int client_send_rdma_message(struct connection_rdma *conn, struct msg_header *msg)
{
	struct rdma_message_context msg_ctx;
	client_rdma_init_message_context(&msg_ctx, msg);
	msg_ctx.on_completion_callback = on_completion_client;
	int ret = __send_rdma_message(conn, msg, &msg_ctx);
	if (ret == KREON_SUCCESS) {
		if (!client_rdma_send_message_success(&msg_ctx))
			ret = KREON_FAILURE;
	}
	return ret;
}

int __send_rdma_message(connection_rdma *conn, msg_header *msg, struct rdma_message_context *msg_ctx)
{
	// int i = 0;
	// while (conn->pending_sent_messages >= MAX_WR) {
	//	__sync_fetch_and_add(&conn->sleeping_workers, 1);
	//	log_warn("Congestion in the write path throttling... %llu\n",
	//(LLU)conn->pending_sent_messages);
	//	sem_wait(&conn->congestion_control);
	//	__sync_fetch_and_sub(&conn->sleeping_workers, 1);
	//	if (++i % 100000 == 0) {
	//		log_warn("Congestion in the write path throttling... %llu\n",
	//(LLU)conn->pending_sent_messages);
	//	}
	//}

	size_t msg_len;
	if (msg->pay_len) // FIXME This if shouldn't be necessary
		msg_len = TU_HEADER_SIZE + msg->pay_len + msg->padding_and_tail;
	else
		msg_len = TU_HEADER_SIZE;

	/* *
   * do we want to associate any context with the message aka let the completion
   * thread perform any operation
   * for us? For client PUT,GET,MULTI_GET,UPDATE,DELETE we don't
   * */
	void *context;
	if (!msg_ctx && LIBRARY_MODE == SERVER_MODE) {
		switch (msg->type) {
		case PUT_REQUEST:
		case GET_REQUEST:
		case MULTI_GET_REQUEST:
		case PUT_OFFT_REQUEST:
		case DELETE_REQUEST:
		case TEST_REQUEST:
		case TEST_REQUEST_FETCH_PAYLOAD:
		case GET_LOG_BUFFER_REQ:
		case FLUSH_COMMAND_REQ:
		case FLUSH_COMMAND_REP:
		case GET_LOG_BUFFER_REP:
		case PUT_REPLY:
		case GET_REPLY:
		case MULTI_GET_REPLY:
		case PUT_OFFT_REPLY:
		case DELETE_REPLY:
		case TEST_REPLY:
		case TEST_REPLY_FETCH_PAYLOAD:
			context = NULL;
			break;
		default: {
			/*rest I care*/
			assert(0);
			struct rdma_message_context *msg_ctx = malloc(sizeof(struct rdma_message_context));
			client_rdma_init_message_context(msg_ctx, msg);
			msg_ctx->on_completion_callback = on_completion_server;
			msg_ctx->args = (void *)conn;
			context = msg_ctx;
			break;
		}
		}
	} else {
		context = (void *)msg_ctx;
	}

	int ret;

	while (1) {
		ret = rdma_post_write(conn->rdma_cm_id, context, msg, msg_len,
				      conn->rdma_memory_regions->local_memory_region, IBV_SEND_SIGNALED,
				      ((uint64_t)conn->peer_mr->addr + msg->remote_offset), conn->peer_mr->rkey);
		if (!ret) {
			break;
		}

		if (conn->status == CONNECTION_ERROR) {
			log_fatal("connection failed !: %s\n", strerror(errno));
			raise(SIGINT);
			exit(EXIT_FAILURE);
		}
	}

	return KREON_SUCCESS;
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
	// assert(conn->pending_received_messages > 0);
	_zero_rendezvous_locations(msg);
	//__sync_fetch_and_sub(&conn->pending_received_messages, 1);
}

void free_rdma_local_message(connection_rdma *conn)
{
	// assert(conn->pending_sent_messages > 0);
	//__sync_fetch_and_sub(&conn->pending_sent_messages, 1);
	// if (conn->sleeping_workers > 0) {
	//	sem_post(&conn->congestion_control);
	//}
	return;
}

/*gesalous, disconnect*/
void disconnect_and_close_connection(connection_rdma *conn)
{
	msg_header *disconnect_request = allocate_rdma_message(conn, 0, DISCONNECT);
	send_rdma_message(conn, disconnect_request);
	DPRINT("Successfully sent disconnect message, bye bye Caution! Missing "
	       "deallocation of resources follows...\n");
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
	int num_devices;
	struct ibv_context **dev_list = rdma_get_devices(&num_devices);
	struct ibv_context *rdma_dev = NULL;
	for (int i = 0; i < num_devices; ++i)
		if (!strncmp(dev_list[i]->device->name, DEFAULT_DEV_IBV, strlen(DEFAULT_DEV_IBV))) {
			rdma_dev = dev_list[i];
			break;
		}
	if (!rdma_dev) {
		log_fatal("Cannot find RDMA device %s", DEFAULT_DEV_IBV);
		exit(EXIT_FAILURE);
	}
	return rdma_dev;
}

/**
 * Pick a connection to steal memory from. For the first implementation, a lower
 * priority connection will be picked
 * randomly.
 * @param connections_list A pointer to the connections list to search in for
 * the candidate connection
 * @return A pointer to a candidate connection from where to steal memory
 */
connection_rdma *find_memory_steal_candidate(SIMPLE_CONCURRENT_LIST *connections_list)
{
	SIMPLE_CONCURRENT_LIST_NODE *node = NULL;
	// SIMPLE_CONCURRENT_LIST_NODE*	node_max = NULL;
	connection_rdma *ret = NULL;
	// int i;
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

// TODO [mvard] Change ethernet_server_connect to use a free port number and add
// it to zookeeper so the clients can get that info
static void __stop_client(connection_rdma *conn);

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
	/*gesalous staff initialization*/
	conn->idle_iterations = 0;
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
	int host_copy_size = 1024;
	char *host_copy = (char *)malloc(host_copy_size);
	if (host_copy_size < strlen(hosts[0])) {
		log_fatal("Potential buffer overflow string len is %d allocated buffer is %d", strlen(hosts[0]),
			  host_copy_size);
		exit(EXIT_FAILURE);
	}
	char *strtok_state = NULL;
	strcpy(host_copy, hosts[0]);
	memset(&hints, 0, sizeof hints);
	hints.ai_port_space = RDMA_PS_TCP;
	int idx = strlen(host_copy) - 1;
	char special_character[2] = { '\0', '\0' };
	while (idx >= 0) {
		if (host_copy[idx] == ':' || host_copy[idx] == '-') {
			special_character[0] = host_copy[idx];
			break;
		}
		--idx;
	}
	ip = strtok_r(host_copy, special_character, &strtok_state);
	port = strtok_r(NULL, special_character, &strtok_state);

	log_info("Connecting to %s at port %s\n", ip, port);
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
	int tries = 0;
	while (tries < 100) {
		ret = rdma_connect(rdma_cm_id, &conn_param);
		if (ret) {
			log_warn("rdma_connect failed reconnecting: %s", strerror(errno));
			usleep(50000);
			++tries;
		} else
			break;
	}
	if (ret) {
		log_fatal("rdma_connect failed: %s", strerror(errno));
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
	free(host_copy);
	switch (type) {
	case MASTER_TO_REPLICA_CONNECTION:
		log_info("Remote side accepted created a new MASTER_TO_REPLICA_CONNECTION");
		conn->type = MASTER_TO_REPLICA_CONNECTION;
		// conn->rdma_memory_regions =
		//	mrpool_get_static_buffer(rdma_cm_id, sizeof(struct ru_rdma_buffer) *
		//RU_REPLICA_NUM_SEGMENTS);
		conn->rdma_memory_regions = mrpool_allocate_memory_region(channel->dynamic_pool, rdma_cm_id);
		break;
	case CLIENT_TO_SERVER_CONNECTION:
		// log_info("Remote side accepted created a new
		// CLIENT_TO_SERVER_CONNECTION");
		conn->type = CLIENT_TO_SERVER_CONNECTION;
		conn->rdma_memory_regions = mrpool_allocate_memory_region(channel->dynamic_pool, rdma_cm_id);
		break;
	case REPLICA_TO_MASTER_CONNECTION:
	case SERVER_TO_CLIENT_CONNECTION:
		log_warn("Should not handle this kind of connection here");
	default:
		log_fatal("BAD connection type");
		exit(EXIT_FAILURE);
	}
	conn->remaining_bytes_in_remote_rdma_region = conn->rdma_memory_regions->memory_region_length;
	conn->priority = LOW_PRIORITY; // FIXME I don't think I use this anymore
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

	conn->status = CONNECTION_OK;
	/*zero all memory*/
	memset(conn->rdma_memory_regions->local_memory_buffer, 0x00, conn->rdma_memory_regions->memory_region_length);
	if (sem_init(&conn->congestion_control, 0, 0) != 0) {
		log_fatal("failed to initialize semaphore reason follows");
		perror("Reason: ");
	}
	conn->sleeping_workers = 0;
	// conn->pending_sent_messages = 0;
	// conn->pending_received_messages = 0;
	conn->offset = 0;
	conn->qp = conn->rdma_cm_id->qp;

#ifdef CONNECTION_BUFFER_WITH_MUTEX_LOCK
	pthread_mutex_init(&conn->buffer_lock, NULL);
#else
	pthread_spin_init(&conn->buffer_lock, PTHREAD_PROCESS_PRIVATE);
#endif
	switch (conn->type) {
	case CLIENT_TO_SERVER_CONNECTION:
		log_info("Initializing client communication circular buffer");
		conn->send_circular_buf =
			create_and_init_circular_buffer(conn->rdma_memory_regions->local_memory_buffer,
							conn->peer_mr->length, MESSAGE_SEGMENT_SIZE, SEND_BUFFER);
		conn->recv_circular_buf =
			create_and_init_circular_buffer(conn->rdma_memory_regions->remote_memory_buffer,
							conn->peer_mr->length, MESSAGE_SEGMENT_SIZE, RECEIVE_BUFFER);
		conn->reset_point = 0;
		/*Inform the server that you are a client, patch but now I am in a hurry*/
		// log_info("CLIENT: Informing server that I am a client and about my
		// control location\n");
		pthread_mutex_lock(&conn->buffer_lock);
		msg = client_allocate_rdma_message(conn, 0, I_AM_CLIENT);
		pthread_mutex_unlock(&conn->buffer_lock);
		/*control info*/
		msg->reply = (char *)(conn->recv_circular_buf->bitmap_size * BITS_PER_BITMAP_WORD *
				      (uint64_t)MESSAGE_SEGMENT_SIZE);
		msg->reply -= MESSAGE_SEGMENT_SIZE;
		msg->reply_length = MESSAGE_SEGMENT_SIZE;
		conn->control_location = (char *)msg->reply;
		conn->control_location_length = msg->reply_length;
		msg->receive = I_AM_CLIENT;
		if (client_send_rdma_message(conn, msg) != KREON_SUCCESS) {
			log_fatal("RDMA Write error");
			exit(EXIT_FAILURE);
		}
		free_space_from_circular_buffer(conn->send_circular_buf, (char *)msg, MESSAGE_SEGMENT_SIZE);
		log_info("Client Connection created successfully, no spinning thread will "
			 "check it");
		break;

	case MASTER_TO_REPLICA_CONNECTION:
		log_info("Initializing master to replica communication circular buffer");
		conn->send_circular_buf =
			create_and_init_circular_buffer(conn->rdma_memory_regions->local_memory_buffer,
							conn->peer_mr->length, MESSAGE_SEGMENT_SIZE, SC_SEND_BUFFER);
		conn->recv_circular_buf =
			create_and_init_circular_buffer(conn->rdma_memory_regions->remote_memory_buffer,
							conn->peer_mr->length, MESSAGE_SEGMENT_SIZE, SC_RECEIVE_BUFFER);
		conn->reset_point = 0;
		break;

	default:
		conn->send_circular_buf = NULL;
		conn->recv_circular_buf = NULL;
		conn->reset_point = 0;
		crdma_add_connection_channel(channel, conn);
		conn->send_circular_buf = NULL;
		conn->recv_circular_buf = NULL;
		conn->reset_point = 0;
		crdma_add_connection_channel(channel, conn);
	}
	__sync_fetch_and_add(&channel->nused, 1);
}

void crdma_init_generic_create_channel(struct channel_rdma *channel)
{
	int i;
	channel->sockfd = 0;
	channel->context = open_ibv_device(DEFAULT_DEV_IBV);

	channel->comp_channel = ibv_create_comp_channel(channel->context);
	if (channel->comp_channel == 0) {
		log_fatal("building context reason follows:");
		perror("Reason: \n");
		exit(EXIT_FAILURE);
	}

	channel->pd = ibv_alloc_pd(channel->context);
	channel->nconn = 0;
	channel->nused = 0;
	channel->connection_created = NULL;

	if (LIBRARY_MODE == CLIENT_MODE) {
		channel->static_pool = NULL;
		channel->dynamic_pool = mrpool_create(channel->pd, -1, DYNAMIC, MEM_REGION_BASE_SIZE);

		pthread_mutex_init(&channel->spin_conn_lock,
				   NULL); // Lock for the conn_list
		channel->spinning_th = 0;
		channel->spinning_conn = 0;
		// log_info("Client: setting spinning threads number to 1");
		channel->spinning_num_th = 1;

		assert(channel->spinning_num_th <= SPINNING_NUM_TH);

		for (i = 0; i < channel->spinning_num_th; i++) {
			pthread_mutex_init(&channel->spin_list_conn_lock[i], NULL);
			channel->spin_list[i] = init_simple_concurrent_list();
			channel->idle_conn_list[i] = init_simple_concurrent_list();
		}

		for (i = 0; i < channel->spinning_num_th; i++) {
			channel->spin_list[i] = init_simple_concurrent_list();
			channel->spin_num[i] = 0;
			sem_init(&channel->sem_spinning[i], 0, 0);
			spinning_thread_parameters *params =
				(spinning_thread_parameters *)malloc(sizeof(spinning_thread_parameters));
			params->channel = channel;
			params->spinning_thread_id = i;
		}
	}
	/*Creating the thread in charge of the completion channel*/
	if (pthread_create(&channel->cq_poller_thread, NULL, poll_cq, channel) != 0) {
		log_fatal("Failed to create poll_cq thread reason follows:");
		perror("Reason: \n");
		exit(EXIT_FAILURE);
	}
}

struct channel_rdma *crdma_client_create_channel(void)
{
	struct channel_rdma *channel;

	channel = malloc(sizeof(*channel));
	if (channel == NULL) {
		perror("ERROR crdma_alloc_init_channel_rdma: memory problem, malloc failed\n");
		exit(EXIT_FAILURE);
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

void crdma_add_connection_channel(struct channel_rdma *channel, struct connection_rdma *conn)
{
	conn->idconn = channel->nconn;
	// conn->local_mrq->idconn =  conn->idconn;
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
// log_info(" *** Added connection with ID %d to spinning thread %d of total
// spinning threads %d ***",
//	 conn->idconn, idx, channel->spinning_num_th);
#endif
}

void ec_sig_handler(int signo)
{
	struct sigaction sa = {};

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = ec_sig_handler;
	sigaction(SIGINT, &sa, 0);
}

/************************************************************
 ***************** spinning thread helper functions ********/
void _zero_rendezvous_locations_l(msg_header *msg, uint32_t length)
{
	void *start_memory;
	void *end_memory;
	assert(length % MESSAGE_SEGMENT_SIZE == 0);
	start_memory = (void *)msg;
	end_memory = start_memory + length;

	while (start_memory < end_memory) {
		((msg_header *)start_memory)->receive = 4;
		//((msg_header *)start_memory)->reply = (void *)0xF40F2;
		//((msg_header *)start_memory)->reply_length = 0;
		*(uint32_t *)(start_memory + (MESSAGE_SEGMENT_SIZE - TU_TAIL_SIZE)) = 0;
		start_memory = start_memory + MESSAGE_SEGMENT_SIZE;
	}
}

void _zero_rendezvous_locations(msg_header *msg)
{
	void *start_memory;
	void *end_memory;
	/*for acks that fit entirely in a header pay_len and padding_and_tail could be
   * 0.
   * This is ok because we want to ommit sending extra useless bytes. However we
   * need to
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
		((msg_header *)start_memory)->receive = 999;
		//((msg_header *)start_memory)->reply = (void *)0xF40F2;
		//((msg_header *)start_memory)->reply_length = 0;
		*(uint32_t *)((start_memory + MESSAGE_SEGMENT_SIZE) - TU_TAIL_SIZE) = 999;
		start_memory = start_memory + MESSAGE_SEGMENT_SIZE;
	}
}

uint32_t wait_for_payload_arrival(msg_header *hdr)
{
	int message_size;
	uint32_t *tail;
	if (hdr->pay_len > 0) {
		message_size = TU_HEADER_SIZE + hdr->pay_len + hdr->padding_and_tail;
		tail = (uint32_t *)(((uint64_t)hdr + TU_HEADER_SIZE + hdr->pay_len + hdr->padding_and_tail) -
				    sizeof(uint32_t));
		/*calculate the address of the tail*/
		// blocking style
		wait_for_value(tail, TU_RDMA_REGULAR_MSG);
		// non-blocking style
		// if (*tail != TU_RDMA_REGULAR_MSG) {
		// 	return 0;
		// }
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
	msg->request_message_local_addr = NULL;

	struct ibv_mr *new_mr = (struct ibv_mr *)msg->data;
	memset(new_mr, 0x00, sizeof(struct ibv_mr));
	new_mr->addr = conn->next_rdma_memory_regions->remote_memory_region->addr;
	new_mr->length = conn->next_rdma_memory_regions->remote_memory_region->length;
	new_mr->rkey = conn->next_rdma_memory_regions->remote_memory_region->rkey;
	DPRINT("addr = %p, length = %lu KB, rkey = %u\n", new_mr->addr, new_mr->length / 1024, new_mr->rkey);
	__send_rdma_message(conn, msg, NULL);
}

void _update_client_rendezvous_location(connection_rdma *conn, int message_size)
{
	if (message_size < MESSAGE_SEGMENT_SIZE)
		message_size = MESSAGE_SEGMENT_SIZE;

	assert(message_size % MESSAGE_SEGMENT_SIZE == 0);
	if ((uint64_t)conn->rendezvous + message_size >= (uint64_t)conn->rdma_memory_regions->remote_memory_buffer +
								 (conn->peer_mr->length - MESSAGE_SEGMENT_SIZE)) {
		conn->rendezvous = conn->rdma_memory_regions->remote_memory_buffer;
		log_info("Silent reset");
	} else
		conn->rendezvous = (void *)((uint64_t)conn->rendezvous + message_size);
}

void _update_rendezvous_location(connection_rdma *conn, int message_size)
{
	assert(message_size % MESSAGE_SEGMENT_SIZE == 0);

	if (conn->type == SERVER_TO_CLIENT_CONNECTION || conn->type == REPLICA_TO_MASTER_CONNECTION) {
		if (message_size < MESSAGE_SEGMENT_SIZE) {
			message_size = MESSAGE_SEGMENT_SIZE;
		}
		if (((uint64_t)conn->rendezvous + message_size) >=
		    ((uint64_t)conn->rdma_memory_regions->remote_memory_buffer +
		     conn->rdma_memory_regions->memory_region_length)) {
			conn->rendezvous = (void *)conn->rdma_memory_regions->remote_memory_buffer;
			// log_info("silent reset");
		} else {
			conn->rendezvous = (void *)((uint64_t)conn->rendezvous + (uint32_t)message_size);
		}
	} else {
		log_fatal("Faulty connection type");
		exit(EXIT_FAILURE);
#if 0
		if (message_size > 0) {
			if (conn->remaining_bytes_in_remote_rdma_region >= message_size) {
				conn->remaining_bytes_in_remote_rdma_region -= message_size;
				conn->rendezvous = (void *)((uint64_t)conn->rendezvous + message_size);
			} else {
				log_info("Just waiting for a RESET_BUFFER");
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
#endif
	}
}

void close_and_free_RDMA_connection(struct channel_rdma *channel, struct connection_rdma *conn)
{
	conn->status = CONNECTION_CLOSING;

	mrpool_free_memory_region(&conn->rdma_memory_regions);

	/*remove connection from its corresponding list*/
	pthread_mutex_lock(&channel->spin_list_conn_lock[conn->responsible_spinning_thread_id]);
	mark_element_for_deletion_from_simple_concurrent_list(conn->responsible_spin_list, conn);
	DPRINT("\t * Removed connection form list successfully :-) \n");
	channel->nconn--;
	channel->nused--;
	pthread_mutex_unlock(&channel->spin_list_conn_lock[conn->responsible_spinning_thread_id]);
	conn->channel = NULL;
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

	// printf("Thread Events CTX\n");fflush(stdout);

	channel = (struct channel_rdma *)args;

	while (1) {
		// printf("Thread Events CTX\n");fflush(stdout);
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

void client_rdma_init_message_context(struct rdma_message_context *msg_ctx, struct msg_header *msg)
{
	memset(msg_ctx, 0, sizeof(*msg_ctx));
	msg_ctx->msg = msg;
	sem_init(&msg_ctx->wait_for_completion, 0, 0);
	msg_ctx->__is_initialized = 1;
}

bool client_rdma_send_message_success(struct rdma_message_context *msg_ctx)
{
	assert(msg_ctx->__is_initialized == 1);
	// on_completion_client will post this semaphore once it gets to the CQE for
	// this message
	sem_wait(&msg_ctx->wait_for_completion);
	assert((uint64_t)msg_ctx == msg_ctx->wc.wr_id);
	if (msg_ctx->wc.status == IBV_WC_SUCCESS)
		return true;
	else
		return false;
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
			log_fatal("polling cq failure reason follows");
			perror("Reason: \n");
			exit(EXIT_FAILURE);
		}
		ibv_ack_cq_events(cq, 1);
		if (ibv_req_notify_cq(cq, 0) != 0) {
			perror("ERROR poll_cq: ibv_req_notify_cq\n");
			exit(-1);
		}

		while (1) {
			rc = ibv_poll_cq(cq, MAX_COMPLETION_ENTRIES, wc);
			if (rc < 0) {
				log_fatal("poll of completion queue failed!");
				exit(EXIT_FAILURE);
			} else if (rc > 0) {
				conn = (connection_rdma *)cq->cq_context;
				assert(conn);
				for (i = 0; i < rc; i++) {
					struct rdma_message_context *msg_ctx =
						(struct rdma_message_context *)wc[i].wr_id;
					if (msg_ctx && msg_ctx->on_completion_callback) {
						memcpy(&msg_ctx->wc, &wc[i], sizeof(struct ibv_wc));
						msg_ctx->on_completion_callback(msg_ctx);
					}
					memset(&wc[i], 0x00, sizeof(struct ibv_wc));
				}
			} else
				break;
		}
	}
	return NULL;
}

void on_completion_server(struct rdma_message_context *msg_ctx)
{
	struct ibv_wc *wc = &msg_ctx->wc;
	struct connection_rdma *conn = (struct connection_rdma *)msg_ctx->args;
	assert(LIBRARY_MODE == SERVER_MODE);
	msg_header *msg;
	if (wc->status == IBV_WC_SUCCESS) {
		switch (wc->opcode) {
		case IBV_WC_SEND:
			// log_info("IBV_WC_SEND code id of connection %d", conn->idconn);
			break;
		case IBV_WC_RECV:
			// log_info("IBV_WC_RECV code id of connection %d", conn->idconn);
			break;
		case IBV_WC_RDMA_WRITE:
			msg = msg_ctx->msg;
			if (msg) {
				switch (msg->type) {
				/*server to client messages*/
				case CLIENT_STOP_NOW:
				case CLIENT_RECEIVED_READY:
					/*do nothing, client handles them*/
					break;
				/*server to server new school*/
				case GET_LOG_BUFFER_REQ:
				case GET_LOG_BUFFER_REP:
				case FLUSH_COMMAND_REQ:
				case FLUSH_COMMAND_REP:
					break;
				/*server to server old school*/
				case SPILL_INIT_ACK:
				case SPILL_COMPLETE_ACK:
				case SPILL_INIT:
				case SPILL_BUFFER_REQUEST:
				case SPILL_COMPLETE:
					free_rdma_local_message(conn);
					break;
				/*client to server RPCs*/
				case DISCONNECT:
					msg->got_send_completion = 1;
					break;
				case SERVER_I_AM_READY:
					break;
				case I_AM_CLIENT:
				case RESET_RENDEZVOUS:
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
		log_fatal("conn type is %d %s\n", conn->type, ibv_wc_status_str(wc->status));
		conn->status = CONNECTION_ERROR;
		raise(SIGINT);
		exit(KREON_FAILURE);
	}

	free(msg_ctx);
}

/* Set as the on_completion_callback for channels in client library mode.
 * It passes the work completion struct to the client through the message's
 * context and posts the
 * semaphore used to block until the message's completion has arrived
 */
void on_completion_client(struct rdma_message_context *msg_ctx)
{
	sem_post(&msg_ctx->wait_for_completion);
	return;
}

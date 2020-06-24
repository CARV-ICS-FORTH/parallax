/**
*  kreon server
 * Created by Pilar Gonzalez-Ferez on 28/07/16.
 * Edited by Giorgos Saloustros <gesalous@ics.forth.gr>, Michalis Vardoulakis <mvard@ics.forth.gr>
 * Copyright (c) 2016 Pilar Gonzalez-Ferez <pilar@ics.forth.gr>.
*
 **/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <limits.h>
#include <stdio.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <alloca.h>
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>

//#include "regions.h"
//#include "prototype.h"
//#include "storage_devices.h"
#include "messages.h"
#include "globals.h"
#include "metadata.h"
#include "../kreon_lib/btree/btree.h"
#include "../kreon_lib/btree/segment_allocator.h"
#include "../kreon_lib/scanner/scanner.h"
//#include "zk_server.h"
#include "../kreon_rdma/rdma.h"

#include "../kreon_lib/scanner/scanner.h"
#include "../kreon_lib/btree/conf.h"
#include "../utilities/queue.h"
#include "../utilities/min_max_heap.h"
#include <log.h>
#include "stats.h"

#ifdef CHECKSUM_DATA_MESSAGES
#include "djb2.h"
#endif

#define TIERING_MAX_CAPACITY 8
#define LOG_SEGMENT_CHUNK 32 * 1024
#define MY_MAX_THREADS 2048

#define WORKER_THREAD_PRIORITIES_NUM 4
#define WORKER_THREAD_HIGH_PRIORITY_TASKS_PER_TURN 1
#define WORKER_THREAD_NORMAL_PRIORITY_TASKS_PER_TURN 1

static int32_t WORKER_THREADS_PER_SPINNING_THREAD;
uint32_t RDMA_LOG_BUFFER_PADDING;
extern uint32_t RDMA_TOTAL_LOG_BUFFER_SIZE;

/*block the socket thread if there's no available memory to allocate to an incoming connection*/
sem_t memory_steal_sem;
volatile memory_region *backup_region = NULL;

extern char *DB_NO_SPILLING;

typedef struct prefix_table {
	char prefix[PREFIX_SIZE];
} prefix_table;

enum work_task_status {
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
};

struct work_task {
	struct channel_rdma *channel;
	struct connection_rdma *conn;
	msg_header *msg;
	void *region; /*sorry, circular dependency was created so I patched it quickly*/
	void *notification_addr;
	msg_header *reply_msg;
	msg_header *flush_segment_request;
	/*used for two puproses (keeping state)
	 * 1. For get it keeps the get result if the  server cannot allocate immediately memory to respond to the client.
	 * This save CPU cycles at the server  because it voids entering kreon each time a stall happens.
	 * 2. For puts it keeps the result of a spill task descriptor
	 */
	void *intermediate_buffer;
	int sockfd; /*from accept() for building connections*/
	int thread_id;
	enum work_task_status kreon_operation_status;
	enum work_task_status allocation_status;
	enum work_task_status overall_status;
};

struct worker_thread {
	struct work_task job_buffers[UTILS_QUEUE_CAPACITY];
	struct work_task high_priority_job_buffers[UTILS_QUEUE_CAPACITY];
	/*queue for empty work_task buffers*/
	utils_queue_s empty_job_buffers_queue;
	utils_queue_s empty_high_priority_job_buffers_queue;

	/* queues for normal priority, high priority*/
	utils_queue_s work_queue;
	utils_queue_s high_priority_queue;

	sem_t sem;
	pthread_t context;
	pthread_spinlock_t work_queue_lock;
	struct channel_rdma *channel;
	worker_status status;
	//struct worker_group *my_group;
	int worker_id;
} worker_thread;

//struct worker_group {
//	int next_server_worker_to_submit_job;
//	int next_client_worker_to_submit_job;
//	struct worker_thread *group;
//};

struct ds_spinning_thread {
	pthread_t spinner_context;
	pthread_mutex_t conn_list_lock;
	SIMPLE_CONCURRENT_LIST *conn_list;
	SIMPLE_CONCURRENT_LIST *idle_conn_list;
	int num_workers;
	int next_server_worker_to_submit_job;
	int next_client_worker_to_submit_job;
	int id;
	struct worker_thread worker[];
};

struct ds_server {
	int num_of_spinning_threads;
	struct ds_spinning_thread spinner[];
};
static struct ds_server *dataserver;

typedef struct spill_task_descriptor {
	pthread_t spill_worker_context;
	bt_spill_request *spill_req;
	/*XXX TODO XXX, add appropriate fields*/
	struct work_task task;
	struct _tucana_region_S *region;
	int standalone;
	volatile enum work_task_status spill_task_status;
} spill_task_descriptor;

#ifdef TIERING
typedef struct replica_tiering_compaction_request {
	pthread_t tiering_compaction_context;
	_tucana_region_S *region;
	int level_id;
} tiering_compaction_request;
void tiering_compaction_worker(void *);
#endif

/*inserts to Kreon and implements the replication logic*/
void insert_kv_pair(struct krm_region_desc *r_desc, void *kv, connection_rdma *rdma_conn, kv_location *location,
		    struct work_task *task, int wait);

static void crdma_server_create_connection_inuse(struct connection_rdma *conn, struct channel_rdma *channel,
						 connection_type type)
{
	/*gesalous, This is the path where it creates the useless memory queues*/
	tu_rdma_init_connection(conn);
	conn->type = type;
	conn->channel = channel;
}

void *socket_thread(void *args)
{
	int next_spinner_to_submit_conn = 0;
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

		conn->status = CONNECTION_OK;
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
		/*choose a spinner and add connection in its list*/
		/**/

		conn->idconn = -1; //what?
		if (next_spinner_to_submit_conn >= dataserver->num_of_spinning_threads)
			next_spinner_to_submit_conn = 0;
		struct ds_spinning_thread *spinner = &dataserver->spinner[next_spinner_to_submit_conn];
		pthread_mutex_lock(&spinner->conn_list_lock);
		/*gesalous new policy*/
		add_last_in_simple_concurrent_list(spinner->conn_list, conn);
		conn->responsible_spin_list = spinner->conn_list;
		conn->responsible_spinning_thread_id = next_spinner_to_submit_conn;

		pthread_mutex_unlock(&spinner->conn_list_lock);
		log_info("Built new connection successfully");
	}
	return NULL;
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
	struct work_task *job = NULL;
	struct worker_thread *worker_descriptor;
	//uint64_t time_elapsed;

	int turn = 0;

	pthread_setname_np(pthread_self(), "worker_thread");
	worker_descriptor = (struct worker_thread *)args;
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
	log_warn("worker thread exited");
	return NULL;
}

static int assign_job_to_worker(struct ds_spinning_thread *spinner, struct connection_rdma *conn, msg_header *msg,
				int sockfd)
{
	struct work_task *job = NULL;
	int worker_id = 0;

	if (conn->worker_id == -1) {
		/*unassigned connection*/
		if (++spinner->next_server_worker_to_submit_job >= spinner->num_workers) {
			spinner->next_server_worker_to_submit_job = 0;
		}
		conn->worker_id = spinner->next_server_worker_to_submit_job;
	}

	if (msg->type == FLUSH_SEGMENT_AND_RESET || msg->type == FLUSH_SEGMENT || msg->type == SPILL_INIT ||
	    msg->type == SPILL_COMPLETE || msg->type == SPILL_BUFFER_REQUEST) {
		/*to ensure FIFO processing , vital for these protocol operations*/

		worker_id = conn->worker_id;
		job = (struct work_task *)utils_queue_pop(
			&spinner->worker[worker_id].empty_high_priority_job_buffers_queue);
		if (job == NULL) {
			//assert(0);
			return KREON_FAILURE;
		}
	} else {
		/*just in case we want to perform different assignment policy based on the priority level*/
		worker_id = conn->worker_id;
		/*DPRINT("Adding job to thread id %d\n",worker_id);*/
		job = (struct work_task *)utils_queue_pop(&spinner->worker[worker_id].empty_job_buffers_queue);
		if (job == NULL) {
			//assert(0);
			return KREON_FAILURE;
		}
	}

	memset(job, 0x0, sizeof(struct work_task));
	job->channel = globals_get_rdma_channel();
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
	case PUT_OFFT_REQUEST:
	case DELETE_REQUEST:
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
		log_fatal("unhandled type");
		assert(0);
		exit(EXIT_FAILURE);
	}

	if (msg->type == FLUSH_SEGMENT_AND_RESET || msg->type == FLUSH_SEGMENT || msg->type == SPILL_INIT ||
	    msg->type == SPILL_COMPLETE || msg->type == SPILL_BUFFER_REQUEST) {
		if (utils_queue_push(&spinner->worker[worker_id].high_priority_queue, (void *)job) == NULL) {
			log_warn(
				"Failed to add CONTROL job of type: %d to queue tried worker %d its status is %llu retrying\n",
				job->msg->type, worker_id, (LLU)spinner->worker[worker_id].status);
			utils_queue_push(&spinner->worker[worker_id].empty_high_priority_job_buffers_queue,
					 (void *)job);
			assert(0);
			return KREON_FAILURE;
		}
	} else {
		/*normal priority*/
		if (utils_queue_push(&spinner->worker[worker_id].work_queue, (void *)job) == NULL) {
			log_warn("Failed to add job of type: %d to queue tried worker %d its status is %llu retrying\n",
				 job->msg->type, worker_id, (LLU)spinner->worker[worker_id].status);
			utils_queue_push(&spinner->worker[worker_id].empty_job_buffers_queue, (void *)job);
			//assert(0);
			return KREON_FAILURE;
		}
	}
	pthread_spin_lock(&spinner->worker[worker_id].work_queue_lock);
	if (spinner->worker[worker_id].status == IDLE_SLEEPING) {
		/*wake him up */
		// DPRINT("Boom\n");
		++wake_up_workers_operations;
		sem_post(&spinner->worker[worker_id].sem);
	}
	pthread_spin_unlock(&spinner->worker[worker_id].work_queue_lock);
	return KREON_SUCCESS;
}

void _update_connection_score(int spinning_list_type, connection_rdma *conn)
{
	if (spinning_list_type == HIGH_PRIORITY)
		conn->idle_iterations = 0;
	else
		++conn->idle_iterations;
}

static void *server_spinning_thread_kernel(void *args)
{
	struct msg_header *hdr;

	SIMPLE_CONCURRENT_LIST_NODE *node;
	SIMPLE_CONCURRENT_LIST_NODE *prev_node;
	SIMPLE_CONCURRENT_LIST_NODE *next_node;

	struct sigaction sa = {};
	struct ds_spinning_thread *spinner = (struct ds_spinning_thread *)args;
	struct connection_rdma *conn;

	uint32_t message_size;
	volatile uint32_t recv;

	int spinning_thread_id = spinner->id;
	int spinning_list_type;
	int rc;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = ec_sig_handler;

	pthread_t self;
	self = pthread_self();
	pthread_setname_np(self, "SPINNING_THREAD");

	int count = 0;

	while (1) {
		/*in cases where there are no connections stop spinning (optimization)*/
		//if (!channel->spin_num[spinning_thread_id])
		//	sem_wait(&channel->sem_spinning[spinning_thread_id]);

		/*gesalous, iterate the connection list of this channel for new messages*/
		if (count < 10) {
			node = spinner->conn_list->first;
			spinning_list_type = HIGH_PRIORITY;
		} else {
			node = spinner->idle_conn_list->first;
			spinning_list_type = LOW_PRIORITY;
			count = 0;
		}

		prev_node = NULL;

		while (node != NULL) {
			conn = (connection_rdma *)node->data;

			if (conn->status != CONNECTION_OK)
				goto iterate_next_element;

			hdr = (msg_header *)conn->rendezvous;
			recv = hdr->receive;

			/*messages belonging to data path category*/
			if (recv == TU_RDMA_REGULAR_MSG) {
				_update_connection_score(spinning_list_type, conn);
				message_size = wait_for_payload_arrival(hdr);
				if (message_size == 0) {
					/*payload have not arrived yet check next connection*/
					goto iterate_next_element;
				}
				__sync_fetch_and_add(&conn->pending_received_messages, 1);

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
						log_info("wake up thread FLUSH_SEGMENT_ACK arrived");
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
					rc = assign_job_to_worker(spinner, conn, hdr, -1);
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

				rc = assign_job_to_worker(spinner, conn, hdr, -1);
				/*all workers are busy returns KREON_FAILURE*/
				if (rc != KREON_FAILURE) {
					hdr->receive =
						0; /*responsible worker will zero and update rendevous locations*/
				}
				goto iterate_next_element;
				/*rendezvous will by changed by the worker!*/
			} else if (recv == CONNECTION_PROPERTIES) {
				message_size = wait_for_payload_arrival(hdr);
				if (message_size == 0) {
					/*payload have not arrived yet check next connection*/
					goto iterate_next_element;
				}

				if (hdr->type == DISCONNECT) {
					// Warning! the guy that consumes/handles the message is responsible for zeroing
					// the message's segments for possible future rendezvous points. This is done
					// inside free_rdma_received_message function

					log_info("Disconnect operation bye bye mr Client garbage collection follows\n");
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
					log_warn("Remote side wants to change its connection properties\n");
					set_connection_property_req *req = (set_connection_property_req *)hdr->data;

					if (req->desired_priority_level == HIGH_PRIORITY) {
						log_warn("Remote side wants to pin its connection\n");
						/*pin this conn bitches!*/
						conn->priority = HIGH_PRIORITY;
						msg_header *reply = allocate_rdma_message(
							conn, 0, CHANGE_CONNECTION_PROPERTIES_REPLY);
						reply->request_message_local_addr = hdr->request_message_local_addr;
						send_rdma_message(conn, reply);

						if (spinning_list_type == LOW_PRIORITY) {
							log_warn("Upgrading its connection\n");
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
					log_fatal("unknown message type for connetion properties unknown type is %d\n",
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
				log_info("SERVER: We have a new client control location %llu",
					 (LLU)conn->control_location);
				_zero_rendezvous_locations(hdr);
				_update_rendezvous_location(conn, MESSAGE_SEGMENT_SIZE);
				goto iterate_next_element;
			} else if (recv == SERVER_I_AM_READY) {
				conn->status = CONNECTION_OK;
				hdr->receive = 0;
				conn->control_location = hdr->data;

				log_info("Received SERVER_I_AM_READY at %llu\n", (LLU)conn->rendezvous);
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

		iterate_next_element:
			if (node->marked_for_deletion) {
				log_warn("garbage collection");
				pthread_mutex_lock(&spinner->conn_list_lock);
				next_node = node->next; /*Caution prev_node remains intact*/
				if (spinning_list_type == HIGH_PRIORITY)
					delete_element_from_simple_concurrent_list(spinner->conn_list, prev_node, node);
				else
					delete_element_from_simple_concurrent_list(spinner->idle_conn_list, prev_node,
										   node);
				node = next_node;
				pthread_mutex_unlock(&spinner->conn_list_lock);
			}

			else if (0
				 /*spinning_list_type == HIGH_PRIORITY &&
						conn->priority != HIGH_PRIORITY &&//we don't touch high priority connections
						conn->idle_iterations > MAX_IDLE_ITERATIONS*/) {
				log_warn("Downgrading connection...");
				pthread_mutex_lock(&spinner->conn_list_lock);
				next_node = node->next; /*Caution prev_node remains intact*/
				remove_element_from_simple_concurrent_list(spinner->conn_list, prev_node, node);
				add_node_in_simple_concurrent_list(spinner->idle_conn_list, node);
				conn->responsible_spin_list = spinner->idle_conn_list;
				conn->idle_iterations = 0;
				node = next_node;
				pthread_mutex_unlock(&spinner->conn_list_lock);
				log_warn("Downgrading connection...D O N E ");
			}

			else if (spinning_list_type == LOW_PRIORITY && conn->idle_iterations > MAX_IDLE_ITERATIONS) {
			upgrade_connection:
				log_warn("Upgrading connection...");
				pthread_mutex_lock(&spinner->conn_list_lock);
				next_node = node->next; /*Caution prev_node remains intact*/
				remove_element_from_simple_concurrent_list(spinner->idle_conn_list, prev_node, node);
				add_node_in_simple_concurrent_list(spinner->conn_list, node);
				conn->responsible_spin_list = spinner->conn_list;
				conn->idle_iterations = 0;
				node = next_node;
				pthread_mutex_unlock(&spinner->conn_list_lock);
				log_warn("Upgrading connection...D O N E");
			} else {
				prev_node = node;
				node = node->next;
			}
		}
	}
	log_warn("Server Spinning thread %d exiting", spinning_thread_id);
	return NULL;
}

#if 0
/*functions for building index at replicas*/
void _calculate_btree_index_nodes(_tucana_region_S *region, uint64_t num_of_keys);
void append_entry_to_leaf_node(_tucana_region_S *region, void *pointer_to_kv_pair, void *prefix, int32_t tree_id);
struct node_header *_create_tree_node(struct _tucana_region_S *region, int tree_id, int node_height, int type);
void _append_pivot_to_index(_tucana_region_S *region, node_header *left_brother, void *pivot,
			    node_header *right_brother, int tree_id, int node_height);
#endif
pthread_mutex_t reg_lock; /*Lock for the conn_list*/

//extern _tuzk_server tuzk_S;
//extern _RegionsSe regions_S;
//extern tu_storage_device storage_dev;
//char *Device_name = NULL;
//uint64_t Device_size = 0;

/*
 * protocol that threads use to inform the system that they perform
 * a region operation (insert,get,delete). Crucial for the case where
 * regions are destroyed due to failures of another server or
 * some elastic operation
 * */
#define ENTERED_REGION 0x02
#define EXITED_REGION 0x03
#define THROTTLE 2048

struct msg_header *handle_scan_request(struct msg_header *data_message, void *connection);
struct msg_header *Server_Handling_Received_Message(struct msg_header *data_message, int reg_num, int next_mail);
int handle_put_request(msg_header *data_message, connection_rdma *rdma_conn);

#if 0
_tucana_region_S *get_region(void *key, int key_len)
{
	//_tucana_region_S * region = (_tucana_region_S *)find_region_min_key_on_rbtree( &regions_S.tree, key, key_len);
	_tucana_region_S *region = find_region(key, key_len);
	if (region == NULL) {
		DPRINT("FATAL region not found\n");
		exit(EXIT_FAILURE);
	}
	return region;
}
#endif

static void kreonR_spill_worker(void *_spill_task_desc)
{
//gesalous leave it for later
#if 0
	kv_location location;
	spill_task_descriptor *spill_task_desc = (spill_task_descriptor *)_spill_task_desc;
	bt_spill_request *spill_req = spill_task_desc->spill_req;
	msg_header *msg = NULL;
	msg_header *spill_buffer_msg = NULL;
	void *spill_buffer;
	uint64_t log_addr;
	msg_header *reply = NULL;
	level_scanner *level_sc = NULL;

	void *free_addr;
	uint64_t size;
	void *addr;
	uint32_t region_key_len;
	uint32_t keys_batch_to_spill;
	uint32_t num_of_spilled_keys;
	int i;
	int rc;

	while (1) {
		switch (spill_task_desc->spill_task_status) {
		case SEND_SPILL_INIT:

			assert(spill_task_desc->standalone == 0);
			log_info("MASTER: Sending spill init to replica\n");

			region_key_len = *(uint32_t *)spill_task_desc->region->ID_region.minimum_range;
			msg = __allocate_rdma_message(spill_task_desc->region->replica_next_control_con,
						      28 + region_key_len, SPILL_INIT, ASYNCHRONOUS, 0,
						      &spill_task_desc->task);
			if (spill_task_desc->task.allocation_status != ALLOCATION_SUCCESS) {
				DPRINT("allocation rollback\n");
				if (pthread_yield() != 0) {
					DPRINT("FATAL yield failed\n");
				}
				break;
			}
			/*reset the status flag for subsequent operations*/
			spill_task_desc->task.allocation_status = ALLOCATION_START;

			addr = msg->data;
			/*command */
			*(uint32_t *)addr = region_key_len;
			addr += sizeof(int32_t);
			/*region key for replica to locate the corresponding region*/
			memcpy(addr, spill_task_desc->region->ID_region.minimum_range + sizeof(uint32_t),
			       region_key_len);
			addr += region_key_len;
			/*L0 start*/
			*(uint64_t *)addr = spill_task_desc->spill_req->l0_start;
			addr += sizeof(uint64_t);
			/*L0 end*/
			*(uint64_t *)addr = spill_task_desc->spill_req->l0_end;
			addr += sizeof(uint64_t);
			/*total keys to spill*/
			log_info("keys from level:%u tree:%u to spill are are %llu\n", spill_req->src_level,
				 spill_req->src_tree,
				 spill_req->db_desc->levels[spill_req->src_tree].total_keys[spill_req->src_tree]);
			*(uint64_t *)addr =
				spill_req->db_desc->levels[spill_req->src_level].total_keys[spill_req->src_tree];
			addr += sizeof(uint64_t);
			msg->next = addr;
			msg->request_message_local_addr = msg; /*info to spinning thread to wake us up on reply*/
			msg->reply_message = NULL;
			if (send_rdma_message(spill_task_desc->region->replica_next_control_con, msg) !=
			    KREON_SUCCESS) {
				log_info("failed to send message\n");
				exit(EXIT_FAILURE);
			}
			log_info(
				"Sent spill init command to replica to region: %s payload len %u waiting for reply...\n",
				spill_task_desc->region->ID_region.minimum_range + 4, 24 + region_key_len);
			spill_task_desc->spill_task_status = WAIT_FOR_SPILL_INIT_REPLY;
			break;

		case WAIT_FOR_SPILL_INIT_REPLY:

			if (msg->reply_message == NULL) {
				if (pthread_yield() != 0) {
					DPRINT("FATAL yield failed\n");
				}
				break;
			}
			reply = (msg_header *)msg->reply_message;

			if (reply->error_code == KREON_OK) {
				log_info("MASTER: Replica ready to participate in spill :-)\n");
			} else if (reply->error_code == REPLICA_PENDING_SPILL) {
				log_info("FATAL: Replica has unfinished spills, what are you going to do gesalous?\n");
				exit(EXIT_FAILURE);
			} else {
				log_info("FATAL Unknown code\n");
				raise(SIGINT);
				exit(EXIT_FAILURE);
			}
			free_rdma_received_message(spill_task_desc->region->replica_next_control_con, reply);
			spill_task_desc->spill_task_status = INIT_SPILL_BUFFER_SCANNER;
			log_info("MASTER: got SPILL_INIT reply!\n");
			break;

		case INIT_SPILL_BUFFER_SCANNER:

			DPRINT("MASTER: INIT_SPILL_BUFFER_SCANNER!\n");
			level_sc = _init_spill_buffer_scanner(spill_task_desc->region->db, spill_req->src_root,
							      spill_req->start_key);

			assert(level_sc != NULL);
			keys_batch_to_spill =
				(SPILL_BUFFER_SIZE - (2 * sizeof(uint32_t))) / (PREFIX_SIZE + sizeof(uint64_t));
			spill_task_desc->spill_task_status = SPILL_BUFFER_REQ;
			break;

		case SPILL_BUFFER_REQ:

			if (!spill_task_desc->standalone) {
				/*allocate buffer*/
				spill_buffer_msg =
					__allocate_rdma_message(spill_task_desc->region->replica_next_control_con,
								SPILL_BUFFER_SIZE, SPILL_BUFFER_REQUEST, ASYNCHRONOUS,
								0, &spill_task_desc->task);
				if (spill_task_desc->task.allocation_status != ALLOCATION_SUCCESS) {
					if (pthread_yield() != 0) {
						DPRINT("FATAL yield failed\n");
					}
					break;
				}
				spill_buffer = spill_buffer_msg->data;
				spill_buffer += sizeof(uint32_t); /*keep 4 bytes for num of entries*/
				/*reset the status flag for subsequent operations*/
				spill_task_desc->task.allocation_status = ALLOCATION_START;
			}
			num_of_spilled_keys = 0;
			bt_insert_req req;
			for (i = 0; i < keys_batch_to_spill; i++) {
				location.kv_addr = level_sc->keyValue;
				location.log_offset = 0; /*unused*/
				req.handle = spill_task_desc->region->db;
				req.key_value_buf = level_sc->keyValue;
				req.level_id = spill_req->dst_level;
				req.tree_id = spill_req->dst_tree;
				req.key_format = KV_PREFIX;
				req.append_to_log = 0;
				req.gc_request = 0;
				req.recovery_request = 0;
				_insert_key_value(&req);

				if (!spill_task_desc->standalone) {
					/*for the replica prefix*/
					memcpy(spill_buffer, level_sc->keyValue, PREFIX_SIZE);
					spill_buffer += PREFIX_SIZE;
					/*relative log address*/
					log_addr = (*(uint64_t *)(level_sc->keyValue + PREFIX_SIZE)) - MAPPED;
					memcpy(spill_buffer, &log_addr, sizeof(uint64_t));
					spill_buffer += sizeof(uint64_t);
					++num_of_spilled_keys;
				}

				rc = _get_next_KV(level_sc);
				if (rc == END_OF_DATABASE) {
					if (!spill_task_desc->standalone) {
						spill_task_desc->spill_task_status = SEND_SPILL_COMPLETE;
						break;
					} else {
						spill_task_desc->spill_task_status = CLOSE_SPILL_BUFFER;
						break;
					}
				}
			}

			if (!spill_task_desc->standalone) {
				*(uint32_t *)spill_buffer_msg->data = num_of_spilled_keys;
				if (send_rdma_message(spill_task_desc->region->replica_next_control_con,
						      spill_buffer_msg) != KREON_SUCCESS) {
					DPRINT("FATAL failed message\n");
					exit(EXIT_FAILURE);
				} else {
					//DPRINT("MASTER: Just send buffer for spill with keys %d\n",num_of_spilled_keys);
				}
			}

			break;

		case CLOSE_SPILL_BUFFER:

			_close_spill_buffer_scanner(level_sc, spill_task_desc->spill_req->src_root);
			/*sanity check
					if(spilled_keys != db_desc->total_keys[spill_req->src_tree_id]){
					printf("[%s:%s:%d] FATAL keys missing --- spilled keys %llu actual %llu spiller id %d\n",__FILE__,__func__,__LINE__,(LLU)spilled_keys,(LLU)db_desc->total_keys[spill_req->src_tree_id], spill_req->src_tree_id);
					exit(EXIT_FAILURE);
					}
					*/

			/*Clean up code, Free the buffer tree was occupying. free_block() used intentionally*/
			__sync_fetch_and_sub(&spill_task_desc->region->db->db_desc->levels[spill_req->src_level]
						      .outstanding_spill_ops,
					     1);
			assert(spill_task_desc->region->db->db_desc->levels[spill_req->src_level]
				       .outstanding_spill_ops == 0);

			if (spill_task_desc->region->db->db_desc->levels[spill_req->src_level].outstanding_spill_ops ==
			    0) {
				seg_free_level(spill_task_desc->region->db, spill_req->src_level, spill_req->src_tree);
				if (spill_req->src_level == 0) {
					spill_task_desc->region->db->db_desc->levels[0].level_size = 0;
					spill_task_desc->region->db->db_desc->L0_start_log_offset = spill_req->l0_end;
				}
				spill_task_desc->region->db->db_desc->levels[spill_req->src_level]
					.tree_status[spill_req->src_tree] = NO_SPILLING;
			}
			free(spill_task_desc);
			log_info("MASTER spill finished and cleaned remains\n");
			return;

		case SEND_SPILL_COMPLETE:
			assert(spill_task_desc->region->replica_next_control_con != NULL);

			region_key_len = *(uint32_t *)spill_task_desc->region->ID_region.minimum_range;

			msg = __allocate_rdma_message(spill_task_desc->region->replica_next_control_con,
						      20 + region_key_len, SPILL_COMPLETE, ASYNCHRONOUS, 0,
						      &spill_task_desc->task);
			if (spill_task_desc->task.allocation_status != ALLOCATION_SUCCESS) {
				if (pthread_yield() != 0) {
					DPRINT("FATAL yield failed\n");
				}
				break;
			}

			DPRINT("MASTER: Sending SPILL_COMPLETE message to REPLICA\n");
			spill_task_desc->task.allocation_status = ALLOCATION_START;

			addr = msg->data;
			*(uint32_t *)addr = region_key_len;
			addr += sizeof(int32_t);
			memcpy(addr, spill_task_desc->region->ID_region.minimum_range + sizeof(uint32_t),
			       region_key_len);
			addr += region_key_len;
			*(uint64_t *)addr = spill_task_desc->spill_req.l0_start;
			addr += sizeof(uint64_t);
			*(uint64_t *)addr = spill_task_desc->spill_req.l0_end;
			addr += sizeof(uint64_t);
			msg->next = addr;
			msg->request_message_local_addr = msg;
			msg->reply_message = NULL;
			if (send_rdma_message(spill_task_desc->region->replica_next_control_con, msg) !=
			    KREON_SUCCESS) {
				DPRINT("FATAL to send spill complete message\n");
				exit(EXIT_FAILURE);
			}
			spill_task_desc->spill_task_status = WAIT_FOR_SPILL_COMPLETE_REPLY;
			break;

		case WAIT_FOR_SPILL_COMPLETE_REPLY:
			//DPRINT("MASTER: Waiting for SPILL_COMPLETE reply\n");
			if (msg->reply_message == NULL) {
				if (pthread_yield() != 0) {
					DPRINT("FATAL yield failed\n");
				}
				break;
			}
			reply = (msg_header *)msg->reply_message;

			if (reply == NULL) {
				DPRINT("FATAL reply to spill buffer request is NULL\n");
				exit(EXIT_FAILURE);
			}

			if (reply->error_code == KREON_OK) {
				DPRINT("Replica completed remote spill\n");
				free_rdma_received_message(spill_task_desc->region->replica_next_control_con, reply);
				spill_task_desc->spill_task_status = CLOSE_SPILL_BUFFER;
				/*DO THE CLEANINING HERE, and exit thread*/
				DPRINT("Master: Replica informed that it finished its spill\n");
				break;
			} else if (reply->error_code == REPLICA_PENDING_SPILL) {
				DPRINT("FATAL: Replica has unfinished spills, what are you going to do gesalous?\n");
				exit(EXIT_FAILURE);
			} else {
				DPRINT("Unknown spill completion code\n");
				exit(EXIT_FAILURE);
			}
		default:
			DPRINT("FATAL unkown state for spill task\n");
			exit(EXIT_FAILURE);
		}
	}
#endif
}

#ifdef TIERING
void tiering_compaction_check(_tucana_region_S *region, int level_id)
{
	tiering_compaction_request *request;
	db_descriptor *db_desc = region->db->db_desc;
	int level_max_capacity = 4;
	int level_size = 0;
	int i;

	/*check if level 1 capacity is full*/
	for (i = 0; i < level_max_capacity; i++) {
		if (db_desc->replica_forest.tree_roots[(level_id * level_max_capacity) + i] != NULL) {
			++level_size;
		}
	}

	if (level_size >= level_max_capacity) {
		request = (tiering_compaction_request *)malloc(sizeof(tiering_compaction_request));
		request->region = region;
		request->level_id = 0;
		DPRINT("REPLICA: Time for a tiering compaction\n");
		db_desc->db_mode = BACKUP_DB_TIERING_COMPACTION;
		pthread_setname_np(request->tiering_compaction_context, "replica_tiering_worker");
		if (pthread_create(&request->tiering_compaction_context, NULL, (void *)tiering_compaction_worker,
				   (void *)request) != 0) {
			DPRINT("FATAL: error spawning tiering compaction worker\n");
			exit(EXIT_FAILURE);
		}
	}
}

void tiering_compaction_worker(void *_tiering_request)
{
	tiering_compaction_request *request;
	min_heap *heap = create_and_initialize_heap(TIERING_MAX_CAPACITY);
	min_heap_node node;
	uint64_t total_keys_to_compact;
	uint64_t actual_compacted_keys;
	int destination_tree_id;
	int i;
	int rc;
	int scanner_id;
	int empty_scanners_num = 0;

	request = (tiering_compaction_request *)_tiering_request;

	level_scanner **scanners = (level_scanner **)alloca(sizeof(level_scanner *) * TIERING_MAX_CAPACITY);
	total_keys_to_compact = 0;
	actual_compacted_keys = 0;

	for (i = 0; i < TIERING_MAX_CAPACITY; i++) {
		total_keys_to_compact += request->region->db->db_desc->replica_forest
						 .total_keys_per_tree[(request->level_id * TIERING_MAX_CAPACITY) + i];
		scanners[i] =
			_init_spill_buffer_scanner(request->region->db,
						   request->region->db->db_desc->replica_forest
							   .tree_roots[(request->level_id * TIERING_MAX_CAPACITY) + i],
						   NULL);
		add_to_min_heap(heap, scanners[i]->keyValue, KV_PREFIX, (request->level_id * TIERING_MAX_CAPACITY) + i);
	}
	/*now find an available tree in the id+1 level*/
	destination_tree_id = -1;
	for (i = 0; i < TIERING_MAX_CAPACITY; i++) {
		if (request->region->db->db_desc->replica_forest
			    .tree_roots[((request->level_id + 1) * TIERING_MAX_CAPACITY) + i] == NULL) {
			destination_tree_id = ((request->level_id + 1) * TIERING_MAX_CAPACITY) + i;
			break;
		}
	}
	assert(destination_tree_id != -1);

	DPRINT("REPLICA: Tiering compaction from level %d to level %d number of keys to compact = %" PRIu64 "\n",
	       request->level_id, request->level_id + 1, total_keys_to_compact);
	_calculate_btree_index_nodes(request->region, total_keys_to_compact);

	while (empty_scanners_num > 0) {
		node = pop_min(heap);
		++actual_compacted_keys;
		append_entry_to_leaf_node(request->region, node.keyValue + PREFIX_SIZE, node.keyValue,
					  destination_tree_id);
		scanner_id = node.tree_id - (request->level_id * TIERING_MAX_CAPACITY);
		rc = _get_next_KV(scanners[scanner_id]);
		if (rc == END_OF_DATABASE) {
			scanners[scanner_id] = NULL;
			++empty_scanners_num;
		}
	}
	assert(actual_compacted_keys == total_keys_to_compact);
	request->region->db->db_desc->replica_forest.tree_status[destination_tree_id] = READY_TO_PERSIST;
	DPRINT("REPLICA: Tiering compaction from level to level maybe a snapshot now? XXX TODO XXX\n");
	request->region->db->db_desc->db_mode = BACKUP_DB_NO_PENDING_SPILL;

	tiering_compaction_check(request->region, request->level_id + 1);
	free(_tiering_request);
}
#endif

int _ks_init_replica_rdma_connections(struct krm_region_desc *r_desc)
{
	char *host;
	int i;
	if (r_desc->role == KRM_BACKUP || r_desc->region->num_of_backup == 0) {
		r_desc->init_rdma_conn = 0;
		r_desc->r_state = NULL;
		return KREON_SUCCESS;
	}
	r_desc->r_state = (struct ru_replication_state *)malloc(sizeof(struct ru_replication_state));
	r_desc->r_state->data_conn =
		(struct connection_rdma **)malloc(sizeof(struct connection_rdma *) * r_desc->region->num_of_backup);
	r_desc->r_state->control_conn =
		(struct connection_rdma **)malloc(sizeof(struct connection_rdma *) * r_desc->region->num_of_backup);
	log_info("Primary: Creating replica connections for region range %s", r_desc->region->max_key);

	for (i = 0; i < r_desc->region->num_of_backup; i++) {
		host = r_desc->region->backups[i].RDMA_IP_addr;
		r_desc->r_state->data_conn[i] = crdma_client_create_connection_list_hosts(
			globals_get_rdma_channel(), &host, 1, MASTER_TO_REPLICA_DATA_CONNECTION);

		/*fix replica buffer staff*/
		r_desc->r_state->master_rep_buf =
			(struct ru_replica_log_buffer *)malloc(sizeof(struct ru_replica_log_buffer));
		/*valid range for start-end log offset this segment covers*/
		r_desc->r_state->master_rep_buf->bounds[0].start =
			r_desc->db->db_desc->KV_log_size - (r_desc->db->db_desc->KV_log_size % SEGMENT_SIZE);
		r_desc->r_state->master_rep_buf->bounds[0].end =
			r_desc->r_state->master_rep_buf->bounds[0].start + SEGMENT_SIZE;
		/*bytes written in this segment*/
		r_desc->r_state->master_rep_buf->seg_bufs[0].bytes_wr_per_seg = 0;

		r_desc->r_state->master_rep_buf->seg_bufs[0].rdma_local_buf =
			(struct ru_rdma_buffer *)r_desc->r_state->data_conn[i]->rdma_memory_regions->local_memory_buffer;
		r_desc->r_state->master_rep_buf->seg_bufs[0].rdma_local_buf =
			(struct ru_rdma_buffer *)r_desc->r_state->data_conn[i]
				->rdma_memory_regions->remote_memory_buffer;
	}

	for (i = 1; i < RU_REPLICA_NUM_SEGMENTS; i++) {
		r_desc->r_state->master_rep_buf->bounds[i].start = 0;
		r_desc->r_state->master_rep_buf->bounds[i].end = 0;
		r_desc->r_state->master_rep_buf->seg_bufs[i].bytes_wr_per_seg = 0;
		r_desc->r_state->master_rep_buf->seg_bufs[i].rdma_local_buf =
			(struct ru_rdma_buffer *)((uint64_t)r_desc->r_state->master_rep_buf->seg_bufs[i - 1]
							  .rdma_local_buf +
						  sizeof(struct ru_rdma_buffer));
		r_desc->r_state->master_rep_buf->seg_bufs[i].rdma_remote_buf =
			(struct ru_rdma_buffer *)((uint64_t)r_desc->r_state->master_rep_buf->seg_bufs[i - 1]
							  .rdma_local_buf +
						  sizeof(struct ru_rdma_buffer));
		r_desc->r_state->data_conn[i]->priority = HIGH_PRIORITY;
	}

	for (i = 0; i < r_desc->region->num_of_backup; i++) {
		log_info("MASTER: Creating control connection for region range %s\n", r_desc->region->min_key);
		r_desc->r_state->control_conn[i] = r_desc->r_state->data_conn[i] =
			crdma_client_create_connection_list_hosts(globals_get_rdma_channel(), &host, 1,
								  MASTER_TO_REPLICA_CONTROL_CONNECTION);

		r_desc->r_state->control_conn[i]->priority = HIGH_PRIORITY;
		log_info("MASTER: replica data and control connection created successfuly");
		/*allocate remote log buffer*/
		log_info("MASTER: Allocating and initializing remote log buffer");

		msg_header *tmp = (msg_header *)r_desc->r_state->data_conn[0]->rdma_memory_regions->local_memory_buffer;

		/*init message*/
		tmp->pay_len = 4096 + BUFFER_SEGMENT_SIZE;
		tmp->padding_and_tail = RDMA_LOG_BUFFER_PADDING + TU_TAIL_SIZE; //???
		DPRINT("TOTAL LOG BUFFER SIZE %d Padding %d\n", RDMA_TOTAL_LOG_BUFFER_SIZE, RDMA_LOG_BUFFER_PADDING);
		tmp->data = (void *)((uint64_t)tmp + TU_HEADER_SIZE);
		tmp->next = tmp->data;
		tmp->receive = TU_RDMA_REGULAR_MSG;
		/*set the tail to the proper value*/
		*(uint32_t *)((uint64_t)tmp + TU_HEADER_SIZE + 4096 + BUFFER_SEGMENT_SIZE + RDMA_LOG_BUFFER_PADDING) =
			TU_RDMA_REGULAR_MSG;
		tmp->type = FLUSH_SEGMENT;
		tmp->local_offset = 0;
		tmp->remote_offset = 0;

		tmp->ack_arrived = KR_REP_PENDING;
		tmp->callback_function = NULL;
		tmp->request_message_local_addr = NULL;
		__sync_fetch_and_add(&r_desc->r_state->data_conn[0]->pending_sent_messages, 1);
		/*set connection propeties with the replica
		 *	1. pin data and control conn to high priority
		 *	2. Reduce memory for control conn
		 */
		/*
			 DPRINT("Setting connection properties with the Replica");
			 set_connection_property_req * req;
			 msg_header * data_conn_req = allocate_rdma_message(*S_tu_region->db->db_desc->data_conn, sizeof(set_connection_property_req),CHANGE_CONNECTION_PROPERTIES_REQUEST);
			 req = (set_connection_property_req *)data_conn_req->data;
			 req->desired_priority_level = HIGH_PRIORITY;
			 req->desired_RDMA_memory_size = DEFAULT_MEMORY_SIZE_OPTION;
			 data_conn_req->request_message_local_addr = (void *)data_conn_req;
			 send_rdma_message(*S_tu_region->db->db_desc->data_conn, data_conn_req);
			 int i = 0;
			 while(data_conn_req->ack_arrived != REPLY_ARRIVED){
			 if(++i%100000 == 0){
			 DPRINT("Waiting for the remote side to pin my connection\n");
			 }
			 }

			 msg_header * control_conn_req = allocate_rdma_message(*S_tu_region->db->db_desc->data_conn, sizeof(set_connection_property_req),CHANGE_CONNECTION_PROPERTIES_REQUEST);
			 req = (set_connection_property_req *)control_conn_req->data;
			 req->desired_priority_level = HIGH_PRIORITY;
			 req->desired_RDMA_memory_size = CONTROL_CONNECTION_MEMORY_SIZE;

			 control_conn_req->request_message_local_addr = (void *)control_conn_req;
			 send_rdma_message(*S_tu_region->db->db_desc->data_conn, control_conn_req);
			 i = 0;
			 while(control_conn_req->ack_arrived != REPLY_ARRIVED){
			 if(++i%100000 == 0){
			 DPRINT("Waiting for the remote side to pin my connection\n");
			 }
			 }
			 DPRINT("Setting connection properties with the Replica ... DONE");
			 */
	}
	return KREON_SUCCESS;
}

/*
 * This functions handle PUT_QUERY requests which contain a single key value
 * put operation task states that this function must handle
 INITIAL_STATE
 WAIT_FOR_REPLICA_TO_FLUSH_REGION
 WAIT_FOR_REPLICA_CONNECTION_TO_RESET
 CHECK_FOR_REPLICA_FLUSH_SEGMENT_ACK
 CHECK_FOR_REPLICA_RESET_BUFFER_ACK
 APPEND_SUCCESS
 */
void insert_kv_pair(struct krm_region_desc *r_desc, void *kv, connection_rdma *rdma_conn, kv_location *location,
		    struct work_task *task, int wait)
{
	char *key;
	struct ru_replica_log_segment *curr_seg;
	uint32_t key_length;
	uint32_t value_length;
	uint32_t kv_size;

	int32_t seg_id = -1;
	int32_t i = 0;

	void *rdma_src;
	void *rdma_dst;
	key = kv;
	key_length = *(uint32_t *)key;

	value_length = *(uint32_t *)(key + sizeof(uint32_t) + key_length);
	kv_size = (2 * sizeof(uint32_t)) + key_length + value_length;
	location->rdma_key = rdma_conn->rdma_memory_regions->remote_memory_region->lkey;

	bt_insert_req req;

	/*############## fsm state logic follows ###################*/
	while (1) {
		switch (task->kreon_operation_status) {
		case APPEND_START:

			req.metadata.handle = r_desc->db;
			req.metadata.kv_size = kv_size;
			req.key_value_buf = kv;
			req.metadata.level_id = 0;
			req.metadata.key_format = KV_FORMAT;
			req.metadata.append_to_log = 1;
			req.metadata.gc_request = 0;
			req.metadata.recovery_request = 0;
			req.metadata.segment_full_event = 0;
			_insert_key_value(&req);
			if (r_desc->region->num_of_backup > 0) {
				/*We have a replica to feed*/
				if (req.metadata.segment_full_event) {
					/*find the log segment that corresponds to this full event*/
					seg_id = -1;
					for (i = 0; i < RU_REPLICA_NUM_SEGMENTS; i++) {
						if (r_desc->r_state->master_rep_buf->bounds[i].start <=
							    req.metadata.log_offset_full_event &&
						    r_desc->r_state->master_rep_buf->bounds[i].end >
							    req.metadata.log_offset_full_event) {
							seg_id = i;
							break;
						}
					}
					if (seg_id == -1) {
						log_fatal("Corrupted replica log buffer");
						exit(EXIT_FAILURE);
					}
					uint32_t next_buffer;
					uint8_t msg_type;
					if (seg_id == RU_REPLICA_NUM_SEGMENTS - 1) {
						next_buffer = 0;
						msg_type = FLUSH_SEGMENT_AND_RESET;
					} else {
						next_buffer = seg_id + 1;
						msg_type = FLUSH_SEGMENT;
					}

					/*Now,wait until next buffer is available, server spinning thread updates this field*/
					curr_seg = &r_desc->r_state->master_rep_buf->seg_bufs[next_buffer];
					spin_loop(&curr_seg->buffer_free, 1);
					/*mark it now as in use*/
					curr_seg->buffer_free = 0;
					/*fix its new boundaries*/
					r_desc->r_state->master_rep_buf->bounds[next_buffer].start =
						req.metadata.segment_id * SEGMENT_SIZE;
					r_desc->r_state->master_rep_buf->bounds[next_buffer].end =
						r_desc->r_state->master_rep_buf->bounds[next_buffer].start +
						SEGMENT_SIZE;

					/*ok others are ready to proceed, now let's wake up replica*/
					curr_seg = &r_desc->r_state->master_rep_buf->seg_bufs[seg_id];
					uint32_t bytes_threashold =
						SEGMENT_SIZE - (sizeof(segment_header) + req.metadata.log_padding);
					/*wait until all bytes of segment are written*/
					spin_loop(&curr_seg->bytes_wr_per_seg, bytes_threashold);
					/*prepare segment metadata for replica*/
					curr_seg->rdma_local_buf->metadata.master_segment =
						req.metadata.log_segment_addr;
					curr_seg->rdma_local_buf->metadata.end_of_log = req.metadata.end_of_log;
					curr_seg->rdma_local_buf->metadata.log_padding = req.metadata.log_padding;
					curr_seg->rdma_local_buf->metadata.segment_id = req.metadata.segment_id;
					strcpy(curr_seg->rdma_local_buf->metadata.region_key, r_desc->region->min_key);

					curr_seg->rdma_local_buf->msg.type = msg_type;
					curr_seg->rdma_local_buf->msg.receive = TU_RDMA_REGULAR_MSG;

					rdma_src = (void *)&curr_seg->rdma_local_buf->metadata;
					rdma_dst = (void *)&curr_seg->rdma_remote_buf->metadata;
					/*send metadata to replica*/
					if (rdma_post_write(r_desc->r_state->data_conn[0]->rdma_cm_id, rdma_src,
							    rdma_src, sizeof(struct ru_seg_metadata),
							    r_desc->r_state->data_conn[i]
								    ->rdma_memory_regions->local_memory_region,
							    IBV_SEND_SIGNALED, (uint64_t)rdma_dst,
							    r_desc->r_state->data_conn[i]->peer_mr->rkey) != 0) {
						log_fatal("Writing metadata of segment to replica failed!");
						exit(EXIT_FAILURE);
					}
					/*finally wake up replica*/
					rdma_src = (void *)&curr_seg->rdma_local_buf->msg;
					rdma_dst = (void *)&curr_seg->rdma_remote_buf->msg;
					if (rdma_post_write(r_desc->r_state->data_conn[0]->rdma_cm_id, rdma_src,
							    rdma_src, sizeof(struct msg_header),
							    r_desc->r_state->data_conn[0]
								    ->rdma_memory_regions->local_memory_region,
							    IBV_SEND_SIGNALED, (uint64_t)rdma_dst,
							    r_desc->r_state->data_conn[0]->peer_mr->rkey) != 0) {
						log_fatal("Waking up replica failed!");
						exit(EXIT_FAILURE);
					}
				}

				/*Common ins path, find the log segment that corresponds to this full event*/
				seg_id = -1;
				i = 0;
				while (1) {
					if (r_desc->r_state->master_rep_buf->bounds[i].start <=
						    req.metadata.log_offset &&
					    r_desc->r_state->master_rep_buf->bounds[i].end > req.metadata.log_offset) {
						seg_id = i;
						break;
					}
					if (++i == RU_REPLICA_NUM_SEGMENTS)
						i = 0;
				}

				curr_seg = &r_desc->r_state->master_rep_buf->seg_bufs[seg_id];
				rdma_src =
					(void *)&curr_seg->rdma_local_buf->seg[req.metadata.log_offset % SEGMENT_SIZE];

				rdma_dst =
					(void *)&curr_seg->rdma_remote_buf->seg[req.metadata.log_offset % SEGMENT_SIZE];
				memcpy(rdma_src, req.key_value_buf, req.metadata.kv_size);
				/*now next step to the remote*/
				if (rdma_post_write(
					    r_desc->r_state->data_conn[0]->rdma_cm_id, rdma_src, rdma_src,
					    req.metadata.kv_size,
					    r_desc->r_state->data_conn[0]->rdma_memory_regions->local_memory_region,
					    IBV_SEND_SIGNALED, (uint64_t)rdma_dst,
					    r_desc->r_state->data_conn[0]->peer_mr->rkey) != 0) {
					log_fatal("Writing to replica failed!");
					exit(EXIT_FAILURE);
				}
				/* ok add the bytes*/
				__sync_fetch_and_add(&curr_seg->bytes_wr_per_seg, req.metadata.kv_size);
			}
			task->kreon_operation_status = APPEND_COMPLETE;
			return;
		case CHECK_FOR_REPLICA_FLUSH_SEGMENT_ACK:
			log_fatal("Not implemented!");
			exit(EXIT_FAILURE);
			break;

		case ALLOCATE_NEW_LOG_BUFFER_WITH_REPLICA:
			log_fatal("Not implemented!");
			exit(EXIT_FAILURE);
			break;

		case PERFORM_SPILL_CHECK:
		case WAIT_FOR_SPILL_START:
			log_warn("Not implemented!");
			exit(EXIT_FAILURE);
			break;

		case APPEND_COMPLETE:
		case ALLOCATION_START:
		case CHECK_FOR_RESET_BUFFER_ACK:
		case CHECK_FOR_PENDING_REQUESTS_TO_COMPLETE:
		case ALLOCATION_SUCCESS:
		case TASK_START:
		case TASK_COMPLETED:
		default:
			DPRINT("FATAL Ended up in faulty state\n");
			assert(0);
			return;
		}
	}
}

#if 0 // FIXME never used
struct msg_header *Server_FlushVolume_RDMA( struct msg_header *data_message, struct connection_rdma *rdma_conn )
{
	struct msg_header *reply_data_message;
	_tucana_region_S *S_tu_region;

	S_tu_region = get_first_region();
	DPRINT("flushing volume for region %s min_range %s max_range %s\n",S_tu_region->ID_region.IDstr,S_tu_region->ID_region.minimum_range+4,S_tu_region->ID_region.maximum_range+4);
	flush_volume(S_tu_region->db->volume_desc, SPILL_ALL_DBS_IMMEDIATELY);
	printf("\n******[%s:%s:%d] Flushed Volume successfully ******\n",__FILE__,__func__,__LINE__);
	reply_data_message = tdm_Alloc_Flush_Volume_Reply_Message_WithMR( rdma_conn, data_message );
	return reply_data_message;
}
#endif

/*
 * KreonR main processing function of networkrequests.
 * Each network processing request must be resumable. For each message type KreonR process it via
 * a specific data path. We treat all taks related to network  as paths that may fail, that we can resume later. The idea
 * behind this
 * */
void handle_task(void *__task)
{
	struct work_task *task = (struct work_task *)__task;
	kv_location location;
	struct connection_rdma *rdma_conn;
	struct krm_region_desc *r_desc;
	void *region_key;
	//leave it for later
	void *addr;
	uint64_t log_address;
	void *master_segment;
	void *local_log_addr;
	void *key = NULL;
	void *value;
	scannerHandle *sc;
	msg_put_key *K;
	msg_put_value *V;
	msg_put_offt_req *put_offt_req;
	msg_put_offt_rep *put_offt_rep;
	msg_multi_get_req *multi_get;
	msg_get_req *get_req;
	msg_get_rep *get_rep;
	int tries;
	uint32_t key_length = 0;
	uint32_t actual_reply_size = 0;
	uint32_t padding;
	/*unboxing the arguments*/
	r_desc = NULL;
	task->reply_msg = NULL;
	rdma_conn = task->conn;
	stats_update(task->thread_id);
	switch (task->msg->type) {
		//gesalous leave it for later
#if 0
	case SPILL_INIT:

		task->reply_msg = __allocate_rdma_message(task->conn, 0, SPILL_INIT_ACK, ASYNCHRONOUS, 0, task);
		if (task->allocation_status != ALLOCATION_SUCCESS) {
			return;
		}
		task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;

		region_key = task->msg->data;
		S_tu_region = find_region(region_key + sizeof(uint32_t), *(uint32_t *)region_key);

		assert(S_tu_region->db->db_desc->db_mode != PRIMARY_DB &&
		       S_tu_region->db->db_desc->db_mode == BACKUP_DB_NO_PENDING_SPILL);
		assert(task->conn->pending_received_messages == 1 && rdma_conn->pending_sent_messages == 1);

		DPRINT("REPLICA: Master requests a remote spill  for region %s\n", region_key + sizeof(uint32_t));
		S_tu_region->db->db_desc->db_mode = BACKUP_DB_PENDING_SPILL;
		S_tu_region->db->db_desc->spill_segment_table = S_tu_region->db->db_desc->backup_segment_table;
		S_tu_region->db->db_desc->backup_segment_table = NULL;
		map_entry *s = (map_entry *)malloc(sizeof(map_entry));
		s->key = (uint64_t)S_tu_region->db->db_desc->last_master_segment;
		s->value = (uint64_t)S_tu_region->db->db_desc->last_local_mapping;
		HASH_ADD_PTR(S_tu_region->db->db_desc->backup_segment_table, key, s);

		/*finally find an empty tree in the forest to insert the new spill*/
		S_tu_region->current_active_tree_in_the_forest = -1;
		int i;
		for (i = 0; i < MAX_FOREST_SIZE; i++) {
			if (S_tu_region->db->db_desc->replica_forest.tree_status[i] == NOT_USED) {
				DPRINT("REPLICA: Initiating remote spill for tree_id %d in the forest\n", i);
				S_tu_region->db->db_desc->replica_forest.tree_status[i] = IN_TRANSIT_DIRTY;
				S_tu_region->current_active_tree_in_the_forest = i;
				break;
			}
		}
		_calculate_btree_index_nodes(S_tu_region,
					     *(uint64_t *)(task->msg->data + (task->msg->pay_len - sizeof(uint64_t))));
		if (S_tu_region->current_active_tree_in_the_forest == -1) {
			DPRINT("REPLICA: Time for compaction forest is full XXX TODO XXX\n");
			exit(EXIT_FAILURE);
		}
		task->kreon_operation_status = SPILL_INIT_END;
		task->overall_status = TASK_COMPLETED;
		task->reply_msg->error_code = KREON_OK;
		free_rdma_received_message(task->conn, task->msg);
		break;

	case SPILL_COMPLETE:

		task->reply_msg = __allocate_rdma_message(task->conn, 0, SPILL_COMPLETE_ACK, ASYNCHRONOUS, 0, task);
		if (task->allocation_status != ALLOCATION_SUCCESS) {
			return;
		}
		task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;

		region_key = task->msg->data;
		S_tu_region = find_region(region_key + sizeof(uint32_t), *(uint32_t *)region_key);
		assert(S_tu_region->db->db_desc->db_mode != PRIMARY_DB);
		/*clear all mappings*/
		map_entry *current, *tmp;
		HASH_ITER(hh, S_tu_region->db->db_desc->spill_segment_table, current, tmp)
		{
			HASH_DEL(S_tu_region->db->db_desc->spill_segment_table,
				 current); /* delete it (users advances to next) */
			free(current); /* free it */
		}

		task->reply_msg->error_code = KREON_OK;
		DPRINT("REPLICA: completed remote spill snapshotting volume, ommiting CAUTION\n");
		//snapshot(S_tu_region->db->volume_desc);
		S_tu_region->db->db_desc->L0_end_log_offset = *(uint64_t *)task->msg->data;
		S_tu_region->db->db_desc->L0_start_log_offset = *(uint64_t *)task->msg->data;
		int j;
		for (j = MAX_TREE_HEIGHT - 1; j >= 0; j--) {
			if (S_tu_region->last_node_per_level[j] != NULL) {
				S_tu_region->last_node_per_level[j]->type = rootNode;
				S_tu_region->db->db_desc->replica_forest
					.tree_roots[S_tu_region->current_active_tree_in_the_forest] =
					S_tu_region->last_node_per_level[j];
				break;
			}
		} /*snapshot maybe?, snapshot is for replica thus does not include network communication*/
		S_tu_region->db->db_desc->replica_forest.tree_status[S_tu_region->current_active_tree_in_the_forest] =
			READY_TO_PERSIST;
		DPRINT("REPLICA: Spill complete maybe a snapshot now? XXX TODO XXX\n");
		S_tu_region->db->db_desc->db_mode = BACKUP_DB_NO_PENDING_SPILL;
		task->kreon_operation_status = SPILL_COMPLETE_END;
		task->overall_status = TASK_COMPLETED;
		free_rdma_received_message(task->conn, task->msg);
		break;

	case SPILL_BUFFER_REQUEST:

		/*Nothing to do here for suspend/resume because in this version
				it does not send a reply to the client*/
		region_key = task->msg->data + sizeof(uint32_t);
		S_tu_region = find_region(region_key, PREFIX_SIZE);
		assert(S_tu_region->db->db_desc->db_mode != PRIMARY_DB &&
		       S_tu_region->db->db_desc->db_mode == BACKUP_DB_PENDING_SPILL);
		/*iterate values*/
		addr = task->msg->data;
		num_entries = *(uint32_t *)(addr);
		addr += sizeof(uint32_t);
		//DPRINT("\tREPLICA: applying remote spill buffer at replica num entries %d\n",num_entries);
		S_tu_region->db->db_desc->replica_forest.tree_status[S_tu_region->current_active_tree_in_the_forest] =
			IN_TRANSIT_DIRTY;
		for (i = 0; i < num_entries; i++) {
			/*rewrite mapping, PREFIX stays the same*/
			log_address = (*(uint64_t *)(addr + PREFIX_SIZE));
			master_segment = (void *)log_address - ((uint64_t)log_address % BUFFER_SEGMENT_SIZE);
			//local_log_addr = (void *) clht_get(handle->db_desc->backup_segment_table->ht, (clht_addr_t) master_segment);
			map_entry *s;
			SPIN_LOCK(&S_tu_region->db->db_desc->back_up_segment_table_lock);
			HASH_FIND_PTR(S_tu_region->db->db_desc->spill_segment_table, &master_segment, s);
			if (s == NULL) {
				DPRINT("REPLICA: FATAL mapping is missing for master segment %llu\n",
				       (LLU)master_segment);
				raise(SIGINT);
				exit(EXIT_FAILURE);
			}
			SPIN_UNLOCK(&S_tu_region->db->db_desc->back_up_segment_table_lock);
			/*add the offset*/
			local_log_addr = (void *)MAPPED + s->value + (log_address % BUFFER_SEGMENT_SIZE);
			*(uint64_t *)(addr + PREFIX_SIZE) = (uint64_t)local_log_addr;

			//DPRINT("mapping remote log segment: %llu local segment : %llu local full address in log %llu\n",
			//	(LLU)master_segment,(LLU)s->value, (LLU)local_log_addr);
			//if( *(uint32_t *)local_log_addr > 30 || *(uint32_t *)local_log_addr == 0){
			//	DPRINT("mapping remote log segment: %llu local segment : %llu local full address in log %llu\n",
			//			(LLU)master_segment,(LLU)s->value, (LLU)local_log_addr);
			//	DPRINT("Faulty pointer size %"PRIu32" i is %d\n",*(uint32_t *)local_log_addr,i);
			//	raise(SIGINT);
			//	exit(EXIT_FAILURE);
			//}

#if LEVELING
			location.kv_addr = addr;
			/*insert to local L1*/
			//DEBUGGING
			//if(memcmp(addr, local_log_addr+4,PREFIX_SIZE) != 0){
			//  DPRINT("boom corrupted log remote key %s, local key %s\n",(char *)addr, (char *)local_log_addr+4);
			//  raise(SIGINT);
			//}
			_insert_index_entry(s_tu_region->db, &location,
					    INSERT_TO_L1_INDEX | DO_NOT_APPEND_TO_LOG | (4 << 8) | BACKUP_OPERATION);
#else
			/*tiering*/
			append_entry_to_leaf_node(S_tu_region, (void *)(*(uint64_t *)(addr + PREFIX_SIZE)), addr,
						  S_tu_region->current_active_tree_in_the_forest);
#endif
			addr += (PREFIX_SIZE + sizeof(uint64_t));
		}
		free_rdma_received_message(task->conn, task->msg);
		task->overall_status = TASK_COMPLETED;
		break;

#if 0
		case SCAN_REQUEST:
			task->reply_msg = Server_Scan_MulipleRegions_RDMA(task->msg, rdma_conn);
			task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;
			break;

			/*
			 * Kind reminder, SPILL_INIT, SPILL_BUFFER_REQUEST, and SPILL_COMPLETE are handled by the server
			 * which has backup role for the given region
			 */

#endif
#endif
	case RESET_BUFFER:
		//DPRINT("Got reset buffer request pending received messages are %llu\n", (LLU)task->conn->pending_received_messages);
		if (task->kreon_operation_status == RESET_BUFFER_START) {
			/*Have all requests been completed for this connection?*/
			tries = 0;
			while (task->conn->pending_received_messages != 0) {
				if (++tries >= NUM_OF_TRIES) {
					//DPRINT("\tWaiting for processing of received messages to send RESET_BUFFER_ACK pending messages %llu\n",(LLU)task->conn->pending_received_messages);
					return;
				}
			}
		}
		_send_reset_buffer_ack(task->conn);
		task->kreon_operation_status = RESET_BUFFER_COMPLETE;
		_zero_rendezvous_locations(task->msg);
		_update_rendezvous_location(task->conn, 0); /*"0" indicates RESET*/
		task->overall_status = TASK_COMPLETED;
		break;

	case PUT_OFFT_REQUEST:

		put_offt_req = (msg_put_offt_req *)task->msg->data;

		K = (msg_put_key *)((uint64_t)put_offt_req + sizeof(msg_put_offt_req));
		V = (msg_put_value *)((uint64_t)K + sizeof(msg_put_key) + K->key_size);
		r_desc = krm_get_region(K->key, K->key_size);
		if (r_desc == NULL) {
			log_fatal("Region not found for key size %u:%s", K->key_size, K->key);
			exit(EXIT_FAILURE);
		}
		task->region = (void *)r_desc;
		/*inside kreon now*/
		//log_info("offset %llu key %s", put_offt_req->offset, K->key);
		uint32_t new_size = put_offt_req->offset + sizeof(msg_put_key) + K->key_size + sizeof(msg_put_value) +
				    V->value_size;
		if (new_size <= SEGMENT_SIZE - sizeof(segment_header)) {
			value = __find_key(r_desc->db, put_offt_req->kv, SEARCH_DIRTY_TREE);

			void *new_value =
				malloc(SEGMENT_SIZE - sizeof(segment_header)); /*remove this later when test passes*/
			memset(new_value, 0x00, SEGMENT_SIZE - sizeof(segment_header));
			/*copy key*/
			memcpy(new_value, put_offt_req->kv, sizeof(msg_put_key) + K->key_size);
			/*old value, if it exists*/
			if (value != NULL) {
				memcpy(new_value + sizeof(msg_put_key) + K->key_size, value,
				       sizeof(msg_put_value) + *(uint32_t *)value);
				/*update the value size field if needed*/
				if ((put_offt_req->offset + V->value_size) > *(uint32_t *)value)
					*(uint32_t *)(new_value + sizeof(msg_put_key) + K->key_size) =
						put_offt_req->offset + V->value_size;
				//log_info("New val size is %u offset %u client value %u old val %u kv_size %u",
				//	 *(uint32_t *)(new_value + sizeof(msg_put_key) + K->key_size),
				//	 put_offt_req->offset, V->value_size, *(uint32_t *)value, kv_size);
			} else {
				*(uint32_t *)(new_value + sizeof(msg_put_key) + K->key_size) =
					put_offt_req->offset + V->value_size;
			}

			/*now the value patch*/
			memcpy(new_value + sizeof(msg_put_key) + K->key_size + sizeof(msg_put_value) +
				       put_offt_req->offset,
			       V->value, V->value_size);
			//log_info("new val key %u val size %u", *(uint32_t *)new_value,
			//	 *(uint32_t *)(new_value + sizeof(msg_put_key) + K->key_size));

			insert_kv_pair(r_desc, new_value, task->conn, &location, task, DO_NOT_WAIT_REPLICA_TO_COMMIT);
			free(new_value);
		}

		task->reply_msg = (void *)((uint64_t)task->conn->rdma_memory_regions->local_memory_buffer +
					   (uint64_t)task->msg->reply);
		/*initialize message*/
		actual_reply_size = sizeof(msg_header) + sizeof(msg_put_offt_rep) + TU_TAIL_SIZE;
		if (task->msg->reply_length >= actual_reply_size) {
			padding = MESSAGE_SEGMENT_SIZE - (actual_reply_size % MESSAGE_SEGMENT_SIZE);
			/*set tail to the proper value*/
			*(uint32_t *)((uint64_t)task->reply_msg + actual_reply_size - (TU_TAIL_SIZE) + padding) =
				TU_RDMA_REGULAR_MSG;

			task->reply_msg->pay_len = sizeof(msg_put_offt_rep);
			task->reply_msg->padding_and_tail = padding + TU_TAIL_SIZE;
			//log_info("msg header %d put_rep %d padding_and_tail %d", sizeof(msg_header),
			//	 sizeof(msg_put_rep), task->reply_msg->padding_and_tail);

			task->reply_msg->data = (void *)((uint64_t)task->reply_msg + sizeof(msg_header));
			task->reply_msg->next = task->reply_msg->data;
			task->reply_msg->type = PUT_OFFT_REPLY;

			task->reply_msg->ack_arrived = KR_REP_PENDING;
			task->reply_msg->receive = TU_RDMA_REGULAR_MSG;
			task->reply_msg->local_offset = (uint64_t)task->msg->reply;
			task->reply_msg->remote_offset = (uint64_t)task->msg->reply;
			task->reply_msg->callback_function = NULL;
			put_offt_rep = (msg_put_offt_rep *)((uint64_t)task->reply_msg + sizeof(msg_header));
			put_offt_rep->status = KREON_SUCCESS;
		} else {
			log_fatal("SERVER: mr CLIENT reply space not enough  size %" PRIu32 " FIX XXX TODO XXX\n",
				  task->msg->reply_length);
			exit(EXIT_FAILURE);
		}

		/*piggyback info for use with the client*/
		task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;
		assert(task->reply_msg->request_message_local_addr != NULL);
		task->overall_status = TASK_COMPLETED;
		break;
	case PUT_REQUEST:

		/* *
			 * retrieve region handle for the corresponding key, find_region
			 * initiates internally rdma connections if needed
			 * */

		K = (msg_put_key *)(task->msg->data);
		V = (msg_put_value *)((uint64_t)K + sizeof(msg_put_key) + K->key_size);
		key_length = K->key_size;
		assert(key_length != 0);
		r_desc = krm_get_region(K->key, K->key_size);
		if (r_desc == NULL) {
			log_fatal("Region not found for key size %u:%s", K->key_size, K->key);
			exit(EXIT_FAILURE);
		}
		task->region = (void *)r_desc;

		if (task->kreon_operation_status != APPEND_COMPLETE) {
			insert_kv_pair(r_desc, task->msg->data, task->conn, &location, task,
				       DO_NOT_WAIT_REPLICA_TO_COMMIT);

			if (task->kreon_operation_status == APPEND_COMPLETE) {
				task->allocation_status = ALLOCATION_START;
				//free_rdma_received_message(task->conn, task->msg);
			} else {
				return;
			}
		}

		task->reply_msg = (void *)((uint64_t)task->conn->rdma_memory_regions->local_memory_buffer +
					   (uint64_t)task->msg->reply);
		/*initialize message*/

		if (task->msg->reply_length >= actual_reply_size) {
			task->reply_msg->pay_len = sizeof(msg_put_rep);

			actual_reply_size = sizeof(msg_header) + sizeof(msg_put_rep) + TU_TAIL_SIZE;
			padding = MESSAGE_SEGMENT_SIZE - (actual_reply_size % MESSAGE_SEGMENT_SIZE);
			/*set tail to the proper value*/
			*(uint32_t *)((uint64_t)task->reply_msg + actual_reply_size + (padding - TU_TAIL_SIZE)) =
				TU_RDMA_REGULAR_MSG;
			task->reply_msg->padding_and_tail = padding + TU_TAIL_SIZE;
			task->reply_msg->data = (void *)((uint64_t)task->reply_msg + sizeof(msg_header));
			task->reply_msg->next = task->reply_msg->data;

			task->reply_msg->type = PUT_REPLY;

			task->reply_msg->ack_arrived = KR_REP_PENDING;
			task->reply_msg->receive = TU_RDMA_REGULAR_MSG;
			task->reply_msg->local_offset = (uint64_t)task->msg->reply;
			task->reply_msg->remote_offset = (uint64_t)task->msg->reply;
			task->reply_msg->callback_function = NULL;
			msg_put_rep *put_rep = (msg_put_rep *)((uint64_t)task->reply_msg + sizeof(msg_header));
			put_rep->status = KREON_SUCCESS;
		} else {
			log_fatal("SERVER: mr CLIENT reply space not enough  size %" PRIu32 " FIX XXX TODO XXX\n",
				  task->msg->reply_length);
			exit(EXIT_FAILURE);
		}

		/*piggyback info for use with the client*/
		task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;
		assert(task->reply_msg->request_message_local_addr != NULL);
		task->overall_status = TASK_COMPLETED;
		return;

	case DELETE_REQUEST: {
		msg_delete_req *del_req = (msg_delete_req *)task->msg->data;
		r_desc = krm_get_region(del_req->key, del_req->key_size);
		if (r_desc == NULL) {
			log_fatal("ERROR: Region not found for key %s\n", del_req->key);
			return;
		}
		task->reply_msg = (void *)((uint64_t)task->conn->rdma_memory_regions->local_memory_buffer +
					   (uint64_t)task->msg->reply);

		/*piggyback info for use with the client*/
		task->reply_msg->pay_len = sizeof(msg_delete_rep);

		actual_reply_size = sizeof(msg_header) + sizeof(msg_delete_rep) + TU_TAIL_SIZE;
		padding = MESSAGE_SEGMENT_SIZE - (actual_reply_size % MESSAGE_SEGMENT_SIZE);
		/*set tail to the proper value*/
		*(uint32_t *)((uint64_t)task->reply_msg + actual_reply_size + (padding - TU_TAIL_SIZE)) =
			TU_RDMA_REGULAR_MSG;
		task->reply_msg->padding_and_tail = padding + TU_TAIL_SIZE;
		task->reply_msg->data = (void *)((uint64_t)task->reply_msg + sizeof(msg_header));
		task->reply_msg->next = task->reply_msg->data;

		task->reply_msg->type = DELETE_REPLY;

		task->reply_msg->ack_arrived = KR_REP_PENDING;
		task->reply_msg->receive = TU_RDMA_REGULAR_MSG;
		task->reply_msg->local_offset = (uint64_t)task->msg->reply;
		task->reply_msg->remote_offset = (uint64_t)task->msg->reply;
		task->reply_msg->callback_function = NULL;
		msg_delete_rep *del_rep = (msg_delete_rep *)((uint64_t)task->reply_msg + sizeof(msg_header));
		task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;
		task->overall_status = TASK_COMPLETED;

		if (delete_key(r_desc->db, del_req->key, del_req->key_size) == SUCCESS)
			del_rep->status = KREON_SUCCESS;
		else
			del_rep->status = KREON_FAILURE;
		break;
	}

	case TU_GET_QUERY:
		value = NULL;
		/*kreon phase*/
		get_req = (msg_get_req *)task->msg->data;
		r_desc = krm_get_region(get_req->key, get_req->key_size);

		if (r_desc == NULL) {
			log_fatal("Region not found for key %s", get_req->key);
			exit(EXIT_FAILURE);
		}
		task->reply_msg = (void *)((uint64_t)task->conn->rdma_memory_regions->local_memory_buffer +
					   (uint64_t)task->msg->reply);
		get_rep = (msg_get_rep *)((uint64_t)task->reply_msg + sizeof(msg_header));
		value = __find_key(r_desc->db, &get_req->key_size, SEARCH_DIRTY_TREE);

		if (value == NULL) {
			//log_warn("key not found key %s : length %u region min_key %s max key %s\n",
			//	 get_req->key + sizeof(uint32_t), key_length,
			//	 S_tu_region->ID_region.minimum_range + sizeof(int),
			//	 S_tu_region->ID_region.maximum_range + sizeof(int));
			get_rep->key_found = 0;
			get_rep->bytes_remaining = 0;
			get_rep->value_size = 0;
			get_rep->offset_too_large = 0;
			goto exit;
		} else {
			get_rep->key_found = 1;
			if (get_req->offset > *(uint32_t *)value) {
				get_rep->offset_too_large = 1;
				get_rep->value_size = 0;
				get_rep->bytes_remaining = *(uint32_t *)value;
				goto exit;
			} else
				get_rep->offset_too_large = 0;
			if (!get_req->fetch_value) {
				get_rep->bytes_remaining = *(uint32_t *)value - get_req->offset;
				get_rep->value_size = 0;
				goto exit;
			}
			uint32_t value_bytes_remaining = *(uint32_t *)value - get_req->offset;
			uint32_t bytes_to_read;
			if (get_req->bytes_to_read <= value_bytes_remaining) {
				bytes_to_read = get_req->bytes_to_read;
				get_rep->bytes_remaining = *(uint32_t *)value - (get_req->offset + bytes_to_read);
			} else {
				bytes_to_read = value_bytes_remaining;
				get_rep->bytes_remaining = 0;
			}
			get_rep->value_size = bytes_to_read;
			//log_info("Client wants to read %u will read %u",get_req->bytes_to_read,bytes_to_read);
			memcpy(get_rep->value, value + sizeof(uint32_t) + get_req->offset, bytes_to_read);
		}

	exit:
		/*piggyback info for use with the client*/
		/*finally fix the header*/
		task->reply_msg->type = TU_GET_REPLY;
		task->reply_msg->receive = TU_RDMA_REGULAR_MSG;
		task->reply_msg->pay_len = sizeof(msg_get_rep) + get_rep->value_size;

		actual_reply_size = sizeof(msg_header) + task->reply_msg->pay_len + TU_TAIL_SIZE;
		padding = MESSAGE_SEGMENT_SIZE - (actual_reply_size % MESSAGE_SEGMENT_SIZE);
		/*set tail to the proper value*/
		*(uint32_t *)((uint64_t)task->reply_msg + actual_reply_size + (padding - TU_TAIL_SIZE)) =
			TU_RDMA_REGULAR_MSG;
		task->reply_msg->padding_and_tail = padding + TU_TAIL_SIZE;

		task->reply_msg->local_offset = (uint64_t)task->msg->reply;
		task->reply_msg->remote_offset = (uint64_t)task->msg->reply;
		task->reply_msg->callback_function = NULL;
		task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;
		task->overall_status = TASK_COMPLETED;
		break;

	case MULTI_GET_REQUEST: {
		msg_value zero_value;
		zero_value.size = 0;

		multi_get = (msg_multi_get_req *)task->msg->data;
		r_desc = krm_get_region(multi_get->seek_key, multi_get->seek_key_size);

		if (r_desc == NULL) {
			log_fatal("Region not found for key size %u:%s", multi_get->seek_key_size, multi_get->seek_key);
			exit(EXIT_FAILURE);
		}
		/*create an internal scanner object*/
		sc = (scannerHandle *)malloc(sizeof(scannerHandle));

		if (multi_get->seek_mode != FETCH_FIRST) {
			//log_info("seeking at key %s", multi_get->seek_key);
			initScanner(sc, r_desc->db, &multi_get->seek_key_size, multi_get->seek_mode);
		} else {
			//log_info("seeking at key first key of region");
			initScanner(sc, r_desc->db, NULL, GREATER_OR_EQUAL);
		}

		/*put the data in the buffer*/
		task->reply_msg = (void *)((uint64_t)task->conn->rdma_memory_regions->local_memory_buffer +
					   (uint64_t)task->msg->reply);
		msg_multi_get_rep *buf = (msg_multi_get_rep *)((uint64_t)task->reply_msg + sizeof(msg_header));
		buf->curr_entry = 0;
		buf->end_of_region = 0;
		buf->buffer_overflow = 0;

		buf->capacity =
			task->msg->reply_length - (sizeof(msg_header) + sizeof(msg_multi_get_rep) + TU_TAIL_SIZE);
		buf->remaining = buf->capacity;
		buf->pos = 0;
		buf->num_entries = 0;
		if (sc->keyValue != NULL) {
			msg_key *key = sc->keyValue;

			msg_value *value = (msg_value *)((uint64_t)key + sizeof(msg_key) + key->size);
			if (multi_get->fetch_keys_only)
				value = (msg_value *)&zero_value;
			else
				value = (msg_value *)((uint64_t)key + sizeof(msg_key) + key->size);

			if (msg_push_to_multiget_buf(key, value, buf) == KREON_SUCCESS) {
				while (buf->num_entries <= multi_get->max_num_entries) {
					if (getNext(sc) == END_OF_DATABASE) {
						buf->end_of_region = 1;
						break;
					}
					key = sc->keyValue;
					if (multi_get->fetch_keys_only)
						value = (msg_value *)&zero_value;
					else
						value = (msg_value *)((uint64_t)key + sizeof(msg_key) + key->size);

					if (msg_push_to_multiget_buf(key, value, buf) == KREON_FAILURE) {
						break;
					}
				}
			}
		} else
			buf->end_of_region = 1;

		closeScanner(sc);
		free(sc);

		/*finally fix the header*/
		task->reply_msg->type = MULTI_GET_REPLY;
		task->reply_msg->receive = TU_RDMA_REGULAR_MSG;
		task->reply_msg->pay_len = sizeof(msg_multi_get_rep) + (buf->capacity - buf->remaining);
		/*set now the actual capacity*/
		buf->capacity = buf->capacity - buf->remaining;
		buf->remaining = buf->capacity;

		actual_reply_size = sizeof(msg_header) + task->reply_msg->pay_len + TU_TAIL_SIZE;
		if (actual_reply_size % MESSAGE_SEGMENT_SIZE == 0)
			padding = 0;
		else
			padding = MESSAGE_SEGMENT_SIZE - (actual_reply_size % MESSAGE_SEGMENT_SIZE);

		/*set tail to the proper value*/
		*(uint32_t *)((uint64_t)task->reply_msg + (actual_reply_size - TU_TAIL_SIZE) + padding) =
			TU_RDMA_REGULAR_MSG;
		task->reply_msg->padding_and_tail = padding + TU_TAIL_SIZE;

		//assert((actual_reply_size + padding) % MESSAGE_SEGMENT_SIZE == 0);
		//assert((actual_reply_size + padding) <= task->msg->reply_length);

		//log_info("actual size %u padding and tail %u pay_len %u buf capacity %u buf remaining %u",
		//	 actual_reply_size, task->reply_msg->padding_and_tail, task->reply_msg->pay_len, buf->capacity,
		//	 buf->remaining);
		task->reply_msg->local_offset = (uint64_t)task->msg->reply;
		task->reply_msg->remote_offset = (uint64_t)task->msg->reply;
		task->reply_msg->callback_function = NULL;
		task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;
		assert(task->reply_msg->request_message_local_addr != NULL);
		task->overall_status = TASK_COMPLETED;
		break;
	}

	case TEST_REQUEST:
		task->reply_msg = (void *)((uint64_t)task->conn->rdma_memory_regions->local_memory_buffer +
					   (uint64_t)task->msg->reply);
		/*initialize message*/
		if (task->msg->reply_length >= TU_HEADER_SIZE) {
			task->reply_msg->pay_len = 0;
			task->reply_msg->padding_and_tail = 0;
			task->reply_msg->data = NULL;
			task->reply_msg->next = NULL;

			task->reply_msg->type = TEST_REPLY;
			task->reply_msg->receive = TU_RDMA_REGULAR_MSG;
			task->reply_msg->local_offset = (uint64_t)task->msg->reply;
			task->reply_msg->remote_offset = (uint64_t)task->msg->reply;

			task->reply_msg->ack_arrived = KR_REP_PENDING;
			task->reply_msg->callback_function = NULL;
			task->reply_msg->request_message_local_addr = NULL;
			task->overall_status = TASK_COMPLETED;
		} else {
			log_fatal("CLIENT reply space not enough  size %" PRIu32 " FIX XXX TODO XXX\n",
				  task->msg->reply_length);
			exit(EXIT_FAILURE);
		}
		/*piggyback info for use with the client*/
		task->reply_msg->request_message_local_addr = task->notification_addr;
		break;

	case TEST_REQUEST_FETCH_PAYLOAD:
		log_fatal("Message not supported yet");
		exit(EXIT_FAILURE);
#if 0
		case TU_FLUSH_VOLUME_QUERY:
			reply_data_message = Server_FlushVolume_RDMA( data_message, rdma_conn);
			break;
#endif
	case FLUSH_SEGMENT:
	case FLUSH_SEGMENT_AND_RESET:
		if (task->kreon_operation_status == FLUSH_SEGMENT_START) {
			//DPRINT("**** Ordered from master to perform a flush ****\n");
			/*ommit header find the corresponding region*/
			region_key = (void *)(task->msg->data + 32);
			r_desc = krm_get_region(region_key + sizeof(uint32_t), *(uint32_t *)region_key);

			if (r_desc == NULL) {
				log_fatal("FATAL region with min key %s not found\n", region_key);
				exit(EXIT_FAILURE);
			}
			if (r_desc->role == KRM_PRIMARY) {
				log_fatal("FATAL flushing primary db?\n");
				raise(SIGINT);
				exit(EXIT_FAILURE);
			}

#if !OMMIT_IO_IN_THE_INSERT_PATH
			void *master_segment = (void *)*(uint64_t *)((uint64_t)task->msg->data);
			uint64_t end_of_log = *(uint64_t *)((uint64_t)task->msg->data + (sizeof(uint64_t)));
			uint64_t bytes_to_pad = *(uint64_t *)((uint64_t)task->msg->data + (2 * sizeof(uint64_t)));
			uint64_t segment_id = *(uint64_t *)((uint64_t)task->msg->data + (3 * sizeof(uint64_t)));

			void *buffer = task->msg->data + 4096;
			//DPRINT("REPLICA: master segment %llu end of log %llu bytes to pad %llu segment_id %llu\n",(LLU)master_segment,(LLU)end_of_log,(LLU)bytes_to_pad,(LLU)segment_id);
			ru_flush_replica_log_buffer(r_desc->db, (segment_header *)master_segment, buffer, end_of_log,
						    bytes_to_pad, segment_id);
#endif
			free_rdma_received_message(task->conn, task->msg);
			task->kreon_operation_status = FLUSH_SEGMENT_COMPLETE;
		}

		/*Since reply message is of fixed size we allocate it first*/

		task->reply_msg =
			(msg_header *)(task->conn->rdma_memory_regions->local_memory_buffer + task->conn->offset);
		/*init message*/
		task->reply_msg->pay_len = 0;
		task->reply_msg->padding_and_tail = 0;
		task->reply_msg->data = NULL;
		task->reply_msg->next = task->reply_msg->data;
		task->reply_msg->receive = TU_RDMA_REGULAR_MSG;

		task->reply_msg->local_offset = task->conn->offset;
		task->reply_msg->remote_offset = task->conn->offset;
		task->reply_msg->ack_arrived = KR_REP_PENDING;
		task->reply_msg->callback_function = NULL;
		task->reply_msg->request_message_local_addr = NULL;

		if (task->msg->type == FLUSH_SEGMENT) {
			task->reply_msg->type = FLUSH_SEGMENT_ACK;
			task->conn->offset += MESSAGE_SEGMENT_SIZE;
		} else {
			task->reply_msg->type = FLUSH_SEGMENT_ACK_AND_RESET;
			task->conn->offset = 0;
		}
		//task->reply_msg = __allocate_rdma_message(task->conn, 0, FLUSH_SEGMENT_ACK, ASYNCHRONOUS, 0, task);
		//if(task->allocation_status != ALLOCATION_SUCCESS){
		//	return;
		//}
		task->reply_msg->request_message_local_addr = task->notification_addr;
		__sync_fetch_and_add(&task->conn->pending_sent_messages, 1);
		//DPRINT("* Everything ok sending FLUSH_SEGMENT_ACK pending sent for con are %llu\n",(LLU)task->conn->pending_sent_messages);
		task->overall_status = TASK_COMPLETED;
		break;
	default:
		DPRINT("FATAL unknown operation %d\n", task->msg->type);
		exit(EXIT_FAILURE);
	}
	//free_rdma_received_message(rdma_conn, data_message);
	//assert(reply_data_message->request_message_local_addr);

	return;
}

/*helper functions*/
void _str_split(char *a_str, const char a_delim, uint64_t **core_vector, uint32_t *num_of_cores)
{
	//DPRINT("%s\n",a_str);
	char *tmp = alloca(128);
	char **result = 0;
	size_t count = 0;

	char *last_comma = 0;

	char delim[2];
	int i;

	strcpy(tmp, a_str);
	delim[0] = a_delim;
	delim[1] = 0;

	/* Count how many elements will be extracted. */
	while (*tmp) {
		if (a_delim == *tmp) {
			count++;
			last_comma = tmp;
		}
		tmp++;
	}

	/* Add space for trailing token. */
	count += last_comma < (a_str + strlen(a_str) - 1);
	count++;
	/* Add space for terminating null string so caller
		 knows where the list of returned strings ends. */

	result = malloc(sizeof(char *) * count);

	*num_of_cores = count - 1;
	*core_vector = (uint64_t *)malloc(sizeof(uint64_t) * count);
	i = 0;

	if (result) {
		size_t idx = 0;
		char *token = strtok(a_str, delim);

		while (token) {
			assert(idx < count);
			*(result + idx++) = strdup(token);
			if (*token != 0x00) {
				(*core_vector)[i] = strtol(token, (char **)NULL, 10);
				//DPRINT("Core id %d = %llu\n",i,(LLU)(*core_vector)[i]);
				++i;
			}
			token = strtok(0, delim);
		}
		assert(idx == count - 1);
		*(result + idx) = 0;
		free(result);
	}
	return;
}

sem_t exit_main;
static void tu_ec_sig_handler(int signo)
{
	/*pid_t tid = syscall(__NR_gettid);*/
	DPRINT("caught signal closing server\n");
	stats_notify_stop_reporter_thread();
	sem_post(&exit_main);
}

int main(int argc, char *argv[])
{
	char *device_name;
	uint64_t device_size;
	//globals_set_zk_host(zookeeper_host_port);
	RDMA_LOG_BUFFER_PADDING = 0;
	RDMA_TOTAL_LOG_BUFFER_SIZE = TU_HEADER_SIZE + BUFFER_SEGMENT_SIZE + 4096 + TU_TAIL_SIZE;

	if (RDMA_TOTAL_LOG_BUFFER_SIZE % MESSAGE_SEGMENT_SIZE != 0) {
		/*need to pad */
		RDMA_LOG_BUFFER_PADDING = (MESSAGE_SEGMENT_SIZE - (RDMA_TOTAL_LOG_BUFFER_SIZE % MESSAGE_SEGMENT_SIZE));
		RDMA_TOTAL_LOG_BUFFER_SIZE += RDMA_LOG_BUFFER_PADDING;
		assert(RDMA_TOTAL_LOG_BUFFER_SIZE % MESSAGE_SEGMENT_SIZE == 0);
	}

	if (argc == 7) {
		int rdma_port = strtol(argv[1], NULL, 10);
		globals_set_RDMA_connection_port(rdma_port);
		device_name = argv[2];
		device_size = strtol(argv[3], NULL, 10) * 1024 * 1024 * 1024;
		globals_set_dev(device_name);
		globals_set_zk_host(argv[3]);
		globals_set_RDMA_IP_filter(argv[4]);
		_str_split(argv[5], ',', &spinning_threads_core_ids, &num_of_spinning_threads);
		_str_split(argv[6], ',', &worker_threads_core_ids, &num_of_worker_threads);
	} else {
		log_fatal(
			"Error: usage: ./kreon_server <port number> <device name> <zk_host:zk_port> <RDMA_IP_prefix> <spinning thread core ids>  <working thread core ids>\n");
		exit(EXIT_FAILURE);
	}

	for (uint32_t i = 0; i < num_of_spinning_threads; i++)
		log_info(" spinning thread core[%d] = %llu", i, (LLU)spinning_threads_core_ids[i]);

	for (uint32_t i = 0; i < num_of_worker_threads; i++)
		log_info(" worker thread core[%d] = %llu", i, (LLU)worker_threads_core_ids[i]);

	if (num_of_worker_threads % num_of_spinning_threads != 0) {
		log_fatal("total worker threads mod with total spinning threads must be 0!");
		exit(EXIT_FAILURE);
	}
	WORKER_THREADS_PER_SPINNING_THREAD = (num_of_worker_threads / num_of_spinning_threads);

	log_info("Set pool size for each spinning thread to %u\n", WORKER_THREADS_PER_SPINNING_THREAD);

	pthread_mutex_init(&reg_lock, NULL);

	log_info("Creating RDMA channel...");

	struct channel_rdma *channel = (struct channel_rdma *)malloc(sizeof(*channel));
	if (channel == NULL) {
		log_fatal("malloc failed could do not get memory for channel");
		exit(EXIT_FAILURE);
	}
	crdma_init_generic_create_channel(channel);
	channel->dynamic_pool = mrpool_create(channel->pd, -1, DYNAMIC, MEM_REGION_BASE_SIZE);
	channel->spinning_th = 0; //what?
	channel->spinning_conn = 0; //what?
	channel->spinning_num_th = num_of_spinning_threads; //what?
	globals_set_rdma_channel(channel);
	log_info("Created RDMA channel successfully");
	log_info("Creating server spinning and worker threads...");

	pthread_mutex_init(&channel->spin_conn_lock, NULL); // Lock for the conn_list

	log_info("Setting spinning threads number to %d", num_of_spinning_threads);
	dataserver = (struct ds_server *)malloc(
		sizeof(struct ds_server) +
		(num_of_spinning_threads * (sizeof(struct ds_spinning_thread) +
					    (WORKER_THREADS_PER_SPINNING_THREAD * sizeof(struct worker_thread)))));
	dataserver->num_of_spinning_threads = num_of_spinning_threads;

	for (int i = 0; i < dataserver->num_of_spinning_threads; i++) {
		//pthread_mutex_init(&channel->spin_list_conn_lock[i], NULL);
		//channel->spin_list[i] = init_simple_concurrent_list();
		//channel->idle_conn_list[i] = init_simple_concurrent_list();
		pthread_mutex_init(&dataserver->spinner[i].conn_list_lock, NULL);
		dataserver->spinner[i].conn_list = init_simple_concurrent_list();
		dataserver->spinner[i].idle_conn_list = init_simple_concurrent_list();

		dataserver->spinner[i].next_server_worker_to_submit_job = 0;
		dataserver->spinner[i].next_client_worker_to_submit_job = WORKER_THREADS_PER_SPINNING_THREAD / 2;
		/*Now init workers structures for this spinner*/
		dataserver->spinner[i].num_workers = WORKER_THREADS_PER_SPINNING_THREAD;
		struct ds_spinning_thread *spinner = &dataserver->spinner[i];
		for (int j = 0; j < spinner->num_workers; j++) {
			/*init worker group vars*/
			pthread_spin_init(&spinner->worker[j].work_queue_lock, PTHREAD_PROCESS_PRIVATE);
			spinner->worker[j].worker_id = j;
			spinner->worker[j].status = WORKER_NOT_RUNNING;
			sem_init(&spinner->worker[j].sem, 0, 0);
			utils_queue_init(&spinner->worker[j].empty_job_buffers_queue);
			utils_queue_init(&spinner->worker[j].empty_high_priority_job_buffers_queue);
			utils_queue_init(&spinner->worker[j].work_queue);
			utils_queue_init(&spinner->worker[j].high_priority_queue);

			for (int k = 0; k < UTILS_QUEUE_CAPACITY; k++) {
				utils_queue_push(&spinner->worker[j].empty_job_buffers_queue,
						 &spinner->worker[j].job_buffers[k]);
				utils_queue_push(&spinner->worker[j].empty_high_priority_job_buffers_queue,
						 &spinner->worker[j].high_priority_job_buffers[k]);
			}
		}

		if (pthread_create(&spinner->spinner_context, NULL, server_spinning_thread_kernel,
				   &dataserver->spinner[i]) != 0) {
			log_fatal("failed to spawn server spinning thread reason follows\n");
			perror("Reason: \n");
			exit(EXIT_FAILURE);
		}

		log_info("Pinning spinning thread %d...", i);
		cpu_set_t spinning_thread_affinity_mask;
		CPU_ZERO(&spinning_thread_affinity_mask);
		CPU_SET(spinning_threads_core_ids[i], &spinning_thread_affinity_mask);
		int status = pthread_setaffinity_np(spinner->spinner_context, sizeof(cpu_set_t),
						    &spinning_thread_affinity_mask);
		if (status != 0) {
			log_fatal("failed to pin spinning thread");
			exit(EXIT_FAILURE);
		}
		log_info("Pinned successfully spinning thread to core %llu", (LLU)spinning_threads_core_ids[i]);
		log_info("Generating %d workers for spinning thread %d", spinner->num_workers, spinner->id);

		cpu_set_t worker_threads_affinity_mask;
		CPU_ZERO(&worker_threads_affinity_mask);
		/*set the proper affinity for this worker group*/
		uint32_t start = i * (num_of_worker_threads / num_of_spinning_threads);
		for (uint32_t j = start; j < start + (num_of_worker_threads / num_of_spinning_threads); j++) {
			CPU_SET(worker_threads_core_ids[j], &worker_threads_affinity_mask);
			log_info("Pinning worker threads (belonging to spinning thread core id %llu) to core id %llu",
				 (LLU)spinning_threads_core_ids[i], (LLU)worker_threads_core_ids[j]);
		}

		for (int j = 0; j < spinner->num_workers; j++) {
			pthread_create(&spinner->worker[j].context, NULL, worker_thread_kernel, &spinner->worker[j]);
			/*set affinity for this group*/
			status = pthread_setaffinity_np(spinner->worker[j].context, sizeof(cpu_set_t),
							&worker_threads_affinity_mask);
			if (status != 0) {
				log_fatal("failed to pin worker thread group %d", i);
				exit(EXIT_FAILURE);
			}
		}
		log_info("Pinned workers to spinning thread %d successfully", i);
	}

	log_info("Starting socket thread for listening to new connections...");
	if (pthread_create(&channel->cmthread, NULL, socket_thread, channel) != 0) {
		log_fatal("failed to spawn socket thread reason follows:\n");
		perror("Reason: \n");
		exit(EXIT_FAILURE);
	}
	log_info("Started socket thread successfully");
	pthread_t krm_server;

	log_info("New era has arrived initializing kreonR metadata server");
	if (pthread_create(&krm_server, NULL, krm_metadata_server, NULL)) {
		log_fatal("Failed to start metadata_server");
		exit(EXIT_FAILURE);
	}
	Set_OnConnection_Create_Function(globals_get_rdma_channel(), handle_task);
	stats_init(num_of_worker_threads);
	log_info("Kreon server ready");

	sem_init(&exit_main, 0, 0);
	sem_wait(&exit_main);

	log_info("kreonR server exiting\n");
	return 0;
}

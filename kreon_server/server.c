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
#include "../kreon_rdma/rdma.h"
#include "server_communication.h"
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

struct ds_worker_thread {
	utils_queue_s work_queue;
	sem_t sem;
	pthread_t context;
	pthread_spinlock_t work_queue_lock;
	struct channel_rdma *channel;
	//struct worker_group *my_group;
	int worker_id;
	int spinner_id;
	worker_status status;
};

#define DS_CLIENT_QUEUE_SIZE (UTILS_QUEUE_CAPACITY / 2)
#define DS_POOL_NUM 8

struct ds_task_buffer_pool {
	pthread_mutex_t tbp_lock;
	utils_queue_s task_buffers;
};

struct ds_spinning_thread {
	struct ds_task_buffer_pool ctb_pool[DS_POOL_NUM];
	struct ds_task_buffer_pool stb_pool[DS_POOL_NUM];
	struct ds_task_buffer_pool resume_task_pool[DS_POOL_NUM];
	pthread_t spinner_context;
	pthread_mutex_t conn_list_lock;
	SIMPLE_CONCURRENT_LIST *conn_list;
	SIMPLE_CONCURRENT_LIST *idle_conn_list;
	int num_workers;
	int next_server_worker_to_submit_job;
	int next_client_worker_to_submit_job;
	int c_last_pool;
	int s_last_pool;
	int id;
	struct ds_worker_thread worker[];
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
	struct krm_work_task task;
	struct _tucana_region_S *region;
	int standalone;
	volatile enum krm_work_task_status spill_task_status;
} spill_task_descriptor;

#ifdef TIERING
typedef struct replica_tiering_compaction_request {
	pthread_t tiering_compaction_context;
	_tucana_region_S *region;
	int level_id;
} tiering_compaction_request;
void tiering_compaction_worker(void *);
#endif

static void handle_task(struct krm_work_task *task);
static void ds_put_server_task_buffer(struct ds_spinning_thread *spinner, struct krm_work_task *task);
static void ds_put_client_task_buffer(struct ds_spinning_thread *spinner, struct krm_work_task *task);
static void ds_put_resume_task(struct ds_spinning_thread *spinner, struct krm_work_task *task);
/*inserts to Kreon and implements the replication logic*/
void insert_kv_pair(struct krm_work_task *task);

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
		// Block until a new connection request arrives
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
		ret = rdma_post_recv(new_conn_id, NULL, &incoming_connection_type, sizeof(connection_type), recv_mr);
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
			log_info("We have a new client connection request");
		} else if (incoming_connection_type == MASTER_TO_REPLICA_CONNECTION) {
			incoming_connection_type = REPLICA_TO_MASTER_CONNECTION;
			log_info("We have a new replica connection request");
		} else {
			log_fatal("bad connection type");
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
		case REPLICA_TO_MASTER_CONNECTION:
			conn->rdma_memory_regions = mrpool_allocate_memory_region(channel->dynamic_pool, new_conn_id);
			break;
		case MASTER_TO_REPLICA_CONNECTION:
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
static inline size_t diff_timespec_usec(struct timespec *start, struct timespec *stop)
{
	struct timespec result;
	if ((stop->tv_nsec - start->tv_nsec) < 0) {
		result.tv_sec = stop->tv_sec - start->tv_sec - 1;
		result.tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
	} else {
		result.tv_sec = stop->tv_sec - start->tv_sec;
		result.tv_nsec = stop->tv_nsec - start->tv_nsec;
	}
	return result.tv_sec * 1000000 + (size_t)(result.tv_nsec / (double)1000) + 1;
}

void *worker_thread_kernel(void *args)
{
	struct krm_work_task *job = NULL;
	struct ds_worker_thread *worker;
	const int spin_time_usec = globals_get_worker_spin_time_usec();

	pthread_setname_np(pthread_self(), "ds_worker");
	worker = (struct ds_worker_thread *)args;
	worker->status = BUSY;

	while (1) {
		// Get the next task from one of the task queues
		// If there are tasks pending, rotate between all queues
		// Try to get a task
		if (!(job = utils_queue_pop(&worker->work_queue))) {
			// Try for a few more usecs
			struct timespec start, end;
			int time = 0;
			clock_gettime(CLOCK_MONOTONIC, &start);
			while (time < spin_time_usec) {
				// I could have a for loop with a few iterations to avoid constantly calling clock_gettime
				if ((job = utils_queue_pop(&worker->work_queue)))
					break;
				clock_gettime(CLOCK_MONOTONIC, &end);
				time = diff_timespec_usec(&start, &end);
			}

			if (!job) {
#if 0
				// Go to sleep
				pthread_spin_lock(&worker->work_queue_lock);
				// Double check
				job = utils_queue_pop(&worker->work_queue);
				if (!job) {
					//#if 0
					worker->status = IDLE_SLEEPING;
					pthread_spin_unlock(&worker->work_queue_lock);
					worker->status = IDLE_SLEEPING;
					pthread_spin_unlock(&worker->work_queue_lock);
					// DPRINT("Sleeping...\n");
					sem_wait(&worker->sem);
					// DPRINT("Woke up\n");
					worker->status = BUSY;
					//#endif
					//pthread_spin_unlock(&worker_descriptor->work_queue_lock);
					worker->status = BUSY;
					continue;
				} else {
					assert(job);
					pthread_spin_unlock(&worker->work_queue_lock);
				}

#endif

				continue;
			}
		}

		/*process task*/
		handle_task(job);
		if (!job->suspended) {
			switch (job->kreon_operation_status) {
			case TASK_COMPLETE:
				_zero_rendezvous_locations(job->msg);
				__send_rdma_message(job->conn, job->reply_msg, NULL);
				switch (job->pool_type) {
				case KRM_CLIENT_POOL:
					ds_put_client_task_buffer(&dataserver->spinner[worker->spinner_id], job);
					break;
				case KRM_SERVER_POOL:
					ds_put_server_task_buffer(&dataserver->spinner[worker->spinner_id], job);
					break;
				}
				break;

			default:
				/*send it to spinning thread*/
				//log_info("Putting task %p away to be resumed pool id %d pool type %d spinner id %d",
				//	 job, job->pool_id, job->pool_type, worker->spinner_id);
				ds_put_resume_task(&dataserver->spinner[worker->spinner_id], job);
			}
		}
		job = NULL;
	}

	log_warn("worker thread exited");
	return NULL;
}

static inline int worker_queued_jobs(struct ds_worker_thread *worker)
{
	return utils_queue_used_slots(&worker->work_queue);
}

static struct krm_work_task *ds_get_server_task_buffer(struct ds_spinning_thread *spinner)
{
	struct krm_work_task *job = NULL;
	int idx = spinner->s_last_pool + 1;
	if (spinner->s_last_pool >= DS_POOL_NUM)
		idx = 0;

	int i = idx;
	while (1) {
		job = (struct krm_work_task *)utils_queue_pop(&spinner->stb_pool[i].task_buffers);
		if (job != NULL)
			break;

		++i;
		if (i == idx || DS_POOL_NUM == 1)
			//nothing found after a full round
			break;
		if (i >= DS_POOL_NUM)
			i = 0;
	}
	// reset task struct
	if (job) {
		spinner->c_last_pool = i;
		int job_idx = job->pool_id;
		int pool_type = job->pool_type;
		memset(job, 0, sizeof(struct krm_work_task));

		job->pool_id = job_idx;
		job->pool_type = pool_type;
		assert(job->pool_id < DS_POOL_NUM);
	}
	return job;
}

static void ds_put_server_task_buffer(struct ds_spinning_thread *spinner, struct krm_work_task *task)
{
	uint32_t pool_id = task->pool_id;
	pthread_mutex_lock(&spinner->stb_pool[pool_id].tbp_lock);
	if (utils_queue_push(&spinner->stb_pool[pool_id].task_buffers, task) == NULL) {
		log_fatal("Failed to add task buffer in pool id %d, this should not happen", pool_id);
		exit(EXIT_FAILURE);
	}
	pthread_mutex_unlock(&spinner->stb_pool[pool_id].tbp_lock);
	return;
}

static void ds_put_resume_task(struct ds_spinning_thread *spinner, struct krm_work_task *task)
{
	int pool_id = task->pool_id;
	pthread_mutex_lock(&spinner->resume_task_pool[pool_id].tbp_lock);
	if (utils_queue_push(&spinner->resume_task_pool[pool_id].task_buffers, task) == NULL) {
		log_fatal("failed to add to resumed task queue");
		exit(EXIT_FAILURE);
	}
	pthread_mutex_unlock(&spinner->resume_task_pool[pool_id].tbp_lock);
}

static struct krm_work_task *ds_get_client_task_buffer(struct ds_spinning_thread *spinner)
{
	struct krm_work_task *job = NULL;
	int idx = spinner->c_last_pool + 1;
	if (idx >= DS_POOL_NUM)
		idx = 0;

	int i = idx;
	while (1) {
		job = (struct krm_work_task *)utils_queue_pop(&spinner->ctb_pool[i].task_buffers);
		if (job != NULL)
			break;
		++i;
		if (i == idx || DS_POOL_NUM == 1)
			//nothing found after a full round
			break;
		if (i >= DS_POOL_NUM)
			i = 0;
	}

	// reset task struct
	if (job) {
		spinner->c_last_pool = i;
		int job_idx = job->pool_id;
		int pool_type = job->pool_type;
		memset(job, 0, sizeof(struct krm_work_task));

		job->pool_id = job_idx;
		job->pool_type = pool_type;
		assert(job->pool_id < DS_POOL_NUM);
	}
	return job;
}

static void ds_put_client_task_buffer(struct ds_spinning_thread *spinner, struct krm_work_task *task)
{
	uint32_t pool_id = task->pool_id;
	pthread_mutex_lock(&spinner->ctb_pool[pool_id].tbp_lock);
	if (utils_queue_push(&spinner->ctb_pool[pool_id].task_buffers, task) == NULL) {
		log_fatal("Failed to add task buffer in pool id %d, this should not happen", pool_id);
		exit(EXIT_FAILURE);
	}
	pthread_mutex_unlock(&spinner->ctb_pool[pool_id].tbp_lock);
	return;
}

static int assign_job_to_worker(struct ds_spinning_thread *spinner, struct connection_rdma *conn, msg_header *msg,
				struct krm_work_task *task)
{
	struct krm_work_task *job = NULL;
	uint8_t is_task_resumed;
	if (task == NULL) {
		is_task_resumed = 0;
		switch (msg->type) {
		case FLUSH_COMMAND_REQ:
		case FLUSH_COMMAND_REP:
		case SPILL_INIT:
		case SPILL_INIT_ACK:
		case SPILL_BUFFER_REQUEST:
		case SPILL_COMPLETE:
		case SPILL_COMPLETE_ACK:
		case GET_LOG_BUFFER_REQ:
		case GET_LOG_BUFFER_REP:

			job = (struct krm_work_task *)ds_get_server_task_buffer(spinner);
			break;
		default:
			job = (struct krm_work_task *)ds_get_client_task_buffer(spinner);
			break;
		}
	} else {
		job = task;
		is_task_resumed = 1;
	}
	if (!job) {
		//log_info("assign_job_to_worker failed!");
		return KREON_FAILURE;
	}

	struct ds_worker_thread *workers = spinner->worker;
	int worker_id = spinner->next_server_worker_to_submit_job;
	int max_queued_jobs = globals_get_job_scheduling_max_queue_depth(); // TODO [mvard] Tune this

#if 0
	/* Regular tasks scheduling policy
	 * Assign tasks to one worker until he is swamped, then start assigning
	 * to the next one. Once all workers are swamped it will essentially
	 * become a round robin policy since the worker_id will be incremented
	 * at for every task.
	 */
	// 1. Round robin with threshold
	if (worker_queued_jobs(&workers[worker_id]) >= max_queued_jobs) {
		/* Find an active worker with used_slots < max_queued_jobs
		 * If there's none, wake up a sleeping worker
		 * If all worker's are running, pick the one with least load
		 * NOTE a worker's work can only increase through this function call, which is only called by the spinning
		 * thread. Each worker is assigned to one spinning thread, therefore a worker can't wake up or have its
		 * work increased during the duration of a single call of this function
		 */

		// Find active worker with min worker_queued_jobs
		int current_choice = worker_id; // worker_id is most likely not sleeping
		int a_sleeping_worker_id = -1;
		for (int i = 0; i < WORKER_THREADS_PER_SPINNING_THREAD; ++i) {
			// Keep note of a sleeping worker in case we need to wake him up for this task
			if (workers[i].status == IDLE_SLEEPING) {
				if (a_sleeping_worker_id == -1)
					a_sleeping_worker_id = i;
				continue;
			}
			if (worker_queued_jobs(&workers[i]) < worker_queued_jobs(&workers[current_choice]))
				current_choice = i;
		}
#endif

	// 3. Round robin
	worker_id = spinner->next_server_worker_to_submit_job++;
	if (spinner->next_server_worker_to_submit_job == spinner->num_workers)
		spinner->next_server_worker_to_submit_job = 0;

	if (!is_task_resumed) {
		job->channel = globals_get_rdma_channel();
		job->conn = conn;
		job->msg = msg;
		job->kreon_operation_status = TASK_START;
		/*initialization of various fsm*/
		job->thread_id = worker_id;
		job->notification_addr = (void *)job->msg->request_message_local_addr;
	}

	if (utils_queue_push(&workers[worker_id].work_queue, (void *)job) == NULL) {
		// Give back the allocated job buffer
		switch (job->pool_type) {
		case KRM_SERVER_POOL:
			ds_put_server_task_buffer(spinner, job);
			break;
		case KRM_CLIENT_POOL:
			ds_put_client_task_buffer(spinner, job);
			log_info("Boom");
			break;
		default:
			log_fatal("Corrupted pool type of job");
			exit(EXIT_FAILURE);
		}
		return KREON_FAILURE;
	}

	pthread_spin_lock(&workers[worker_id].work_queue_lock);
	if (workers[worker_id].status == IDLE_SLEEPING) {
		/*wake him up */
		// DPRINT("Boom\n");
		++wake_up_workers_operations;
		sem_post(&workers[worker_id].sem);
	}
	pthread_spin_unlock(&workers[worker_id].work_queue_lock);
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
	pthread_setname_np(self, "spinner");
	log_info("Spinning thread %d initializing empty task buffers pool size %d, putting %d buffers per pool",
		 spinner->id, DS_POOL_NUM, DS_CLIENT_QUEUE_SIZE / DS_POOL_NUM);
	spinner->s_last_pool = DS_POOL_NUM;
	spinner->c_last_pool = DS_POOL_NUM;
	for (int i = 0; i < DS_POOL_NUM; i++) {
		pthread_mutex_init(&spinner->ctb_pool[i].tbp_lock, NULL);
		utils_queue_init(&spinner->ctb_pool[i].task_buffers);

		pthread_mutex_init(&spinner->stb_pool[i].tbp_lock, NULL);
		pthread_mutex_init(&spinner->stb_pool[i].tbp_lock, NULL);

		int size = DS_CLIENT_QUEUE_SIZE / DS_POOL_NUM;
		for (int j = 0; j < size; j++) {
			/*adding buffer to the server/client pool*/
			struct krm_work_task *work_task = (struct krm_work_task *)malloc(sizeof(struct krm_work_task));
			memset(work_task, 0x00, sizeof(struct krm_work_task));
			work_task->pool_id = i;
			work_task->pool_type = KRM_CLIENT_POOL;
			utils_queue_push(&spinner->ctb_pool[i].task_buffers, (void *)work_task);
			work_task = (struct krm_work_task *)malloc(sizeof(struct krm_work_task));
			memset(work_task, 0x00, sizeof(struct krm_work_task));
			work_task->pool_id = i;
			work_task->pool_type = KRM_SERVER_POOL;
			utils_queue_push(&spinner->stb_pool[i].task_buffers, (void *)work_task);
		}
	}
	/*Init my worker threads*/
	for (int j = 0; j < spinner->num_workers; j++) {
		/*init worker group vars*/
		pthread_spin_init(&spinner->worker[j].work_queue_lock, PTHREAD_PROCESS_PRIVATE);
		spinner->worker[j].worker_id = j;
		spinner->worker[j].status = WORKER_NOT_RUNNING;
		sem_init(&spinner->worker[j].sem, 0, 0);
		utils_queue_init(&spinner->worker[j].work_queue);
	}

	/*set the proper affinity for my workers*/
	cpu_set_t worker_threads_affinity_mask;
	CPU_ZERO(&worker_threads_affinity_mask);
	uint32_t start = spinner->id * (num_of_worker_threads / num_of_spinning_threads);
	for (uint32_t j = start; j < start + (num_of_worker_threads / num_of_spinning_threads); j++) {
		CPU_SET(worker_threads_core_ids[j], &worker_threads_affinity_mask);
		log_info("Pinning worker threads (belonging to spinning thread core id %llu) to core id %llu",
			 (LLU)spinning_threads_core_ids[spinner->id], (LLU)worker_threads_core_ids[j]);
	}
	/*create my workers*/
	for (int j = 0; j < spinner->num_workers; j++) {
		pthread_create(&spinner->worker[j].context, NULL, worker_thread_kernel, &spinner->worker[j]);
		/*set affinity for this group*/
		int status = pthread_setaffinity_np(spinner->worker[j].context, sizeof(cpu_set_t),
						    &worker_threads_affinity_mask);
		if (status != 0) {
			log_fatal("failed to pin workers for spinning thread %d", spinner->id);
			exit(EXIT_FAILURE);
		}
		log_info("Spinning thread %d Started worker %d", spinner->id, j);
	}
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
		int check_pending_tasks = 1;
		while (node != NULL) {
			/*check for resumed tasks to be rescheduled*/

			if (check_pending_tasks) {
				for (int i = 0; i < DS_POOL_NUM; i++) {
					struct krm_work_task *task;
					task = utils_queue_pop(&spinner->resume_task_pool[i].task_buffers);
					if (task != NULL) {
						assert(task->r_desc != NULL);
						//log_info("Rescheduling task");
						rc = assign_job_to_worker(spinner, task->conn, task->msg, task);
						if (rc == KREON_FAILURE) {
							//log_warn("Failed to reschedule task");
							utils_queue_push(&spinner->resume_task_pool[i].task_buffers,
									 task);
						}
					}
				}
				check_pending_tasks = 0;
			}
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

				if (hdr->type == SPILL_INIT_ACK || hdr->type == SPILL_COMPLETE_ACK) {
					msg_header *request = (msg_header *)hdr->request_message_local_addr;
					request->reply_message = hdr;
					request->ack_arrived = KR_REP_ARRIVED;
					/*No more waking ups, spill thread will poll (with yield) to see the message*/
					//sem_post(&((msg_header *)hdr->request_message_local_addr)->sem);
				} else {
					/*normal messages*/
					hdr->receive = 0;
					rc = assign_job_to_worker(spinner, conn, hdr, NULL);
					if (rc == KREON_FAILURE) {
						/*all workers are busy let's see messages from other connections*/
						__sync_fetch_and_sub(&conn->pending_received_messages, 1);
						/*Caution! message not consumed leave the rendezvous points as is*/
						hdr->receive = recv;
						goto iterate_next_element;
					}
				}

				/**
				 * Set the new rendezvous point, be careful for the case that the rendezvous is
				 * outsize of the rdma_memory_regions->remote_memory_buffer
				 * */
				_update_rendezvous_location(conn, message_size);
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
				//log_info("SERVER: Clients wants a reset ... D O N E");
				_zero_rendezvous_locations(hdr);
				conn->rendezvous = conn->rdma_memory_regions->remote_memory_buffer;
				goto iterate_next_element;
			} else if (recv == I_AM_CLIENT) {
				assert(conn->type == SERVER_TO_CLIENT_CONNECTION ||
				       conn->type == REPLICA_TO_MASTER_CONNECTION);
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
				__send_rdma_message(conn, msg, NULL);

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

void insert_kv_pair(struct krm_work_task *task)
{
	/*############## fsm state logic follows ###################*/
	while (1) {
		switch (task->kreon_operation_status) {
		case TASK_START:
		case TASK_SUSPENDED: {
			task->kreon_operation_status = GET_RSTATE;
			break;
		}

		case GET_RSTATE: {
			if (task->r_desc->region->num_of_backup) {
				if (task->r_desc->replica_bufs_initialized)
					task->kreon_operation_status = INS_TO_KREON;
				else {
					pthread_mutex_lock(&task->r_desc->region_lock);
					if (task->r_desc->region_halted) {
						/*suspend and return*/
						log_info("Suspending task %p key %s", task, task->key->key);
						task->suspended = 1;
						utils_queue_push(&task->r_desc->halted_tasks, task);
						pthread_mutex_unlock(&task->r_desc->region_lock);
						return;
					} else if (!task->r_desc->replica_bufs_initialized) {
						log_info("initializing log buffers with replicas");
						task->r_desc->region_halted = 1;
						task->kreon_operation_status = INIT_LOG_BUFFERS;

					} else
						task->kreon_operation_status = INS_TO_KREON;
					pthread_mutex_unlock(&task->r_desc->region_lock);
				}
			} else {
				/*log_info("No replicated region");*/
				task->kreon_operation_status = INS_TO_KREON;
			}
			break;
		}
		case INIT_LOG_BUFFERS: {
			struct krm_region_desc *r_desc = task->r_desc;
			if (r_desc->m_state == NULL) {
				r_desc->m_state = (struct ru_master_state *)malloc(
					sizeof(struct ru_master_state) +
					(r_desc->region->num_of_backup *
					 (sizeof(struct ru_master_log_buffer) +
					  (RU_REPLICA_NUM_SEGMENTS * sizeof(struct ru_master_log_buffer_seg)))));
				/*we need to dive into Kreon to check what in the current end of log.
				 * Since for this region we are the first to do this there is surely no concurrent access*/
				uint64_t range;
				if (r_desc->db->db_desc->KV_log_size > 0) {
					range = r_desc->db->db_desc->KV_log_size -
						(r_desc->db->db_desc->KV_log_size % SEGMENT_SIZE);
				} else
					range = 0;
				for (uint32_t i = 0; i < r_desc->region->num_of_backup; i++) {
					r_desc->m_state->r_buf[i].stat = RU_BUFFER_UNINITIALIZED;
					for (int j = 0; j < RU_REPLICA_NUM_SEGMENTS; j++) {
						r_desc->m_state->r_buf[i].segment[j].start = range;
						range += SEGMENT_SIZE;

						r_desc->m_state->r_buf[i].segment[j].end = range;
						r_desc->m_state->r_buf[i].segment[j].flush_cmd_stat =
							RU_BUFFER_UNINITIALIZED;
						memset(&r_desc->m_state->r_buf[i].segment[j].mr, 0x00,
						       sizeof(struct ibv_mr));
					}
				}
			}

			for (uint32_t i = 0; i < r_desc->region->num_of_backup; i++) {
				struct connection_rdma *conn =
					sc_get_conn(r_desc->region->backups[i].kreon_ds_hostname);

				if (r_desc->m_state->r_buf[i].stat == RU_BUFFER_UNINITIALIZED) {
					log_info("Sending get_log_buffer req to %s",
						 r_desc->region->backups[i].kreon_ds_hostname);
					r_desc->m_state->r_buf[i].p = sc_allocate_rpc_pair(
						conn,
						sizeof(struct msg_get_log_buffer_req) + r_desc->region->min_key_size,
						sizeof(struct msg_get_log_buffer_rep) +
							(RU_REPLICA_NUM_SEGMENTS * sizeof(struct ibv_mr)),
						GET_LOG_BUFFER_REQ);

					if (r_desc->m_state->r_buf[i].p.stat != ALLOCATION_IS_SUCCESSFULL)
						continue;
					else {
						/*inform the req about its buddy*/
						msg_header *req_header = r_desc->m_state->r_buf[i].p.request;
						msg_header *rep_header = r_desc->m_state->r_buf[i].p.reply;
						req_header->request_message_local_addr = req_header;
						req_header->ack_arrived = KR_REP_PENDING;
						/*location where server should put the reply*/
						req_header->reply =
							(char *)((uint64_t)rep_header -
								 (uint64_t)conn->recv_circular_buf->memory_region);
						req_header->reply_length = sizeof(msg_header) + rep_header->pay_len +
									   rep_header->padding_and_tail;
						/*time to send the message*/
						struct msg_get_log_buffer_req *g_req =
							(struct msg_get_log_buffer_req *)((uint64_t)req_header +
											  sizeof(struct msg_header));
						g_req->num_buffers = RU_REPLICA_NUM_SEGMENTS;
						g_req->buffer_size = SEGMENT_SIZE;
						g_req->region_key_size = r_desc->region->min_key_size;
						strcpy(g_req->region_key, r_desc->region->min_key);

						send_rdma_message_busy_wait(conn, req_header);

						log_info("DONE Sending get_log_buffer req to %s",
							 r_desc->region->backups[i].kreon_ds_hostname);
						r_desc->m_state->r_buf[i].stat = RU_BUFFER_REQUESTED;
					}
				}
			}
			//log_info("Checking log buffer replies num of replicas are %d", r_desc->region->num_of_backup);
			/*check possible replies*/
			uint32_t ready_buffers = 0;
			for (uint32_t i = 0; i < r_desc->region->num_of_backup; i++) {
				if (r_desc->m_state->r_buf[i].stat == RU_BUFFER_REQUESTED) {
					/*check reply and process*/
					//log_info("Waiting tail at offset: %d",
					//	 (sizeof(struct msg_header) +
					//	  r_desc->m_state->r_buf[i].p.reply->pay_len +
					//	  r_desc->m_state->r_buf[i].p.reply->padding_and_tail) -
					//		 TU_TAIL_SIZE);
					/*wait first for the header and then the payload*/
					if (r_desc->m_state->r_buf[i].p.reply->receive != TU_RDMA_REGULAR_MSG)
						continue;
					uint32_t *tail =
						(uint32_t *)(((uint64_t)r_desc->m_state->r_buf[i].p.reply +
							      sizeof(struct msg_header) +
							      r_desc->m_state->r_buf[i].p.reply->pay_len +
							      r_desc->m_state->r_buf[i].p.reply->padding_and_tail) -
							     TU_TAIL_SIZE);

					if (*tail == TU_RDMA_REGULAR_MSG) {
						struct msg_get_log_buffer_rep *rep =
							(struct msg_get_log_buffer_rep
								 *)(((uint64_t)r_desc->m_state->r_buf[i].p.reply) +
								    sizeof(struct msg_header));
						assert(rep->status == KREON_SUCCESS);
						r_desc->m_state->r_buf[i].segment_size = SEGMENT_SIZE;
						r_desc->m_state->r_buf[i].num_buffers = RU_REPLICA_NUM_SEGMENTS;
						uint64_t seg_offt = r_desc->db->db_desc->KV_log_size -
								    (r_desc->db->db_desc->KV_log_size % SEGMENT_SIZE);
						task->r_desc->next_segment_to_flush = seg_offt;
						for (int j = 0; j < RU_REPLICA_NUM_SEGMENTS; j++) {
							r_desc->m_state->r_buf[i].segment[j].start = seg_offt;
							seg_offt += SEGMENT_SIZE;
							r_desc->m_state->r_buf[i].segment[j].end = seg_offt;
							r_desc->m_state->r_buf[i].segment[j].mr = rep->mr[j];

							assert(r_desc->m_state->r_buf[i].segment[j].mr.length ==
							       SEGMENT_SIZE);
						}
						r_desc->m_state->r_buf[i].stat = RU_BUFFER_OK;
						/*finally free the message*/
						sc_free_rpc_pair(&r_desc->m_state->r_buf[i].p);
					}
				}
				if (r_desc->m_state->r_buf[i].stat == RU_BUFFER_OK)
					++ready_buffers;
			}
			if (ready_buffers == r_desc->region->num_of_backup) {
				pthread_mutex_lock(&task->r_desc->region_lock);
				for (uint32_t i = 0; i < r_desc->region->num_of_backup; i++)
					r_desc->m_state->r_buf[i].stat = RU_BUFFER_UNINITIALIZED;

				//log_info("Remote buffers ready initialize remote segments with current state");

				//1.prepare the context for the poller to later free the staff needed*/
				struct msg_recover_log_context *context = (struct msg_recover_log_context *)malloc(
					sizeof(struct msg_recover_log_context));
				context->header.type = RECOVER_LOG_CONTEXT;
				context->num_of_replies_needed = r_desc->region->num_of_backup;
				context->num_of_replies_received = 0;
				context->memory = malloc(SEGMENT_SIZE);
				//2. copy last segment to a register buffer
				struct segment_header *last_segment = (struct segment_header *)context->memory;
				memcpy(last_segment, (const char *)r_desc->db->db_desc->KV_log_last_segment,
				       SEGMENT_SIZE);
				struct connection_rdma *r_conn =
					sc_get_conn(r_desc->region->backups[0].kreon_ds_hostname);
				context->mr = rdma_reg_write(r_conn->rdma_cm_id, last_segment, SEGMENT_SIZE);
				if (context->mr == NULL) {
					log_fatal("Failed to reg memory");
					exit(EXIT_FAILURE);
				}

				for (int j = 0; j < r_desc->region->num_of_backup; j++) {
					r_conn = sc_get_conn(r_desc->region->backups[j].kreon_ds_hostname);
					//2. rdma it to the remote
					while (1) {
						int ret = rdma_post_write(
							r_conn->rdma_cm_id, context, last_segment, SEGMENT_SIZE,
							context->mr, IBV_SEND_SIGNALED,
							(uint64_t)r_desc->m_state->r_buf[j].segment[0].mr.addr,
							r_desc->m_state->r_buf[j].segment[0].mr.rkey);
						if (!ret) {
							break;
						}
						if (r_conn->status == CONNECTION_ERROR) {
							log_fatal("connection failed !: %s\n", strerror(errno));
							exit(EXIT_FAILURE);
						}
					}
				}
				r_desc->next_segment_to_flush = r_desc->db->db_desc->KV_log_size -
								(r_desc->db->db_desc->KV_log_size % SEGMENT_SIZE);
				log_info("Successfully sent the last segment to all the group");

				/*resume halted tasks*/
				log_info("Resuming halted tasks");
				struct krm_work_task *halted_task = utils_queue_pop(&r_desc->halted_tasks);
				while (halted_task != NULL) {
					halted_task->suspended = 0;
					log_info("Resuming task pool %d key is %s", halted_task->pool_id,
						 halted_task->key->key);
					ds_put_resume_task(&dataserver->spinner[task->spinner_id], halted_task);
					halted_task = utils_queue_pop(&r_desc->halted_tasks);
				}
				//log_info("*******************");

				task->r_desc->region_halted = 0;
				task->r_desc->replica_bufs_initialized = 1;
				pthread_mutex_unlock(&task->r_desc->region_lock);
				task->kreon_operation_status = INS_TO_KREON;
			} else {
				//log_info("Not all replicas ready waiting status %d suspended %d",
				//	 task->kreon_operation_status, task->suspended);
				return;
			}

			break;
		}
		case REGION_HALTED:
			break;
		case INS_TO_KREON: {
			task->ins_req.metadata.handle = task->r_desc->db;
			task->ins_req.metadata.kv_size = 0;
			task->ins_req.key_value_buf = task->key;
			task->ins_req.metadata.level_id = 0;
			task->ins_req.metadata.key_format = KV_FORMAT;
			task->ins_req.metadata.append_to_log = 1;
			task->ins_req.metadata.gc_request = 0;
			task->ins_req.metadata.recovery_request = 0;
			task->ins_req.metadata.segment_full_event = 0;
			_insert_key_value(&task->ins_req);
			if (task->r_desc->region->num_of_backup > 0) {
				if (task->ins_req.metadata.segment_full_event)
					task->kreon_operation_status = FLUSH_REPLICA_BUFFERS;
				else
					task->kreon_operation_status = REPLICATE;
				break;
			} else {
				task->kreon_operation_status = TASK_COMPLETE;
				return;
			}
		}

		case FLUSH_REPLICA_BUFFERS: {
			struct krm_region_desc *r_desc = task->r_desc;
			pthread_mutex_lock(&task->r_desc->region_lock);
			/*Is it my turn to flush or can I resume?*/
			if (task->ins_req.metadata.log_offset_full_event >= r_desc->next_segment_to_flush &&
			    task->ins_req.metadata.log_offset_full_event <=
				    r_desc->next_segment_to_flush + SEGMENT_SIZE) {
				//log_info("Ok my turn to flush proceeding");
				task->r_desc->region_halted = 1;
				pthread_mutex_unlock(&task->r_desc->region_lock);
			} else {
				//log_info("Not my turn my seg addr is %llu next to flush is %llu resuming later",
				//	 task->ins_req.metadata.log_offset_full_event, r_desc->next_segment_to_flush);
				pthread_mutex_unlock(&task->r_desc->region_lock);
				return;
			}
			/*find out the idx of the buffer that needs flush*/
			task->seg_id_to_flush = -1;

			for (int i = 0; i < RU_REPLICA_NUM_SEGMENTS; i++) {
				if (task->ins_req.metadata.log_offset_full_event >=
					    r_desc->m_state->r_buf[0].segment[i].start &&
				    task->ins_req.metadata.log_offset_full_event <=
					    r_desc->m_state->r_buf[0].segment[i].end) {
					task->seg_id_to_flush = i;
					break;
				} //else {
				//log_info("not a good fit start %llu event %llu end %llu",
				//	 r_desc->m_state->r_buf[0].segment[i].start,
				//	 task->ins_req.metadata.log_offset_full_event,
				//	 r_desc->m_state->r_buf[0].segment[i].end);
				//}
			}

			if (task->seg_id_to_flush == -1) {
				log_fatal("No appropriate remote segment id found for flush, what?");
				exit(EXIT_FAILURE);
			}
			//log_info("Flushing id %d Kreon log was at %llu", task->seg_id_to_flush,
			//	 task->ins_req.metadata.log_offset_full_event);
			/*sent flush command to all motherfuckers*/
			task->kreon_operation_status = SEND_FLUSH_COMMANDS;
			break;
		}

		case SEND_FLUSH_COMMANDS: {
			struct krm_region_desc *r_desc = task->r_desc;
			for (int i = 0; i < r_desc->region->num_of_backup; i++) {
				struct connection_rdma *r_conn = NULL;
				/*allocate and send command*/
				if (r_desc->m_state->r_buf[i].segment[task->seg_id_to_flush].flush_cmd_stat ==
				    RU_BUFFER_UNINITIALIZED) {
					r_conn = sc_get_conn(r_desc->region->backups[i].kreon_ds_hostname);
					uint32_t req_size =
						sizeof(struct msg_flush_cmd_req) + r_desc->region->min_key_size;
					uint32_t rep_size = sizeof(struct msg_flush_cmd_rep);
					r_desc->m_state->r_buf[i].segment[task->seg_id_to_flush].flush_cmd =
						sc_allocate_rpc_pair(r_conn, req_size, rep_size, FLUSH_COMMAND_REQ);

					if (r_desc->m_state->r_buf[i].segment[task->seg_id_to_flush].flush_cmd.stat !=
					    ALLOCATION_IS_SUCCESSFULL)
						return;

					msg_header *req_header = r_desc->m_state->r_buf[i]
									 .segment[task->seg_id_to_flush]
									 .flush_cmd.request;
					msg_header *rep_header =
						r_desc->m_state->r_buf[i].segment[task->seg_id_to_flush].flush_cmd.reply;
					req_header->request_message_local_addr = req_header;
					req_header->ack_arrived = KR_REP_PENDING;
					/*location where server should put the reply*/
					req_header->reply =
						(char *)((uint64_t)rep_header -
							 (uint64_t)r_conn->recv_circular_buf->memory_region);
					req_header->reply_length =
						sizeof(msg_header) + rep_header->pay_len + rep_header->padding_and_tail;
					/*time to send the message*/
					struct msg_flush_cmd_req *f_req =
						(struct msg_flush_cmd_req *)((uint64_t)req_header +
									     sizeof(struct msg_header));

					/*where primary has stored its segment*/
					f_req->log_buffer_id = task->seg_id_to_flush;
					f_req->master_segment = task->ins_req.metadata.log_segment_addr;
					f_req->segment_id = task->ins_req.metadata.segment_id;
					f_req->end_of_log = task->ins_req.metadata.end_of_log;
					f_req->log_padding = task->ins_req.metadata.log_padding;
					f_req->region_key_size = r_desc->region->min_key_size;
					strcpy(f_req->region_key, r_desc->region->min_key);

					send_rdma_message_busy_wait(r_conn, req_header);
					r_desc->m_state->r_buf[i].stat = RU_BUFFER_REQUESTED;
					//log_info("Sent flush command req_header %llu", req_header);
				}
			}
			task->kreon_operation_status = WAIT_FOR_FLUSH_REPLIES;
			break;
		}

		case WAIT_FOR_FLUSH_REPLIES: {
			struct krm_region_desc *r_desc = task->r_desc;
			for (int i = 0; i < r_desc->region->num_of_backup; i++) {
				/*check if header is there*/
				msg_header *reply =
					r_desc->m_state->r_buf[i].segment[task->seg_id_to_flush].flush_cmd.reply;

				if (reply->receive != TU_RDMA_REGULAR_MSG)
					return;
				/*check if payload is there*/

				uint32_t *tail = (uint32_t *)(((uint64_t)reply + sizeof(struct msg_header) +
							       reply->pay_len + reply->padding_and_tail) -
							      TU_TAIL_SIZE);

				if (*tail != TU_RDMA_REGULAR_MSG)
					return;
			}
			/*got all replies motherfuckers*/
			pthread_mutex_lock(&task->r_desc->region_lock);
			r_desc->next_segment_to_flush += SEGMENT_SIZE;
			//pthread_mutex_unlock(&task->r_desc->region_lock);

			for (int i = 0; i < r_desc->region->num_of_backup; i++) {
				r_desc->m_state->r_buf[i].segment[task->seg_id_to_flush].start +=
					(RU_REPLICA_NUM_SEGMENTS * SEGMENT_SIZE);
				r_desc->m_state->r_buf[i].segment[task->seg_id_to_flush].end +=
					(RU_REPLICA_NUM_SEGMENTS * SEGMENT_SIZE);
				sc_free_rpc_pair(&r_desc->m_state->r_buf[i].segment[task->seg_id_to_flush].flush_cmd);
			}
			//log_info("Resume possible halted tasks after flush");
			//pthread_mutex_lock(&r_desc->region_lock);
			r_desc->region_halted = 0;
			struct krm_work_task *halted_task = utils_queue_pop(&task->r_desc->halted_tasks);
			while (halted_task != NULL) {
				halted_task->suspended = 0;
				ds_put_resume_task(&dataserver->spinner[task->spinner_id], halted_task);
				halted_task = utils_queue_pop(&task->r_desc->halted_tasks);
			}
			pthread_mutex_unlock(&r_desc->region_lock);
			task->kreon_operation_status = REPLICATE;
			break;
		}

		case REPLICATE: {
			struct krm_region_desc *r_desc = task->r_desc;
			uint32_t kv_size;
			kv_size = task->key->key_size + sizeof(struct msg_put_key);
			kv_size = kv_size + task->value->value_size + sizeof(struct msg_put_value);
			uint32_t remote_offset;
			if (task->ins_req.metadata.log_offset > 0)
				remote_offset = task->ins_req.metadata.log_offset % SEGMENT_SIZE;
			else
				remote_offset = 0;
			uint32_t done = 0;
		retry:
			for (int i = 0; i < task->r_desc->region->num_of_backup; i++) {
				/*find appropriate seg buffer to rdma the mutation*/
				for (int j = 0; j < RU_REPLICA_NUM_SEGMENTS; j++) {
					if (task->ins_req.metadata.log_offset >=
						    r_desc->m_state->r_buf[i].segment[j].start &&
					    task->ins_req.metadata.log_offset <=
						    r_desc->m_state->r_buf[i].segment[j].end) {
						/*rdma the fucking thing*/
						struct connection_rdma *r_conn =
							sc_get_conn(r_desc->region->backups[i].kreon_ds_hostname);

						int ret;
						while (1) {
							ret = rdma_post_write(
								r_conn->rdma_cm_id, NULL, task->key, kv_size,
								task->conn->rdma_memory_regions->remote_memory_region,
								IBV_SEND_SIGNALED,
								(uint64_t)r_desc->m_state->r_buf[i].segment[j].mr.addr +
									remote_offset,
								r_desc->m_state->r_buf[i].segment[j].mr.rkey);
							if (!ret) {
								break;
							}
							if (r_conn->status == CONNECTION_ERROR) {
								log_fatal("connection failed !: %s\n", strerror(errno));
								exit(EXIT_FAILURE);
							}
						}
						done = 1;
						break;
					} else {
						/*log_info(
							"Cannot RDMA flush in progress? state of remote buffers follow");

						for (int i = 0; i < task->r_desc->region->num_of_backup; i++) {
							for (int j = 0; j < RU_REPLICA_NUM_SEGMENTS; j++) {
								log_info("replica[%d].seg[%d].start = %llu", i, j,
									 r_desc->m_state->r_buf[i].segment[j].start);
								log_info("log addr to replicate %llu",
									 task->ins_req.metadata.log_offset);
								log_info("replica[%d].seg[%d].end = %llu", i, j,
									 r_desc->m_state->r_buf[i].segment[j].end);
							}
						}

				*/
					}
				}
			}
			if (!done) {
				/*seems some segment flushes at the replicas..., check if region is halted otherwise retry*/
				pthread_mutex_lock(&r_desc->region_lock);
				if (r_desc->region_halted) {
					log_info("halting task region waits for flush");
					task->suspended = 1;
					if (utils_queue_push(&r_desc->halted_tasks, task) == NULL) {
						log_fatal("failed to add task to halt queue");
						exit(EXIT_FAILURE);
					}
					pthread_mutex_unlock(&r_desc->region_lock);
					return;
				} else {
					pthread_mutex_unlock(&r_desc->region_lock);
					//goto retry;
					return;
				}
			}

			task->kreon_operation_status = TASK_COMPLETE;
			break;
		}
		case TASK_COMPLETE:
			return;

		default:
			log_fatal("Ended up in faulty state");
			assert(0);
			return;
		}
	}
}

/*
 * KreonR main processing function of networkrequests.
 * Each network processing request must be resumable. For each message type KreonR process it via
 * a specific data path. We treat all taks related to network  as paths that may fail, that we can resume later. The idea
 * behind this
 * */
static void handle_task(struct krm_work_task *task)
{
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


		case SCAN_REQUEST:
			task->reply_msg = Server_Scan_MulipleRegions_RDMA(task->msg, rdma_conn);
			task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;
			break;

			/*
			 * Kind reminder, SPILL_INIT, SPILL_BUFFER_REQUEST, and SPILL_COMPLETE are handled by the server
			 * which has backup role for the given region
			 */
#endif
	case GET_LOG_BUFFER_REQ: {
		void *addr;
		struct msg_get_log_buffer_req *get_log =
			(struct msg_get_log_buffer_req *)((uint64_t)task->msg + sizeof(struct msg_header));
		log_info("Region master wants a log buffer for region %s key size %d", get_log->region_key,
			 get_log->region_key_size);
		struct krm_region_desc *r_desc = krm_get_region(get_log->region_key, get_log->region_key_size);
		if (r_desc == NULL) {
			log_fatal("no hosted region found for min key %s", get_log->region_key);
			exit(EXIT_FAILURE);
		}
		pthread_mutex_lock(&r_desc->region_lock);
		if (r_desc->r_state == NULL) {
			r_desc->r_state = (struct ru_replica_state *)malloc(
				sizeof(struct ru_replica_state) +
				(get_log->num_buffers * sizeof(struct ru_replica_log_buffer_seg)));
			r_desc->r_state->num_buffers = get_log->num_buffers;
			for (int i = 0; i < get_log->num_buffers; i++) {
				addr = malloc(get_log->buffer_size);
				r_desc->r_state->seg[i].segment_size = get_log->buffer_size;
				r_desc->r_state->seg[i].mr =
					rdma_reg_write(task->conn->rdma_cm_id, addr, get_log->buffer_size);
			}
			/*what is the next segment id that we should expect (for correctness reasons)*/
			if (r_desc->db->db_desc->KV_log_size > 0 &&
			    r_desc->db->db_desc->KV_log_size % SEGMENT_SIZE == 0)
				r_desc->r_state->next_segment_id_to_flush =
					r_desc->db->db_desc->KV_log_last_segment->segment_id + 1;
			else
				r_desc->r_state->next_segment_id_to_flush =
					r_desc->db->db_desc->KV_log_last_segment->segment_id;
		} else {
			log_fatal("remote buffers already initialized, what?");
			exit(EXIT_FAILURE);
		}

		pthread_mutex_unlock(&r_desc->region_lock);

		task->reply_msg = (void *)((uint64_t)task->conn->rdma_memory_regions->local_memory_buffer +
					   (uint64_t)task->msg->reply);
		/*initialize message*/
		task->reply_msg->pay_len =
			sizeof(struct msg_get_log_buffer_rep) + (get_log->num_buffers * sizeof(struct ibv_mr));

		actual_reply_size = sizeof(msg_header) + task->reply_msg->pay_len + TU_TAIL_SIZE;
		padding = MESSAGE_SEGMENT_SIZE - (actual_reply_size % MESSAGE_SEGMENT_SIZE);
		/*set tail to the proper value*/
		//log_info("Setting tail to offset %d", actual_reply_size + (padding - TU_TAIL_SIZE));
		*(uint32_t *)((uint64_t)task->reply_msg + actual_reply_size + (padding - TU_TAIL_SIZE)) =
			TU_RDMA_REGULAR_MSG;
		task->reply_msg->padding_and_tail = padding + TU_TAIL_SIZE;
		task->reply_msg->data = (void *)((uint64_t)task->reply_msg + sizeof(msg_header));
		task->reply_msg->next = task->reply_msg->data;

		task->reply_msg->type = GET_LOG_BUFFER_REP;

		task->reply_msg->ack_arrived = KR_REP_PENDING;
		task->reply_msg->receive = TU_RDMA_REGULAR_MSG;
		task->reply_msg->local_offset = (uint64_t)task->msg->reply;
		task->reply_msg->remote_offset = (uint64_t)task->msg->reply;
		task->reply_msg->callback_function = NULL;

		struct msg_get_log_buffer_rep *rep =
			(struct msg_get_log_buffer_rep *)((uint64_t)task->reply_msg + sizeof(msg_header));
		rep->status = KREON_SUCCESS;
		rep->num_buffers = get_log->num_buffers;
		for (int i = 0; i < rep->num_buffers; i++) {
			rep->mr[i] = *r_desc->r_state->seg[i].mr;
		}

		/*piggyback info for use with the client*/
		task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;
		assert(task->reply_msg->request_message_local_addr != NULL);
		log_info("Region master wants a log buffer...DONE");
		task->kreon_operation_status = TASK_COMPLETE;
		break;
	}

	case FLUSH_COMMAND_REQ: {
		//log_info("Master orders a flush, obey your master!");
		struct msg_flush_cmd_req *flush_req =
			(struct msg_flush_cmd_req *)((uint64_t)task->msg + sizeof(struct msg_header));

		struct krm_region_desc *r_desc = krm_get_region(flush_req->region_key, flush_req->region_key_size);
		if (r_desc->r_state == NULL) {
			log_fatal("No state for backup region %s", r_desc->region->id);
			exit(EXIT_FAILURE);
		}
		struct segment_header *seg =
			(struct segment_header *)r_desc->r_state->seg[flush_req->log_buffer_id].mr->addr;
		seg->segment_id = flush_req->segment_id;

		if (flush_req->log_padding)
			memset((void *)((uint64_t)seg + (SEGMENT_SIZE - flush_req->log_padding)), 0x00,
			       flush_req->log_padding);

		pthread_mutex_lock(&r_desc->db->db_desc->lock_log);
		/*Now take a segment from the allocator and copy the buffer*/
		volatile segment_header *last_log_segment = r_desc->db->db_desc->KV_log_last_segment;

		if (r_desc->r_state->next_segment_id_to_flush != flush_req->segment_id) {
			log_fatal("Corruption non-contiguous segment ids: expected %llu  got flush_req id is %llu",
				  r_desc->r_state->next_segment_id_to_flush, flush_req->segment_id);
			exit(EXIT_FAILURE);
		}
		++r_desc->r_state->next_segment_id_to_flush;
		segment_header *disk_segment = seg_get_raw_log_segment(r_desc->db->volume_desc);
		memcpy(disk_segment, seg, SEGMENT_SIZE);
		disk_segment->next_segment = NULL;
		disk_segment->prev_segment = (segment_header *)((uint64_t)last_log_segment - MAPPED);

		if (r_desc->db->db_desc->KV_log_first_segment == NULL)
			r_desc->db->db_desc->KV_log_first_segment = disk_segment;

		r_desc->db->db_desc->KV_log_last_segment = disk_segment;
		r_desc->db->db_desc->KV_log_size += SEGMENT_SIZE;

		pthread_mutex_unlock(&r_desc->db->db_desc->lock_log);
		/*time for reply :-)*/

		task->reply_msg = (void *)((uint64_t)task->conn->rdma_memory_regions->local_memory_buffer +
					   (uint64_t)task->msg->reply);

		/*piggyback info for use with the client*/
		task->reply_msg->pay_len = sizeof(struct msg_flush_cmd_rep);

		actual_reply_size = sizeof(msg_header) + sizeof(msg_delete_rep) + TU_TAIL_SIZE;
		padding = MESSAGE_SEGMENT_SIZE - (actual_reply_size % MESSAGE_SEGMENT_SIZE);
		/*set tail to the proper value*/
		*(uint32_t *)((uint64_t)task->reply_msg + actual_reply_size + (padding - TU_TAIL_SIZE)) =
			TU_RDMA_REGULAR_MSG;
		task->reply_msg->padding_and_tail = padding + TU_TAIL_SIZE;
		task->reply_msg->data = (void *)((uint64_t)task->reply_msg + sizeof(msg_header));
		task->reply_msg->next = task->reply_msg->data;

		task->reply_msg->type = FLUSH_COMMAND_REP;

		task->reply_msg->ack_arrived = KR_REP_PENDING;
		task->reply_msg->receive = TU_RDMA_REGULAR_MSG;
		task->reply_msg->local_offset = (uint64_t)task->msg->reply;
		task->reply_msg->remote_offset = (uint64_t)task->msg->reply;
		task->reply_msg->callback_function = NULL;
		struct msg_flush_cmd_rep *flush_rep =
			(struct msg_flush_cmd_rep *)((uint64_t)task->reply_msg + sizeof(msg_header));
		flush_rep->status = KREON_SUCCESS;
		task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;
		task->kreon_operation_status = TASK_COMPLETE;
		//log_info("Responded to server!");
		break;
	}

	case PUT_OFFT_REQUEST: {
		if (task->key == NULL) {
			put_offt_req = (msg_put_offt_req *)task->msg->data;
			msg_put_key *K = (msg_put_key *)((uint64_t)put_offt_req + sizeof(msg_put_offt_req));
			msg_put_value *V = (msg_put_value *)((uint64_t)K + sizeof(msg_put_key) + K->key_size);
			r_desc = krm_get_region(K->key, K->key_size);
			if (r_desc == NULL) {
				log_fatal("Region not found for key size %u:%s", K->key_size, K->key);
				exit(EXIT_FAILURE);
			}
			task->r_desc = (void *)r_desc;
			/*inside kreon now*/
			//log_info("offset %llu key %s", put_offt_req->offset, K->key);
			uint32_t new_size = put_offt_req->offset + sizeof(msg_put_key) + K->key_size +
					    sizeof(msg_put_value) + V->value_size;
			if (new_size <= SEGMENT_SIZE - sizeof(segment_header)) {
				value = __find_key(r_desc->db, put_offt_req->kv, SEARCH_DIRTY_TREE);

				void *new_value = malloc(SEGMENT_SIZE -
							 sizeof(segment_header)); /*remove this later when test passes*/
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
				task->key = new_value;
			}
		}

		insert_kv_pair(task);
		if (task->kreon_operation_status == TASK_COMPLETE) {
			free(task->key);

			task->reply_msg = (void *)((uint64_t)task->conn->rdma_memory_regions->local_memory_buffer +
						   (uint64_t)task->msg->reply);
			/*initialize message*/
			actual_reply_size = sizeof(msg_header) + sizeof(msg_put_offt_rep) + TU_TAIL_SIZE;
			if (task->msg->reply_length >= actual_reply_size) {
				padding = MESSAGE_SEGMENT_SIZE - (actual_reply_size % MESSAGE_SEGMENT_SIZE);
				/*set tail to the proper value*/
				*(uint32_t *)((uint64_t)task->reply_msg + actual_reply_size - (TU_TAIL_SIZE) +
					      padding) = TU_RDMA_REGULAR_MSG;

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
				log_fatal("SERVER: mr CLIENT reply space not enough  size %" PRIu32
					  " FIX XXX TODO XXX\n",
					  task->msg->reply_length);
				exit(EXIT_FAILURE);
			}

			/*piggyback info for use with the client*/
			task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;
			assert(task->reply_msg->request_message_local_addr != NULL);
		}
		break;
	}
	case PUT_REQUEST:

		/* retrieve region handle for the corresponding key, find_region
		 * initiates internally rdma connections if needed
		 */
		if (task->key == NULL) {
			task->key = (msg_put_key *)((uint64_t)task->msg + sizeof(struct msg_header));
			task->value =
				(msg_put_value *)((uint64_t)task->key + sizeof(msg_put_key) + task->key->key_size);
			key_length = task->key->key_size;
			assert(key_length != 0);
			r_desc = krm_get_region(task->key->key, task->key->key_size);
			if (r_desc == NULL) {
				log_fatal("Region not found for key size %u:%s", task->key->key_size, task->key->key);
				exit(EXIT_FAILURE);
			}

			task->r_desc = (void *)r_desc;
		}
		insert_kv_pair(task);
		if (task->kreon_operation_status == TASK_COMPLETE) {
			/*prepare the reply*/
			task->reply_msg = (void *)((uint64_t)task->conn->rdma_memory_regions->local_memory_buffer +
						   (uint64_t)task->msg->reply);

			if (task->msg->reply_length >= actual_reply_size) {
				task->reply_msg->pay_len = sizeof(msg_put_rep);

				actual_reply_size = sizeof(msg_header) + sizeof(msg_put_rep) + TU_TAIL_SIZE;
				padding = MESSAGE_SEGMENT_SIZE - (actual_reply_size % MESSAGE_SEGMENT_SIZE);
				/*set tail to the proper value*/
				*(uint32_t *)((uint64_t)task->reply_msg + actual_reply_size +
					      (padding - TU_TAIL_SIZE)) = TU_RDMA_REGULAR_MSG;
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
				log_fatal("SERVER: mr CLIENT reply space not enough  size %" PRIu32
					  " FIX XXX TODO XXX\n",
					  task->msg->reply_length);
				exit(EXIT_FAILURE);
			}
			/*piggyback info for use with the client*/
			task->reply_msg->request_message_local_addr = task->msg->request_message_local_addr;
			assert(task->reply_msg->request_message_local_addr != NULL);
		}
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
		task->kreon_operation_status = TASK_COMPLETE;

		if (delete_key(r_desc->db, del_req->key, del_req->key_size) == SUCCESS) {
			del_rep->status = KREON_SUCCESS;
			//log_info("Deleted key %s successfully", del_req->key);
		} else {
			del_rep->status = KREON_FAILURE;
			//log_info("Deleted key %s not found!", del_req->key);
		}
		break;
	}

	case GET_REQUEST:
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
		//for (int k = 0; k < 10; k++) {
		value = __find_key(r_desc->db, &get_req->key_size, SEARCH_DIRTY_TREE);
		//if (value != NULL)
		//	break;
		//}

		if (value == NULL) {
			log_warn("key not found key %s : length %u", get_req->key, get_req->key_size);

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
		task->reply_msg->type = GET_REPLY;
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
		task->kreon_operation_status = TASK_COMPLETE;
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
		task->kreon_operation_status = TASK_COMPLETE;
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
			task->kreon_operation_status = TASK_COMPLETE;
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
	default:
		log_fatal("unknown operation %d", task->msg->type);
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
	char *mount_point;
	//uint64_t device_size;
	//globals_set_zk_host(zookeeper_host_port);
	RDMA_LOG_BUFFER_PADDING = 0;
	RDMA_TOTAL_LOG_BUFFER_SIZE = TU_HEADER_SIZE + BUFFER_SEGMENT_SIZE + 4096 + TU_TAIL_SIZE;

	if (RDMA_TOTAL_LOG_BUFFER_SIZE % MESSAGE_SEGMENT_SIZE != 0) {
		/*need to pad */
		RDMA_LOG_BUFFER_PADDING = (MESSAGE_SEGMENT_SIZE - (RDMA_TOTAL_LOG_BUFFER_SIZE % MESSAGE_SEGMENT_SIZE));
		RDMA_TOTAL_LOG_BUFFER_SIZE += RDMA_LOG_BUFFER_PADDING;
		assert(RDMA_TOTAL_LOG_BUFFER_SIZE % MESSAGE_SEGMENT_SIZE == 0);
	}

	if (argc == 8) {
		int rdma_port = strtol(argv[1], NULL, 10);
		globals_set_RDMA_connection_port(rdma_port);
		device_name = argv[2];
		globals_set_dev(device_name);
		mount_point = argv[3];
		globals_set_mount_point(mount_point);
		globals_set_zk_host(argv[4]);
		globals_set_RDMA_IP_filter(argv[5]);
		_str_split(argv[6], ',', &spinning_threads_core_ids, &num_of_spinning_threads);
		_str_split(argv[7], ',', &worker_threads_core_ids, &num_of_worker_threads);
	} else {
		log_fatal(
			"Error: usage: ./kreon_server <port number> <device name> <mount point> <zk_host:zk_port> <RDMA_IP_prefix> <spinning thread core ids>  <working thread core ids>\n");
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
					    (WORKER_THREADS_PER_SPINNING_THREAD * sizeof(struct ds_worker_thread)))));
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
	stats_init(num_of_worker_threads);
	log_info("Kreon server ready");

	sem_init(&exit_main, 0, 0);
	sem_wait(&exit_main);

	log_info("kreonR server exiting\n");
	return 0;
}

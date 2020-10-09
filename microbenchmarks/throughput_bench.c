#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <immintrin.h>
#include <unistd.h>
#include <log.h>
#include "../kreon_rdma_client/client_utils.h"
#include "../kreon_rdma_client/kreon_rdma_client.h"
#include "../kreon_server/globals.h"
#include "../utilities/latency_monitor.h"
#include <log.h>

unsigned Threads = 1;
int Time = 60;
int Message_size = 16 * 1024 - TU_HEADER_SIZE - sizeof(uint32_t);
uint64_t Sleep_interval = 0;
int Outstanding_requests = 128;
char *Zookeeper_service;
volatile int *Sent_messages = NULL, *Received_messages = NULL;

pthread_t *Pthreads;
volatile char Thread_exit = 0;

typedef struct {
	msg_header *reply;
	connection_rdma *conn;
#if LATENCY_MONITOR_ENABLED
	lat_t start_time;
#endif
} krc_post_handle;

typedef enum { KRC_POST_SUCCESS = 0, KRC_POST_INVALID_HANDLE, KRC_POST_RDMA_FAIL, KRC_POST_OUT_OF_MEM } krc_post_status;

krc_post_status krc_post_ping(connection_rdma *conn, int message_size, krc_post_handle *handle)
{
	msg_header *req_header;
	msg_header *rep_header;

	if (!handle)
		return -KRC_POST_INVALID_HANDLE;

	pthread_mutex_lock(&conn->buffer_lock);
	req_header = client_try_allocate_rdma_message(conn, message_size, TEST_REQUEST);
	if (!req_header) {
		pthread_mutex_unlock(&conn->buffer_lock);
		return -KRC_POST_OUT_OF_MEM;
	}

	/*Now the reply part*/
	rep_header = client_try_allocate_rdma_message(conn, sizeof(msg_header), TEST_REPLY);
	if (!rep_header) {
		uint32_t size;
		if (req_header->pay_len == 0) {
			size = MESSAGE_SEGMENT_SIZE;
		} else {
			size = TU_HEADER_SIZE + req_header->pay_len + req_header->padding_and_tail;
			assert(size % MESSAGE_SEGMENT_SIZE == 0);
		}
		free_space_from_circular_buffer(conn->send_circular_buf, (char *)req_header, size);
		pthread_mutex_unlock(&conn->buffer_lock);
		return -KRC_POST_OUT_OF_MEM;
	}
	pthread_mutex_unlock(&conn->buffer_lock);
	rep_header->receive = 0;

	/*inform the req about its buddy*/
	req_header->request_message_local_addr = req_header;
	req_header->ack_arrived = KR_REP_PENDING;
	/*location where server should put the reply*/
	req_header->reply = (char *)((uint64_t)rep_header - (uint64_t)conn->recv_circular_buf->memory_region);
	req_header->reply_length = sizeof(msg_header) + rep_header->pay_len + rep_header->padding_and_tail;

	/*send the actual put*/
#if LATENCY_MONITOR_ENABLED
	latmon_start(&handle->start_time);
#endif
	if (send_rdma_message_busy_wait(conn, req_header) != KREON_SUCCESS) {
		log_warn("failed to send message");
		return -KRC_POST_RDMA_FAIL;
	}

	handle->conn = conn;
	handle->reply = rep_header;

	return KRC_POST_SUCCESS;
}

static inline int krc_poll_ping_reply(krc_post_handle *handle)
{
	// Check if ping reply header has arrived
	if (handle->reply->receive != TU_RDMA_REGULAR_MSG)
		return 0;

	handle->reply->receive = 0;
	_zero_rendezvous_locations(handle->reply);
	client_free_rpc_pair(handle->conn, handle->reply);
	return 1;
}

krc_post_status krc_ping(connection_rdma *conn, int message_size)
{
	krc_post_handle handle;
	krc_post_status ret = krc_post_ping(conn, message_size, &handle);
	if (ret != KRC_POST_SUCCESS)
		return ret;

	while (!krc_poll_ping_reply(&handle))
		;

#if LATENCY_MONITOR_ENABLED
	latmon_end(&handle.start_time);
#endif
	return KRC_POST_SUCCESS;
}

extern struct cu_regions client_regions;

void *bench(void *int_thread_id)
{
	uint32_t connections_per_thread = globals_get_connections_per_server() / Threads;
	int current_connection = 0;
	const uint64_t tid = (uint64_t)int_thread_id;
	connection_rdma *conn;
	struct cu_region_desc *r_desc = cu_get_first_region();
	// ping_handles is used as a circular buffer. head, tail & full are its state variables
#if !LATENCY_MONITOR_ENABLED
	krc_post_handle ping_handles[Outstanding_requests];
	memset(ping_handles, 0, Outstanding_requests * sizeof(krc_post_handle));
	int head = 0;
	int tail = 0;
	char full = 0;
#endif
	while (!Thread_exit) {
		conn = cu_get_conn_for_region(r_desc, (uint64_t)(tid * connections_per_thread) + current_connection);
#if LATENCY_MONITOR_ENABLED
		krc_ping(conn, Message_size);
#else
		// Try to send a new message
		if (!full) {
			assert(ping_handles[head].conn == NULL && ping_handles[head].reply == NULL);
			krc_post_status ret = krc_post_ping(conn, Message_size, &ping_handles[head]);
			// FIXME Add a check to exit after some retries so that it isn't left spinning if an
			// experiment failed
			if (ret == KRC_POST_SUCCESS) {
				head = (head + 1) % Outstanding_requests;
				if (head == tail)
					full = 1;
				++Sent_messages[tid];
			}
			current_connection = (current_connection + 1) % connections_per_thread;
		}

		// Check if a reply has arrived
		if (head != tail || full) {
			if (krc_poll_ping_reply(&ping_handles[tail]) == 1) {
				ping_handles[tail].conn = NULL;
				ping_handles[tail].reply = NULL;
				tail = (tail + 1) % Outstanding_requests;
				full = 0;
				++Received_messages[tid];
			}
		}
#endif
	}

#if !LATENCY_MONITOR_ENABLED
	// Receive all outstanding messages
	while (head != tail || full) {
		while (krc_poll_ping_reply(&ping_handles[tail]) != 1)
			;
		tail = (tail + 1) % Outstanding_requests;
		full = 0;
		++Received_messages[tid];
	}
#endif
	// Correction check: every request has a reply
	if (Sent_messages[tid] != Received_messages[tid]) {
		printf("sent = %d, received = %d\n", Sent_messages[tid], Received_messages[tid]);
		assert(Sent_messages[tid] == Received_messages[tid]);
	}

	return NULL;
}

char *conf_file_name = "conf.txt";

void print_usage(char *exe_name, FILE *out)
{
	fprintf(out, "Usage: %s [options] zookeeper_service\nRequired Arguments:\n", exe_name);
	fprintf(out, "  zookeeper_service                Zookeeper service address (eg. 127.0.0.1:2181");
	fprintf(out, "Options (=default_value):\n");
	fprintf(out, "  -t threads (=1)                  Threads used for issuing new requests\n");
	fprintf(out, "  -d seconds (=60)                 Duration of the benchmark\n");
	fprintf(out, "  -c connections (=threads)        Number of connections to open with each Kreon server\n");
	fprintf(out, "  -m message_size (=16KB)          Message size\n");
	fprintf(out, "  -o concurrent_requests (=128)    Outgoing concurrent requests per benchmark thread\n");
	fprintf(out, "  -h                               Prints this message\n");
}

void parse_command_line_args(int argc, char **argv)
{
	int opt;
	while ((opt = getopt(argc, argv, ":t:d:c:m:o:h")) != -1) {
		switch (opt) {
		case 't':
			Threads = strtoul(optarg, NULL, 10);
			break;
		case 'd':
			Time = strtoul(optarg, NULL, 10);
			break;
		case 'c':
			globals_set_connections_per_server(strtoul(optarg, NULL, 10));
			break;
		case 'm':
			Message_size = strtol(optarg, NULL, 10);
			break;
		case 'o':
			Outstanding_requests = strtol(optarg, NULL, 10);
			break;
		case '?':
			fprintf(stderr, "Error: unknown option \'%c\'\n", optopt);
			print_usage(argv[0], stderr);
			exit(EXIT_FAILURE);
		case ':':
			fprintf(stderr, "Error: option \'%c\' requires an argument\n", optopt);
			print_usage(argv[0], stderr);
			exit(EXIT_FAILURE);
		case 'h':
			print_usage(argv[0], stdout);
			exit(EXIT_SUCCESS);
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: no zookeeper service address specified\n");
		print_usage(argv[0], stderr);
		exit(EXIT_FAILURE);
	}

	Zookeeper_service = argv[optind];
}

void print_parameters(FILE *out)
{
	fprintf(out, "Client Threads\t%d\n", Threads);
	fprintf(out, "Queue Pairs\t%d\n", globals_get_connections_per_server());
	fprintf(out, "Message Size\t%d\n", Message_size);
	fprintf(out, "Outstanding Requests\t%u\n", Outstanding_requests);
	fprintf(out, "Memory Region Size\t%lu\n", MEM_REGION_BASE_SIZE);
}

int main(int argc, char **argv)
{
	// Write configuration to a file
	FILE *conf_file = fopen(conf_file_name, "w");

	parse_command_line_args(argc, argv);

	Message_size = Message_size - TU_HEADER_SIZE - sizeof(uint32_t);

#if LATENCY_MONITOR_ENABLED
	latmon_init();
	FILE *lat_out_file = fopen("lat.csv", "w");
	if (!lat_out_file) {
		ERRPRINT("fopen: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
#endif
	char *tokens[2];
	char *zookeeper_host;
	int zookeeper_port;

	tokens[0] = strtok(Zookeeper_service, ":");
	tokens[1] = strtok(NULL, ":");

	if (!tokens[0] || !tokens[1]) {
		fprintf(stderr, "Error: %s is not a valid service address\n", Zookeeper_service);
		exit(EXIT_FAILURE);
	}
	zookeeper_host = tokens[0];
	zookeeper_port = strtol(tokens[1], NULL, 10);

	print_parameters(conf_file);
	print_parameters(stdout);

	krc_init(zookeeper_host, zookeeper_port);
	srand(time(NULL));

	Sent_messages = (int *)malloc(Threads * sizeof(int));
	Received_messages = (int *)malloc(Threads * sizeof(int));
	memset((void *)Sent_messages, 0, Threads * sizeof(int));
	memset((void *)Received_messages, 0, Threads * sizeof(int));

	Pthreads = (pthread_t *)malloc(Threads * sizeof(pthread_t));
	for (size_t i = 0; i < Threads; ++i) {
		pthread_create(&Pthreads[i], NULL, bench, (void *)i);
	}

	printf("Total time: %d\n", Time);
	static struct timespec SLEEP_DURATION_TIMESPEC = { 1, 0 }; // sec = usec * 10^6
	struct timespec rem;
	size_t seconds_passed = 0;

	int i, outstanding;
	FILE *out_file = fopen("outstanding.txt", "w");
	while (seconds_passed < Time) {
		nanosleep(&SLEEP_DURATION_TIMESPEC, &rem);
		seconds_passed += SLEEP_DURATION_TIMESPEC.tv_sec;

		for (i = 0, outstanding = 0; i < Threads; ++i) {
			outstanding += (Sent_messages[i] - Received_messages[i]);
		}

		fprintf(out_file, "%lu Sec %d Outstanding_Requests\n", seconds_passed, outstanding);
	}
	// sleep(Time);
	printf("Wake up!\n");
	Thread_exit = 1;

	for (int i = 0; i < Threads; ++i) {
		pthread_join(Pthreads[i], NULL);
	}

#if LATENCY_MONITOR_ENABLED
	latmon_stats stats;
	latmon_calc_stats(&stats);

	printf("Total samples = %lu\n", stats.samples);
	printf("Out of bounds samples = %lu\n", stats.out_of_bounds);
	printf("min = %lu, avg = %lu, max = %lu\n", stats.min, stats.avg, stats.max);
	printf("lat90 = %lu, lat99 = %lu, lat999 = %lu\n", stats.lat90, stats.lat90, stats.lat999);

	fprintf(lat_out_file, "samples,out_of_bounds,less_equal_zero,min,avg,max,lat90,lat99,lat999,lat9999\n");
	fprintf(lat_out_file, "%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n", stats.samples, stats.out_of_bounds,
		stats.less_equal_zero, stats.min, stats.avg, stats.max, stats.lat90, stats.lat99, stats.lat999,
		stats.lat9999);
	fclose(lat_out_file);
#endif
	return 0;
}

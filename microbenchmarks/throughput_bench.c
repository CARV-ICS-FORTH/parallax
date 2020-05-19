//#include "../kreon_server/client_regions.h"
#include "../kreon_rdma_client/client_utils.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "../kreon_server/globals.h"
#include "../utilities/latency_monitor.h"
#include <log.h>
#define zookeeper_host_port "192.168.1.134:2181"
#define MAX_THREADS 32
#define THREADS 16

const int TIME = 180;
/* XXX NOTE With larger message size parameters the server spends a lot of time waiting
 * to receive the payload parts of the messages, and delays replies to RESET_BUFFER
 * messages lowering the overall system performance.
 * POSSIBLE FIX: Do not wait for payload once you find an incoming message's header but
 * rather check if the payload has arrived yet and if not move on to the next connection.
 */
const int MSG_SIZE = (8 * 1024) - TU_HEADER_SIZE - sizeof(uint32_t);

pthread_t Threads[MAX_THREADS];
//_Client_Regions *Client_regions = NULL;
int Sent_requests[MAX_THREADS];
volatile int Completed_requests[MAX_THREADS];
volatile char Thread_exit = 0;

//extern client_region **kreon_regions;

struct bench_callback_args {
	int tid;
#if LATENCY_MONITOR_ENABLED
	lat_t start_time;
#endif
};

void bench_callback(void *args)
{
#if LATENCY_MONITOR_ENABLED
	struct bench_callback_args *ca_args = (struct callback_args *)args;
	lat_t end_time;
	latmon_end(&ca_args->start_time);
	++Completed_requests[ca_args->tid];
#else
	++Completed_requests[(int)args];
#endif
}

void *bench(void *int_thread_id)
{
	uint32_t connections_per_thread = NUM_OF_CONNECTIONS_PER_SERVER / THREADS;
	int current_connection = 0;
	const size_t tid = (int)int_thread_id;
	connection_rdma *connection;
	struct cu_region_desc *r_desc = cu_get_first_region();

	while (!Thread_exit) {
		connection =
			cu_get_conn_for_region(r_desc, (uint64_t)(tid * connections_per_thread) + current_connection);
		//connection =
		//Client_regions[0].sorted_tu_regions[0]->head_net[0].rdma_conn[(tid * connections_per_thread) +current_connection];
		msg_header *msg = allocate_rdma_message(connection, MSG_SIZE, TEST_REQUEST);
		msg->request_message_local_addr = msg;
		msg->ack_arrived = 1;
#if LATENCY_MONITOR_ENABLED
		struct bench_callback_args *args =
			(struct bench_callback_args *)malloc(sizeof(struct bench_callback_args));
		args->tid = tid;
		latmon_start(&args->start_time);
#endif
		//DPRINT("Sending will be at %llu  reply at %llu actual msg addr %x\n",(uint64_t)msg - (uint64_t)connection->rdma_local_region,msg->reply,msg);
		async_send_rdma_message(connection, msg, bench_callback,
#if LATENCY_MONITOR_ENABLED
					(void *)args
#else
					(void *)tid
#endif
		);
		++Sent_requests[tid];
		if (++current_connection >= connections_per_thread) {
			current_connection = 0;
		}
	}

	while (Sent_requests[tid] != Completed_requests[tid])
		;

	return NULL;
}

void *stats(void *_ignored)
{
	while (!Thread_exit) {
		printf("In Transit requests / sec: ");
		for (int i = 0; i < THREADS; ++i) {
			printf("%d ", Sent_requests[i] - Completed_requests[i]);
		}
		printf("\n");
		sleep(1);
	}
	return NULL;
}

pthread_t stats_thread;

char *conf_file_name = "conf.txt";

int main(void)
{
	// Write configuration to a file
	FILE *conf_file = fopen(conf_file_name, "w");

#if LATENCY_MONITOR_ENABLED
	latmon_init();
	FILE *lat_out_file = fopen("lat.csv", "w");
	if (!lat_out_file) {
		ERRPRINT("fopen: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
#endif

	fprintf(conf_file, "Queue Pairs\t%d\n", NUM_OF_CONNECTIONS_PER_SERVER);
	fprintf(conf_file, "Client Threads\t%d\n", THREADS);
	fprintf(conf_file, "Message Size\t%d\n", MSG_SIZE);
	fprintf(conf_file, "Memory Regions\t%lu\n", MR_PREALLOCATE_COUNT);
	fprintf(conf_file, "Memory Region Size\t%lu\n", MEM_REGION_BASE_SIZE);

	globals_set_zk_host(zookeeper_host_port);
	//Client_regions = Allocate_Init_Client_Regions();
	char *zk_host;
	char *zk_port;
	char *rest = zookeeper_host_port;
	zk_host = strtok_r(rest, " ", &rest);
	zk_port = strtok_r(rest, " ", &rest);
	int port;
	sprintf((char *)&port, "%s", zk_port);
	log_info("initializing zookeeper at %s port %d", zk_host, port);
	cu_init(zk_host, port);
	srand(time(NULL));

	for (size_t i = 0; i < THREADS; ++i) {
		pthread_create(&Threads[i], NULL, bench, (void *)i);
	}

	// pthread_create(&stats_thread, NULL, stats, NULL);

	printf("Total time: %d\n", TIME);
	sleep(TIME);
	printf("Wake up!\n");
	Thread_exit = 1;

	for (int i = 0; i < THREADS; ++i) {
		pthread_join(Threads[i], NULL);
	}
	//Free_Client_Regions(&Client_regions);

#if LATENCY_MONITOR_ENABLED
	latmon_stats stats;
	latmon_calc_stats(&stats);

	printf("Total samples = %lu\n", stats.samples);
	printf("Out of bounds samples = %lu\n", stats.out_of_bounds);
	printf("min = %lu, avg = %lu, max = %lu\n", stats.min, stats.avg, stats.max);
	printf("lat90 = %lu, lat99 = %lu, lat999 = %lu\n", stats.lat90, stats.lat90, stats.lat999);

	fprintf(lat_out_file, "samples,out_of_bounds,less_equal_zero,min,avg,max,lat90,lat99,lat999\n");
	fprintf(lat_out_file, "%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n", stats.samples, stats.out_of_bounds,
		stats.less_equal_zero, stats.min, stats.avg, stats.max, stats.lat90, stats.lat99, stats.lat999);
	fclose(lat_out_file);
#endif
	return 0;
}

#include "../TucanaServer/client_regions.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "../TucanaServer/globals.h"
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
_Client_Regions *Client_regions = NULL;
int Sent_requests[MAX_THREADS];
volatile int Completed_requests[MAX_THREADS];
volatile char Thread_exit = 0;

extern client_region **kreon_regions;

void increment_completed(void *int_thread_id)
{
	++Completed_requests[(int)int_thread_id];
}

void *bench(void *int_thread_id)
{
	uint32_t connections_per_thread = NUM_OF_CONNECTIONS_PER_SERVER / THREADS;
	int current_connection = 0;
	const size_t tid = (int)int_thread_id;
	connection_rdma *connection;
	//int i = 1;
	while (!Thread_exit) {
		connection =
			Client_regions[0].sorted_tu_regions[0]->head_net[0].rdma_conn[(tid * connections_per_thread) +
										      current_connection];
		tu_data_message_s *msg = allocate_rdma_message(connection, MSG_SIZE, TEST_REQUEST);
		msg->request_message_local_addr = msg;
		msg->ack_arrived = 1;
		//DPRINT("Sending will be at %llu  reply at %llu actual msg addr %x\n",(uint64_t)msg - (uint64_t)connection->rdma_local_region,msg->reply,msg);
		async_send_rdma_message(connection, msg, increment_completed, (void *)tid);
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
		printf("Completed requests: ");
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

	fprintf(conf_file, "Queue Pairs\t%d\n", NUM_OF_CONNECTIONS_PER_SERVER);
	fprintf(conf_file, "Client Threads\t%d\n", THREADS);
	fprintf(conf_file, "Message Size\t%d\n", MSG_SIZE);
	fprintf(conf_file, "Memory Regions\t%lu\n", MR_PREALLOCATE_COUNT);
	fprintf(conf_file, "Memory Region Size\t%lu\n", MEM_REGION_BASE_SIZE);

	globals_set_zk_host(zookeeper_host_port);
	Client_regions = Allocate_Init_Client_Regions();

	Client_Create_Receiving_Threads(Client_regions);
	srand(time(NULL));

	for (size_t i = 0; i < THREADS; ++i) {
		pthread_create(&Threads[i], NULL, bench, (void *)i);
	}

	pthread_create(&stats_thread, NULL, stats, NULL);

	printf("Total time: %d\n", TIME);
	sleep(TIME);
	printf("Wake up!\n");
	Thread_exit = 1;

	for (int i = 0; i < THREADS; ++i) {
		pthread_join(Threads[i], NULL);
	}

	Free_Client_Regions(&Client_regions);
}

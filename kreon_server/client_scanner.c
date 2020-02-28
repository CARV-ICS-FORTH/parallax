/* file: TucanaServer/client_scanner.c
 * Author: Michalis Vardoulakis <mvard@ics.forth.gr>
 * Created On: 07/03/2018
 * Implementation of a client-side cursor API for scan queries
 * Refer to TucanaServer/tests/scan.c as an example.
 */
#include "client_scanner.h"
#include "djb2.h"
#include <assert.h>
#include <string.h>

uint32_t kv_pairs_per_message = 100;

//FIXME It's assumed in many parts of the code(not just this file) that keys and values end with'\0'
//TODO Maybe write an iterator API?
//     Change scan to always return as much as the buffer can fit.
//     Define a flag to [not] include start key in multi_get's reply.
//         Partially done: implemented to avoid duplicate keys; not exposed to clients for first key.
//     Define a flag to [not] return the stop key in client_scan_get_next_kv.
//     Make ret a function argument and stop allocating memory in the init function.

struct tu_data_message* _create_scan_query_message(struct connection_rdma* conn, char* start_key, uint32_t start_key_len,
		char* stop_key, uint32_t stop_key_len)
{
	struct tu_data_message* scan_query;
	uint32_t total_length = 3*sizeof(uint32_t) + start_key_len + stop_key_len;

	/*DPRINT("Start Key = %s:%u | Stop Key = %s:%u\n", start_key, start_key_len, stop_key, stop_key_len);*/

	scan_query = allocate_rdma_message(conn, total_length, SCAN_REQUEST);
	push_buffer_in_tu_data_message(scan_query, &kv_pairs_per_message, sizeof(kv_pairs_per_message));
	push_buffer_in_tu_data_message(scan_query, &start_key_len, sizeof(start_key_len));
	push_buffer_in_tu_data_message(scan_query, start_key, start_key_len);
	push_buffer_in_tu_data_message(scan_query, &stop_key_len, sizeof(stop_key_len));
	push_buffer_in_tu_data_message(scan_query, stop_key, stop_key_len);

	assert((scan_query->flags & 0x0000FF00) == CLIENT_CATEGORY);

	scan_query->request_message_local_addr = scan_query;
	return scan_query;
}

//scan_query->value == 0 means exclude start_key.
//scan_query->value == 1 means include start_key.
scanner_s* client_scan_init(
		char* start_key,
		uint32_t start_key_len,
		char* stop_key,
		uint32_t stop_key_len,
		_Client_Regions* regions
	)
{
	scanner_s *ret = malloc(sizeof(scanner_s));
	client_region* cli_tu_region;
	struct tu_data_message* scan_query;
	int mailbox;

	cli_tu_region = Client_Get_Tu_Region_and_Mailbox(regions, start_key, start_key_len, 0, &mailbox );
	struct connection_rdma* conn = get_connection_from_region(cli_tu_region, djb2_hash((unsigned char*)&scan_query, sizeof(tu_data_message_s*)));
	scan_query = _create_scan_query_message(conn, start_key, start_key_len, stop_key, stop_key_len);
	ret->scan_reply_connection = conn;
	scan_query->value = 1;
	/*DPRINT("Send scan query\n");*/
	scan_query->reply_message = NULL;
	send_rdma_message(conn, scan_query);
	/*DPRINT("Waiting for reply\n");*/
	struct tu_data_message* scan_reply = get_message_reply(conn, scan_query);
	/*DPRINT("Got scan reply\n");*/
	assert(scan_reply);
	scan_reply->next += sizeof(uint32_t);
	ret->scan_reply = scan_reply;
	ret->start_key_len = start_key_len;
	ret->start_key = start_key;
	ret->stop_key_len = stop_key_len;
	ret->stop_key = stop_key;
	ret->last_key = 0;
	ret->last_key_len = 0;
	ret->kv_pairs_used = 0;
	ret->regions = regions;
	return ret;
}

void client_scan_close(scanner_s* scanner)
{
	if (scanner->scan_reply)
		free_rdma_received_message(scanner->scan_reply_connection, scanner->scan_reply);

	free(scanner);
}

void print_kv_buffer(void* kv_buffer, uint32_t kv_pairs);

kv_pair_s client_scan_get_next_kv(scanner_s* scanner)
{
#define END_OF_DATABASE 2
	kv_pair_s kv = {0, 0, 0, 0};

	if (scanner->scan_reply->value != END_OF_DATABASE && scanner->kv_pairs_used >= *(uint32_t*)scanner->scan_reply->data) {
		struct tu_data_message* scan_query;
		client_region* cli_tu_region;
		int mailbox;

		cli_tu_region = Client_Get_Tu_Region_and_Mailbox(scanner->regions, scanner->last_key, scanner->last_key_len, 0, &mailbox );
		struct connection_rdma* conn = get_connection_from_region(cli_tu_region, djb2_hash((unsigned char*)&scan_query, sizeof(tu_data_message_s*)));
		free_rdma_received_message(scanner->scan_reply_connection, scanner->scan_reply);
		scan_query = _create_scan_query_message(conn, scanner->last_key, scanner->last_key_len, scanner->stop_key, scanner->stop_key_len);
		scan_query->reply_message = NULL;
		scan_query->value = 0;
		/*DPRINT("Send scan query\n");*/
		scanner->scan_reply_connection = NULL;
		scanner->scan_reply = NULL;
		send_rdma_message(conn, scan_query);
		scanner->scan_reply = get_message_reply(conn, scan_query);
		scanner->scan_reply_connection = conn;
		free_rdma_local_message(conn);
		/*DPRINT("Got scan reply\n");*/
		assert(scanner->scan_reply);
		scanner->scan_reply->next += sizeof(uint32_t);
		scanner->kv_pairs_used = 0;
	}

	//If keys remaining in this scan reply
	if(scanner->kv_pairs_used < *(uint32_t*)scanner->scan_reply->data) {
		uint32_t key_len = *(uint32_t*)scanner->scan_reply->next;
		void* key = (char*)(scanner->scan_reply->next + sizeof(uint32_t));

		kv.key_len = key_len;
		kv.key = key;
		kv.value_len = *(uint32_t*)(kv.key + kv.key_len);
		kv.value = (char*)(kv.key + kv.key_len + sizeof(uint32_t));
		scanner->scan_reply->next = kv.value + kv.value_len;
		scanner->last_key_len = kv.key_len;
		scanner->last_key = kv.key;
		++scanner->kv_pairs_used;
	} else if(scanner->scan_reply->value == END_OF_DATABASE) {
		free_rdma_received_message(scanner->scan_reply_connection, scanner->scan_reply);
		scanner->scan_reply = NULL;
		scanner->scan_reply_connection = NULL;
		return kv;
	}

	return kv;
}

/* file: TucanaServer/client_scanner.h
 * Author: Michalis Vardoulakis <mvard@ics.forth.gr>
 * Created On: 07/03/2018
 * A client-side cursor API for scan queries
 */
#ifndef _CLIENT_SCANNER_H
#define _CLIENT_SCANNER_H
#include "client_regions.h"

typedef struct {
	struct tu_data_message* scan_reply;
	struct connection_rdma* scan_reply_connection;
	uint32_t start_key_len;
	char* start_key;
	uint32_t stop_key_len;
	char* stop_key;
	char* last_key;
	uint32_t last_key_len;
	uint32_t kv_pairs_used;
	_Client_Regions* regions;
} scanner_s;

typedef struct {
	uint32_t key_len;
	char* key;
	uint32_t value_len;
	char* value;
} kv_pair_s;

scanner_s* client_scan_init(
		char* start_key,
		uint32_t start_key_len,
		char* stop_key,
		uint32_t stop_key_len,
		_Client_Regions* regions
	);

extern uint32_t kv_pairs_per_message;

void client_scan_close(scanner_s* scanner);

kv_pair_s client_scan_get_next_kv(scanner_s* scanner);


struct tu_data_message* _create_scan_query_message(struct connection_rdma* conn, char* start_key, uint32_t start_key_len,
		char* stop_key, uint32_t stop_key_len);

#endif /*_CLIENT_SCANNER_H*/

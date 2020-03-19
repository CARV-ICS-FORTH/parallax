/* YCSB-CXX/db/rdma_dummy_client.h
 * Author: Michalis Vardoulakis
 * Created on: 23/7/2019
 */

#ifndef YCSBC_C_KREON_RDMA_H_
#define YCSBC_C_KREON_RDMA_H_

#include "ycsbdb.h"

#include <iostream>
#include <string>
#include <mutex>
#include <algorithm>
#include <atomic>
#include <functional>
#include <unordered_map>

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <boost/algorithm/string.hpp>

#include "properties.h"

extern "C" {
	#include "allocator/allocator.h"
	#include "btree/btree.h"
	#include "scanner/scanner.h"
	#include "client_tucana_regions.h"
	#include "client_scanner.h"
}

#ifdef CHECKSUM_DATA_MESSAGES
extern "C" {
	#include "djb2.h"
}
#endif

#define MAX_THREADS 128

#define NUM_OF_BATCH_OPERATIONS 1
extern std::unordered_map<std::string, int> ops_per_server;
int pending_requests[MAX_THREADS];
int served_requests[MAX_THREADS];

namespace ycsbc {
	using std::cout;
	using std::cerr;
	using std::endl;

	void callback_function(void *args) {
		__sync_fetch_and_add((int*)args, 1);
	}

	class RDMATestClientDB : public YCSBDB {
	private:
		_Client_Regions *client_regions;
		double tinit, t1,t2;
		struct timeval tim;
		pthread_mutex_t mutex_num;

	public:
		RDMATestClientDB(int num, utils::Properties& props) {
			struct timeval start;
			client_regions = Allocate_Init_Client_Regions( );
			memset(pending_requests,0x00, MAX_THREADS * sizeof(int));
			memset(served_requests,0x00, MAX_THREADS * sizeof(int));

			pthread_mutex_init( &mutex_num, NULL);

			cout << "waiting num regions to connect" << num;
			while ( client_regions->num_regions_connected < num ){
				cout << "TucanServer: There are only " <<  client_regions->num_regions_connected << " regions need total of " << num << "\n" << endl;
				sleep(1);
			}
			Client_Create_Receiving_Threads( client_regions );
			gettimeofday(&start, NULL);
			tinit=start.tv_sec+(start.tv_usec/1000000.0);
		}

		virtual ~RDMATestClientDB(){

			cout << "Calling ~RDMATestClientDB()..." << endl;
			gettimeofday(&tim, NULL);
			t2=tim.tv_sec+(tim.tv_usec/1000000.0);
			fprintf(stderr, "ycsb=[%lf]sec\n", (t2-t1));
			fprintf(stderr, "start=[%lf]sec\n", (t1-tinit));

			//Client_Flush_Volume( client_regions );
			//Client_Flush_Volume_MultipleServers( client_regions );
			cout << "Freeing client regions...\n";
			Free_Client_Regions( &client_regions );
		}

	public:
		void Init(){}
		void Close()
		{
			int i;
			int cnt = 1;

			DPRINT("\tFlushing remaining staff....\n");
			/*flush any remaining staff*/
			DPRINT("\t Done flushing waiting for replies...\n");

			for(i=0;i<MAX_THREADS;i++){
				while(pending_requests[i] != served_requests[i]){
					++cnt;
					if(cnt%1000000000 == 0){
						DPRINT("waiting for thread %d to finish its pending requests requests are %d served are %d\n",i,pending_requests[i],served_requests[i]);
						cnt = 1;
					}
				}
			}

			Free_Client_Regions( &client_regions );
			DPRINT("\t Done Bye Bye!\n");
			exit(EXIT_SUCCESS);
		}

		int Read(int id, const std::string &table, const std::string &key, const std::vector<std::string> *fields, std::vector<KVPair> &result) {
			cerr << "RDMATestClientDB::Read E: operation not supported" << endl;
			exit(EXIT_FAILURE);
		}

		int Scan(int id/*ignore*/, const std::string &table/*ignore*/, const std::string &key, int record_count,
				const std::vector<std::string> *fields/*ignore*/, std::vector<KVPair> &result) {
			cerr << "RDMATestClientDB::Scan E: operation not supported" << endl;
			exit(EXIT_FAILURE);
		}

		int Update(int id, const std::string &table, const std::string &key, std::vector<KVPair> &values) {
			cerr << "RDMATestClientDB::Update E: operation not supported" << endl;
			exit(EXIT_FAILURE);
		}

		int Insert(int id, const std::string &table/*ignored*/, const std::string &key, std::vector<KVPair> &values) {
			char buffer[1512];
			int pos;
			int type = TEST_REQUEST_FETCH_PAYLOAD;
			int total_length = 0;
			struct tu_data_message *mr_message;
			struct tu_data_message *reply_data_message;
			_client_tucana_region *cli_tu_region;
			int ops = 0;
			int mailbox;

			pos = 0;
			assert(values.size() == 1);
			// FIXME can avoid redundant copying by calculating length by iterating the values vector,
			// allocating an rdma message and copying them directly in there
			for(auto v : values){
				if( pos+v.first.length()+v.second.length()  <= 1512){
					memcpy(buffer+pos, (char *)v.first.c_str(),v.first.length());
					pos+= v.first.length();
					buffer[pos] = 0x20;
					++pos;
					memcpy(buffer+pos, (char *)v.second.c_str(),v.second.length());
					pos+= v.second.length();
					buffer[pos] = 0x20;
					++pos;
				} else{
					printf("[%s:%s:%d] FATAL buffer overflow resize buffer\n",__FILE__,__func__,__LINE__);
				}
			}
			/*ommit last space*/
			pos -= 2;
			total_length = key.length() + pos + 8;

			cli_tu_region = Client_Get_Tu_Region_and_Mailbox( client_regions, (char *)key.c_str(),key.length(), 0, &mailbox );
			struct connection_rdma* connection = get_connection_from_region(cli_tu_region, id);

			std::string server(cli_tu_region->head);
			ops_per_server[server] += ops;

			assert(cli_tu_region != NULL);
			assert(cli_tu_region->ID_region.minimum_range != NULL);
			assert(cli_tu_region->ID_region.maximum_range != NULL);

			mr_message = allocate_rdma_message(connection, total_length, type);

#ifdef CHECKSUM_DATA_MESSAGES
			// Incrementally calculate hash of KV buffer [key length, key, value length, value]
			uint32_t key_length = key.length();
			uint32_t value_length = pos;
			unsigned long hash = djb2_hash((unsigned char*)&key_length, sizeof(key_length), -1);
			hash = djb2_hash((unsigned char*)key.c_str(), key_length, hash);
			hash = djb2_hash((unsigned char*)&value_length, sizeof(value_length), hash);
			hash = djb2_hash((unsigned char*)buffer, pos, hash);
			assert(hash);
#endif
			if(!push_buffer_in_tu_data_message(mr_message, (char *)key.c_str(), key.length())) {
				DPRINT("push_buffer for key FAILED\n");
				exit(EXIT_FAILURE);
			}
			if(!push_buffer_in_tu_data_message(mr_message, buffer, pos)) {
				DPRINT("push_buffer for value FAILED\n");
				exit(EXIT_FAILURE);
			}
			reply_data_message = NULL;
			mr_message->request_message_local_addr = mr_message;
			mr_message->ack_arrived = 1;
			__sync_fetch_and_add(&pending_requests[id],1);
#ifdef BLOCKING_INSERT //SYNC_REQUEST
			send_rdma_message(connection, mr_message);
			reply_data_message = get_message_reply(connection, mr_message);
			if(reply_data_message == NULL){
				DPRINT("FATAL send failed\n");
				exit(EXIT_FAILURE);
			}
			free_rdma_received_message(connection, reply_data_message);
			free_rdma_local_message(connection, mr_message);
#else //ASYNC_REQUEST
			async_send_rdma_message(connection, mr_message, &callback_function, &served_requests[id]);
#endif
			return 0;
		}

		int Delete(int id, const std::string &table, const std::string &key) {
			cerr << "RDMATestClientDB::Delete E: operation not supported" << endl;
			exit(EXIT_FAILURE);
		}
	};
}

#endif //YCSBC_C_KREON_RDMA_H_

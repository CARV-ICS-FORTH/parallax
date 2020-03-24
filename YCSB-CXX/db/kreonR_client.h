/**
 * eutropia_db.h
 *  YCSB-C
 * Created by Anastasios Papagiannis on 17/11/15.
 * Copyright (c) 2015 Anastasios Papagiannis <apapag@ics.forth.gr>.
**/

#pragma once

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
#include "../kreon_lib/allocator/allocator.h"
#include "../kreon_lib/btree/btree.h"
#include "../kreon_lib/scanner/scanner.h"
#include "client_regions.h"
#include "client_scanner.h"
#include "../../kreon_server/globals.h"
}
#ifdef CHECKSUM_DATA_MESSAGES
extern "C" {
#include "djb2.h"
}
#endif

#define FIELD_COUNT 10
#define MAX_THREADS 128
using std::cout;
using std::endl;

#define NUM_OF_BATCH_OPERATIONS 1
extern std::unordered_map<std::string, int> ops_per_server;
int pending_requests[MAX_THREADS];
int served_requests[MAX_THREADS];
int num_of_batch_operations_per_thread[MAX_THREADS];

typedef struct rdma_buffer {
	char buffer[NUM_OF_BATCH_OPERATIONS * 1150];
	int pos;
} rdma_buffer;
rdma_buffer client_buffers[MAX_THREADS];

namespace ycsbc
{
void callback_function(void *args)
{
	__sync_fetch_and_add((int *)args, 1);
}
class kreonRClientDB : public YCSBDB {
    private:
	int db_num;
	int field_count;
	std::vector<db_handle *> dbs;
	_Client_Regions *client_regions;
	double tinit, t1, t2;
	struct timeval tim;
	long long how_many = 0;
	int cu_num;
	pthread_mutex_t mutex_num;

    public:
	kreonRClientDB(int num, utils::Properties &props)
		: db_num(num), field_count(std::stoi(props.GetProperty(CoreWorkload::FIELD_COUNT_PROPERTY,
								       CoreWorkload::FIELD_COUNT_DEFAULT))),
		  dbs()
	{
		struct timeval start;
		globals_set_zk_host(zookeeper_host_port);
		client_regions = Allocate_Init_Client_Regions();
		memset(pending_requests, 0x00, MAX_THREADS * sizeof(int));
		memset(served_requests, 0x00, MAX_THREADS * sizeof(int));
		memset(num_of_batch_operations_per_thread, 0x00, MAX_THREADS * sizeof(int));
		memset(client_buffers, 0x00, MAX_THREADS * sizeof(buffer));

		cu_num = 0;
		pthread_mutex_init(&mutex_num, NULL);

		cout << "waiting num regions to connect" << num;
		while (client_regions->num_regions_connected < num) {
			cout << "TucanServer: There are only " << client_regions->num_regions_connected
			     << " regions need total of " << num << "\n"
			     << endl;
			sleep(1);
		}
		Client_Create_Receiving_Threads(client_regions);
		gettimeofday(&start, NULL);
		tinit = start.tv_sec + (start.tv_usec / 1000000.0);
	}

	virtual ~kreonRClientDB()
	{
		cout << "Calling ~kreonRClientDB()..." << endl;
		gettimeofday(&tim, NULL);
		t2 = tim.tv_sec + (tim.tv_usec / 1000000.0);
		fprintf(stderr, "ycsb=[%lf]sec\n", (t2 - t1));
		fprintf(stderr, "start=[%lf]sec\n", (t1 - tinit));

		//Client_Flush_Volume( client_regions );
		//Client_Flush_Volume_MultipleServers( client_regions );
		cout << "Freeing client regions...\n";
		Free_Client_Regions(&client_regions);
	}

    public:
	void Init()
	{
	}
	void Close()
	{
		client_region *cli_tu_region;
		struct connection_rdma *connection;
		struct msg_header *mr_message;
		int total_length, mailbox;
		int i;
		int cnt = 1;
		int a;

		DPRINT("\tFlushing remaining staff....\n");
		sleep(10);
		/*flush any remaining staff*/
		for (i = 0; i < MAX_THREADS; i++) {
			if (num_of_batch_operations_per_thread[i] > 0) {
				cli_tu_region =
					Client_Get_Tu_Region_and_Mailbox(client_regions, client_buffers[i].buffer + 4,
									 *(uint32_t *)client_buffers[i].buffer, 0,
									 &mailbox);
				connection = get_connection_from_region(cli_tu_region, i);
				std::string server(cli_tu_region->head);
				ops_per_server[server] += num_of_batch_operations_per_thread[i];
				mr_message = allocate_rdma_message(connection, client_buffers[i].pos, PUT_REQUEST);
				if (!push_buffer_in_msg_header(mr_message, client_buffers[i].buffer,
								    client_buffers[i].pos)) {
					DPRINT("push_buffer for key FAILED\n");
					exit(EXIT_FAILURE);
				}
				mr_message->request_message_local_addr = mr_message;
				mr_message->ack_arrived = 1;
				mr_message->flags |= ASYNC_REQUEST;
				++pending_requests[i];
				async_send_rdma_message(connection, mr_message, &callback_function,
							&served_requests[i]);
				client_buffers[i].pos = 0;
			}
		}
		DPRINT("\t Done flushing waiting for replies...\n");

		for (i = 0; i < MAX_THREADS; i++) {
			while (pending_requests[i] != served_requests[i]) {
				++cnt;
				if (cnt % 1000000000 == 0) {
					DPRINT("waiting for thread %d to finish its pending requests requests are %d served are %d\n",
					       i, pending_requests[i], served_requests[i]);
					cnt = 1;
				}
			}
		}

		Free_Client_Regions(&client_regions);
		DPRINT("\t Done Bye Bye!\n");
		exit(EXIT_SUCCESS);
	}

	int Read(int id, const std::string &table, const std::string &key, const std::vector<std::string> *fields,
		 std::vector<KVPair> &result)
	{
		if (fields) {
			return __read(id, table, key, fields, result);
		} else {
			std::vector<std::string> __fields;
			for (int i = 0; i < field_count; ++i)
				__fields.push_back("field" + std::to_string(i));
			return __read(id, table, key, &__fields, result);
		}

		return 0;
	}

	int __read(int id, const std::string &table, const std::string &key, const std::vector<std::string> *fields,
		   std::vector<KVPair> &result)
	{
		uint32_t lenKey;
		int length = 0;
		struct msg_header *mr_message;
		struct msg_header *reply_data_message;
		client_region *cli_tu_region;
		int mailbox = 0;
		std::map<std::string, std::string> vmap;
		char *val;
		uint32_t db_id = 0;

#ifdef CHECKSUM_DATA_MESSAGES
		// Incrementally calculate hash of KV buffer [key length, key, value length, value]
		uint32_t key_length = key.length();
		unsigned long hash = djb2_hash((unsigned char *)&key_length, sizeof(key_length), -1);
		hash = djb2_hash((unsigned char *)key.c_str(), key_length, hash);
		assert(hash);
#endif

		cli_tu_region = Client_Get_Tu_Region_and_Mailbox(client_regions, (char *)key.c_str(), key.length(),
								 db_id, &mailbox);
		//struct connection_rdma* connection = get_connection_from_region(cli_tu_region);

		struct connection_rdma *connection =
			cli_tu_region->head_net->rdma_conn[id % NUM_OF_CONNECTIONS_PER_SERVER];
		std::string server(cli_tu_region->head);
		ops_per_server[server] += 1;
		lenKey = key.length();
		length = lenKey + 4;
		mr_message = allocate_rdma_message(connection, length, TU_GET_QUERY);
		*(uint32_t *)mr_message->next = key.length();
		mr_message->next = (void *)((uint64_t)mr_message->next + 4);
		if (!push_buffer_in_msg_header(mr_message, (char *)key.c_str(), key.length())) {
			DPRINT("FATAL push FAILED\n");
			exit(EXIT_FAILURE);
		}
		mr_message->next = (void *)((uint64_t)mr_message->next + key.length());
		mr_message->reply_message = NULL;
		mr_message->request_message_local_addr = mr_message;
		mr_message->flags |= ASYNC_REQUEST;
		async_send_rdma_message(connection, mr_message, &callback_function, &served_requests[id]);
		++pending_requests[id];

#ifdef BLOCKING_READ
		reply_data_message = get_message_reply(connection, mr_message);
#ifdef CHECKSUM_DATA_MESSAGES
		mr_message->hash = hash;
#endif
		if (reply_data_message->data == NULL) {
			DPRINT("FATAL key %s not found\n", key.c_str());
			exit(EXIT_FAILURE);
		}
		len_val = *(uint32_t *)reply_data_message->data;
		val = (char *)(uint64_t)reply_data_message->data + sizeof(uint32_t);
#endif
#if VALUE_CHECK
		std::string value(val, len_val);
		std::vector<std::string> tokens;
		boost::split(tokens, value, boost::is_any_of(" "));
		int cnt = 0;
		for (std::map<std::string, std::string>::size_type i = 0; i + 1 < tokens.size(); i += 2) {
			vmap.insert(std::pair<std::string, std::string>(tokens[i], tokens[i + 1]));
			++cnt;
		}
		if (cnt != field_count) {
			std::cout << "ERROR IN VALUE!" << std::endl
				  << " cnt is = " << cnt << "value len " << len_val << "field count is " << field_count
				  << "\n";
			std::cout << "[" << value << "]" << std::endl << "\n";
			//printf("[%s:%s:%d] rest is %s\n",__FILE__,__func__,__LINE__,val+strlen(val)+4);
			exit(EXIT_FAILURE);
		}
		for (auto f : *fields) {
			std::map<std::string, std::string>::iterator it = vmap.find(f);
			if (it == vmap.end()) {
				std::cout << "[2]cannot find : " << f << " in DB " << db_id << std::endl;
				printf("Value %d %s\n", len_val, val);
				fflush(stdout);
				//exit(EXIT_FAILURE);
				break;
			}
			KVPair k = std::make_pair(f, it->second);
			result.push_back(k);
		}
#endif
#ifdef BLOCKING_READ
		free_rdma_received_message(connection, reply_data_message);
		free_rdma_local_message(connection, mr_message);
#endif
		return 0;
	}

	int Scan(int id /*ignore*/, const std::string &table /*ignore*/, const std::string &key, int record_count,
		 const std::vector<std::string> *fields /*ignore*/, std::vector<KVPair> &result)
	{
		scanner_s *scan_cursor =
			client_scan_init(const_cast<char *>(key.c_str()), key.length(), NULL, 0, client_regions);
		++pending_requests[id];
		kv_pair_s kv = client_scan_get_next_kv(scan_cursor);
		for (int i = 0; i < record_count && kv.key_len; ++i, kv = client_scan_get_next_kv(scan_cursor)) {
			KVPair k = std::make_pair(std::string(kv.key, kv.key_len), std::string(kv.value, kv.value_len));
			result.push_back(k);
		}
		client_scan_close(scan_cursor);
		__sync_fetch_and_add(&served_requests[id], 1);
		return 0;
	}

	void CreateKey(const std::string *key, std::string *qual, char *okey)
	{
		*(int32_t *)okey = key->length() + qual->length() + 1;
		memcpy(okey + sizeof(int32_t), key->c_str(), key->length());
		memcpy(okey + sizeof(int32_t) + key->length(), qual->c_str(), qual->length());
		okey[sizeof(int32_t) + key->length() + qual->length()] = '\0';
	}

	int Update(int id, const std::string &table, const std::string &key, std::vector<KVPair> &values)
	{
		char buffer[1512];
		int pos;
		int total_length = 0;
		struct msg_header *mr_message;
		struct msg_header *reply_data_message;
		client_region *cli_tu_region;
		int mailbox;

		pos = 0;
		for (auto v : values) {
			if (pos + v.first.length() + v.second.length() <= 1512) {
				memcpy(buffer + pos, (char *)v.first.c_str(), v.first.length());
				pos += v.first.length();
				buffer[pos] = 0x20;
				++pos;
				memcpy(buffer + pos, (char *)v.second.c_str(), v.second.length());
				pos += v.second.length();
				buffer[pos] = 0x20;
				++pos;
			} else {
				DPRINT("FATAL buffer overflow resize buffer\n");
			}
		}
		//ommit last space
		pos -= 2;
#ifdef CHECKSUM_DATA_MESSAGES
		// Incrementally calculate hash of KV buffer [key length, key, value length, value]
		uint32_t key_length = key.length();
		uint32_t value_length = pos;
		unsigned long hash = djb2_hash((unsigned char *)&key_length, sizeof(key_length), -1);
		hash = djb2_hash((unsigned char *)key.c_str(), key_length, hash);
		hash = djb2_hash((unsigned char *)&value_length, sizeof(value_length), hash);
		hash = djb2_hash((unsigned char *)buffer, pos, hash);
		assert(hash);
#endif
		cli_tu_region = Client_Get_Tu_Region_and_Mailbox(client_regions, (char *)key.c_str(), key.length(), 0,
								 &mailbox);
		//struct connection_rdma* connection = get_connection_from_region(cli_tu_region);
		struct connection_rdma *connection =
			cli_tu_region->head_net->rdma_conn[id % NUM_OF_CONNECTIONS_PER_SERVER];
		std::string server(cli_tu_region->head);
		ops_per_server[server] += 1;
		total_length = key.length() + pos + 8;

		mr_message = allocate_rdma_message(connection, total_length, TU_UPDATE);
		*(uint32_t *)mr_message->next = (uint32_t)key.length();
		mr_message->next = (void *)((uint64_t)mr_message->next + sizeof(uint32_t)); // XXX TEST THIS
		if (!push_buffer_in_msg_header(mr_message, (char *)key.c_str(), key.length())) {
			DPRINT("push_buffer for key FAILED\n");
			exit(EXIT_FAILURE);
		}
		*(uint32_t *)mr_message->next = (uint32_t)pos;
		mr_message->next = (void *)((uint64_t)mr_message->next + sizeof(uint32_t)); // XXX TEST THIS
		if (!push_buffer_in_msg_header(mr_message, buffer, pos)) {
			DPRINT("push_buffer for value FAILED\n");
			exit(EXIT_FAILURE);
		}

		mr_message->reply_message = NULL;
		mr_message->request_message_local_addr = mr_message;
		mr_message->flags |= ASYNC_REQUEST;

		//send_rdma_message(connection, mr_message);
		async_send_rdma_message(connection, mr_message, &callback_function, &served_requests[id]);
		++pending_requests[id];
		//reply_data_message = get_message_reply(connection, mr_message);

#ifdef CHECKSUM_DATA_MESSAGES
		// Set hash field in msg_header
		mr_message->hash = hash;
#endif
		//if(reply_data_message == NULL){
		//DPRINT("FATAL update operation failed\n");
		//exit(EXIT_FAILURE);
		//}
		//free_rdma_received_message(connection);
		//free_rdma_local_message(connection);
		return 0;
	}

	int Insert(int id, const std::string &table /*ignored*/, const std::string &key, std::vector<KVPair> &values)
	{
		char buffer[1512];
		int pos;
		int i;
		int type;
		int total_length = 0;
		struct msg_header *mr_message;
		struct msg_header *reply_data_message;
		client_region *cli_tu_region;
		int ops = 0;
		int mailbox;

		pos = 0;
		for (auto v : values) {
			if (pos + v.first.length() + v.second.length() <= 1512) {
				memcpy(buffer + pos, (char *)v.first.c_str(), v.first.length());
				pos += v.first.length();
				buffer[pos] = 0x20;
				++pos;
				memcpy(buffer + pos, (char *)v.second.c_str(), v.second.length());
				pos += v.second.length();
				buffer[pos] = 0x20;
				++pos;
			} else {
				DPRINT("FATAL buffer overflow resize buffer\n");
			}
		}
		/*ommit last space*/
		pos -= 2;
		total_length = key.length() + pos + 8;
		type = PUT_REQUEST;

		/*
		 if(num_of_batch_operations_per_thread[id] < NUM_OF_BATCH_OPERATIONS){
			++num_of_batch_operations_per_thread[id];
			*(uint32_t *)(client_buffers[id].buffer + client_buffers[id].pos) = key.length();
			client_buffers[id].pos += 4;
			memcpy(client_buffers[id].buffer+client_buffers[id].pos,(char *)key.c_str(), key.length());
			client_buffers[id].pos += key.length();
			*(uint32_t *)(client_buffers[id].buffer + client_buffers[id].pos) = pos;
			client_buffers[id].pos += 4;
			memcpy(client_buffers[id].buffer+client_buffers[id].pos, buffer, pos);
			client_buffers[id].pos += pos;
			if(num_of_batch_operations_per_thread[id] < NUM_OF_BATCH_OPERATIONS)
				return 0;
			total_length = client_buffers[id].pos;
			type = PUT_REQUEST;

			ops = num_of_batch_operations_per_thread[id];
			num_of_batch_operations_per_thread[id] = 0;
		}
		*/

		cli_tu_region = Client_Get_Tu_Region_and_Mailbox(client_regions, (char *)key.c_str(), key.length(), 0,
								 &mailbox);
		//struct connection_rdma* connection = get_connection_from_region(cli_tu_region);
		struct connection_rdma *connection =
			cli_tu_region->head_net->rdma_conn[id % NUM_OF_CONNECTIONS_PER_SERVER];

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
		unsigned long hash = djb2_hash((unsigned char *)&key_length, sizeof(key_length), -1);
		hash = djb2_hash((unsigned char *)key.c_str(), key_length, hash);
		hash = djb2_hash((unsigned char *)&value_length, sizeof(value_length), hash);
		hash = djb2_hash((unsigned char *)buffer, pos, hash);
		assert(hash);
#endif
		if (type == PUT_REQUEST) {
			*(uint32_t *)mr_message->next = key.length();
			mr_message->next += sizeof(uint32_t);
			if (!push_buffer_in_msg_header(mr_message, (char *)key.c_str(), key.length())) {
				DPRINT("push_buffer for key FAILED\n");
				exit(EXIT_FAILURE);
			}

			*(uint32_t *)mr_message->next = pos;
			mr_message->next += sizeof(uint32_t);
			if (!push_buffer_in_msg_header(mr_message, buffer, pos)) {
				DPRINT("push_buffer for value FAILED\n");
				exit(EXIT_FAILURE);
			}
		} else {
			if (!push_buffer_in_msg_header(mr_message, client_buffers[id].buffer,
							    client_buffers[id].pos)) {
				DPRINT("push_buffer for key FAILED\n");
				exit(EXIT_FAILURE);
			}
		}

		reply_data_message = NULL;
		mr_message->request_message_local_addr = mr_message;
		mr_message->ack_arrived = 1;

#ifdef BLOCKING_INSERT
		mr_message->flags |= SYNC_REQUEST;
#else
		mr_message->flags |= ASYNC_REQUEST;
#endif

		__sync_fetch_and_add(&pending_requests[id], 1);
		async_send_rdma_message(connection, mr_message, &callback_function, &served_requests[id]);

#ifdef BLOCKING_INSERT
		reply_data_message = get_message_reply(connection, mr_message);
		if (reply_data_message == NULL) {
			DPRINT("FATAL send failed\n");
			exit(EXIT_FAILURE);
		}
		free_rdma_received_message(connection, reply_data_message);
		free_rdma_local_message(connection, mr_message);
#endif

		if (type == PUT_REQUEST) {
			//DPRINT("Sent a PUT_REQUEST! request of size %d\n", mr_message->pay_len);
			client_buffers[id].pos = 0;
		}
		return 0;
	}

	int Delete(int id, const std::string &table, const std::string &key)
	{
		std::cerr << "DELETE " << table << ' ' << key << std::endl;
		std::cerr << "Delete() not implemented [" << __FILE__ << ":" << __func__ << "():" << __LINE__ << "]"
			  << std::endl;
		exit(EXIT_FAILURE);
		return 0;
	}
};
} // ycsbc


/**
 * eutropia_db.h
 *  YCSB-C
 * Created by Anastasios Papagiannis on 17/11/15.
 * Copyright (c) 2015 Anastasios Papagiannis <apapag@ics.forth.gr>.
**/

#pragma once

#include "../core/ycsbdb.h"

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
#include <sys/time.h>
#include <boost/algorithm/string.hpp>

#include "../core/properties.h"

extern "C" {
#include "../../kreon_rdma_client/kreon_rdma_client.h"
#include "../../kreon_lib/btree/btree.h"
#include <log.h>
}

#define ZK_HOST "192.168.1.134"
#define ZK_PORT 2181
#define FIELD_COUNT 10
#define MAX_THREADS 128
using std::cout;
using std::endl;

extern std::unordered_map<std::string, int> ops_per_server;
int pending_requests[MAX_THREADS];
int served_requests[MAX_THREADS];
int num_of_batch_operations_per_thread[MAX_THREADS];

namespace ycsbc
{
void callback_function(void *args)
{
	__sync_fetch_and_add((int *)args, 1);
}
class kreonRBlockingClientDB : public YCSBDB {
    private:
	int db_num;
	int field_count;
	std::vector<db_handle *> dbs;

	double tinit, t1, t2;
	struct timeval tim;
	long long how_many = 0;
	int cu_num;
	pthread_mutex_t mutex_num;

    public:
	kreonRBlockingClientDB(int num, utils::Properties &props)
		: db_num(num), field_count(std::stoi(props.GetProperty(CoreWorkload::FIELD_COUNT_PROPERTY,
								       CoreWorkload::FIELD_COUNT_DEFAULT))),
		  dbs()
	{
		struct timeval start;

		if (krc_init(ZK_HOST, ZK_PORT) != KRC_SUCCESS) {
			log_fatal("Failed to init client at zookeeper host %s port %d", ZK_HOST, ZK_PORT);
			exit(EXIT_FAILURE);
		}
		cu_num = 0;
		pthread_mutex_init(&mutex_num, NULL);
		gettimeofday(&start, NULL);
		tinit = start.tv_sec + (start.tv_usec / 1000000.0);
	}

	virtual ~kreonRBlockingClientDB()
	{
		cout << "Calling ~kreonRClientDB()..." << endl;
		gettimeofday(&tim, NULL);
		t2 = tim.tv_sec + (tim.tv_usec / 1000000.0);
		fprintf(stderr, "ycsb=[%lf]sec\n", (t2 - t1));
		fprintf(stderr, "start=[%lf]sec\n", (t1 - tinit));

		// Client_Flush_Volume( client_regions );
		// Client_Flush_Volume_MultipleServers( client_regions );
	}

    public:
	void Init()
	{
	}
	void Close()
	{
		log_info("Done Bye Bye!");
		// exit(EXIT_SUCCESS);
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
		char buffer[2048];
		char *get_buf = buffer;
		uint32_t size = 2048;
		uint32_t code;

		code = krc_get(key.length(), (char *)key.c_str(), &get_buf, &size, 0);
		if (code != KRC_SUCCESS) {
			log_fatal("problem with key %s", key.c_str());
			//exit(EXIT_FAILURE);
		}

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
			// printf("[%s:%s:%d] rest is
			// %s\n",__FILE__,__func__,__LINE__,val+strlen(val)+4);
			exit(EXIT_FAILURE);
		}
		for (auto f : *fields) {
			std::map<std::string, std::string>::iterator it = vmap.find(f);
			if (it == vmap.end()) {
				std::cout << "[2]cannot find : " << f << " in DB " << db_id << std::endl;
				printf("Value %d %s\n", len_val, val);
				fflush(stdout);
				// exit(EXIT_FAILURE);
				break;
			}
			KVPair k = std::make_pair(f, it->second);
			result.push_back(k);
		}
#endif
		return 0;
	}

	int Scan(int id /*ignore*/, const std::string &table /*ignore*/, const std::string &key, int record_count,
		 const std::vector<std::string> *fields /*ignore*/, std::vector<KVPair> &result)
	{
		size_t s_key_size = 0;
		char *s_key = NULL;
		size_t s_value_size = 0;
		char *s_value = NULL;
		krc_scannerp sc = krc_scan_init(32, (16 * 1024));

		krc_scan_set_start(sc, key.length(), (void *)key.c_str(), KRC_GREATER_OR_EQUAL);
		int i = 0;

		while (i < record_count && krc_scan_get_next(sc, &s_key, &s_key_size, &s_value, &s_value_size)) {
			KVPair k = std::make_pair(std::string(s_key, s_key_size), std::string(s_value, s_value_size));
			result.push_back(k);
			++i;
		}
		krc_scan_close(sc);
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
				log_fatal("buffer overflow resize buffer\n");
				exit(EXIT_FAILURE);
			}
		}
		// ommit last space
		pos -= 2;

		if (krc_put(key.length(), (void *)key.c_str(), pos, (void *)buffer) != KRC_SUCCESS) {
			log_fatal("Put failed for key %s", key.c_str());
			exit(EXIT_FAILURE);
		}
		return 0;
	}

	int Insert(int id, const std::string &table /*ignored*/, const std::string &key, std::vector<KVPair> &values)
	{
		char buffer[1512];
		int pos;
		int i;
		int type;
		int total_length = 0;
		int ops = 0;

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
				log_fatal("buffer overflow resize buffer");
				exit(EXIT_FAILURE);
			}
		}
		/*ommit last space*/
		pos -= 2;
		total_length = key.length() + pos + 8;

		if (krc_put(key.length(), (void *)key.c_str(), pos, (void *)buffer) != KRC_SUCCESS) {
			log_fatal("Put failed for key %s", key.c_str());
			exit(EXIT_FAILURE);
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
} // namespace ycsbc

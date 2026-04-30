#ifndef YCSB_C_PARALLAX_DB_IB_H
#define YCSB_C_PARALLAX_DB_IB_H

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <iterator>
#include <mutex>
#include <sstream>
#include <string>

#include "workload_gen.h"
#include <boost/algorithm/string.hpp>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unordered_map>
__thread int x = 0;
extern std::string path;
extern std::string custom_workload;
extern "C" {
#include <parallax/parallax.h>
}
#define MAX_THREADS_NUM 128U
#define GET_BUFFER_SIZE 262144U

using std::cout;
using std::endl;

namespace ycsbc
{

class ParallaxDBIB : public YCSBDB {
    private:
	int db_num;
	int field_count;
	std::unordered_map<int, std::vector<par_handle> > thread_dbs;
	std::mutex db_mutex;

    public:
	ParallaxDBIB(int num, utils::Properties &props)
		: db_num(num)
		, field_count(std::stoi(
			  props.GetProperty(CoreWorkload::FIELD_COUNT_PROPERTY, CoreWorkload::FIELD_COUNT_DEFAULT)))
		, thread_dbs()
	{
	}

	virtual ~ParallaxDBIB()
	{
	}

    private:
	// Retrieve the dbs vector for the current thread, initialize if empty
	std::vector<par_handle> &getDBVector(int thread_id)
	{
		return thread_dbs[thread_id];
	}

    public:
	void Init()
	{
		std::lock_guard<std::mutex> lock(db_mutex);

		if (!thread_dbs[0].empty())
			return;

		par_db_options db_options;
		db_options.volume_name = (char *)"TRELAKIAS";
		db_options.create_flag = PAR_CREATE_DB;
		db_options.options = par_get_default_options();
		for (int i = 0; i < db_num; ++i) {
			std::string db_name = std::string("par_db") + std::to_string(i);
			db_options.db_name = (char *)db_name.c_str();
			const char *error_message = nullptr;
			par_handle hd = par_open(&db_options, &error_message);
			std::cout << "Opened new db with name : " << db_options.db_name << std::endl;

			if (error_message != nullptr) {
				std::cerr << "Error opening DB: " << error_message << std::endl;
				_Exit(EXIT_FAILURE);
			}

			thread_dbs[0].push_back(hd);
		}
	}

	void Close()
	{
		std::lock_guard<std::mutex> lock(db_mutex); // Ensure thread-safe access to the map

		// Iterate over all the thread entries in the global map
		for (auto &entry : thread_dbs) {
			unsigned int tid = entry.first;
			std::vector<par_handle> &dbs = entry.second;

			std::cout << "Closing dbs for thread " << tid << std::endl;

			// Iterate over the dbs vector and close each par_handle
			for (size_t i = 0; i < dbs.size(); ++i) {
				const char *error_message = par_close(dbs[i]);
				if (error_message != nullptr) {
					std::cerr << "Error closing db in thread " << tid << ": " << error_message
						  << std::endl;
					_Exit(EXIT_FAILURE); // Exit if there is an error
				}
			}

			// Clear the vector after closing all dbs
			dbs.clear();
		}

		// Optionally, clear the entire map if you're done with it
		thread_dbs.clear();
	}
	int __read(int id, const std::string &table, const std::string &key, const std::vector<std::string> *fields,
		   std::vector<KVPair> &result)
	{
		std::vector<par_handle> dbs = getDBVector(id);
		char get_buffer[GET_BUFFER_SIZE];
		std::hash<std::string> hash_fn;
		uint32_t db_id = hash_fn(key) % dbs.size();
		std::map<std::string, std::string> vmap;
		struct par_key lookup_key = { .size = (uint32_t)key.length(), .data = (const char *)key.c_str() };
		struct par_value lookup_value = {
			.val_buffer_size = GET_BUFFER_SIZE,
			.val_size = 0,
			.val_buffer = (char *)get_buffer,
		};

		const char *error_message = NULL;
		par_get(dbs[db_id], &lookup_key, &lookup_value, &error_message);
		if (error_message) {
			std::cerr << "[1]cannot find : " << key << " in DB " << db_id << std::endl;
			_exit(EXIT_FAILURE);
		}
		//     return 0;
#if 0
		if (*(int32_t *)val > 16000) {
			std::cout << "TOO LARGE VALUE SIZE IN READ!" << std::endl;
			std::cout << "[" << *(int32_t *)val << "]" << std::endl;
			exit(EXIT_FAILURE);
		}
#endif
#if 0
		std::string value(val + sizeof(int32_t), *(int32_t *)val);

		std::vector<std::string> tokens;
		boost::split(tokens, value, boost::is_any_of(" "));

		int cnt = 0;
#endif
#if 0
		for (std::map<std::string, std::string>::size_type i = 0; i + 1 < tokens.size(); i += 2) {
			vmap.insert(std::pair<std::string, std::string>(tokens[i], tokens[i + 1]));
			++cnt;
		}
		if (cnt != field_count) {
			std::cout << "ERROR IN VALUE!" << std::endl;
			std::cout << "[" << value << "]" << std::endl;
			exit(EXIT_FAILURE);
		}
#endif
#if 0
		for (auto f : *fields) {
			std::map<std::string, std::string>::iterator it = vmap.find(f);
			if (it == vmap.end()) {
				std::cout << "[2]cannot find : " << f << " in DB " << db_id << std::endl;
				return 0;
				exit(EXIT_FAILURE);
			}

			KVPair k = std::make_pair(f, it->second);
			result.push_back(k);
		}
#endif
		return 0;
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

	int Scan(int id, const std::string &table, const std::string &key, int len,
		 const std::vector<std::string> *fields, std::vector<KVPair> &result)
	{
		std::vector<par_handle> dbs = getDBVector(id);

		int items = 0;
		std::hash<std::string> hash_fn;

		struct par_key_value KV_pair = { .k = { .size = (uint32_t)key.length(), .data = key.c_str() },
						 .v = { .val_buffer = NULL } };

		const char *error_message = NULL;
		par_scanner sc =
			par_init_scanner(dbs[hash_fn(key) % db_num], &KV_pair.k, PAR_GREATER_OR_EQUAL, &error_message);
		if (!par_is_valid(sc)) {
			printf("sc is not initisalized after initialization... exiting\n");
			exit(EXIT_FAILURE);
		}

		while (par_is_valid(sc)) {
			if (par_get_next(sc) == 0)
				break;

			if (++items >= len) {
				break;
			}
		}

		par_close_scanner(sc);
		return 0;
	}

	int Update(int id, const std::string &table, const std::string &key, std::vector<KVPair> &values)
	{
		std::vector<par_handle> dbs = getDBVector(id);
		char get_buffer[GET_BUFFER_SIZE];
		if (field_count > 1) { // this results in read-modify-write. Maybe we should use merge operator here
			std::hash<std::string> hash_fn;
			uint32_t db_id = hash_fn(key) % dbs.size();
			std::map<std::string, std::string> vmap;
			struct par_key lookup_key = { .size = (uint32_t)key.length(),
						      .data = (const char *)key.c_str() };
			struct par_value lookup_value = {
				.val_buffer_size = GET_BUFFER_SIZE,
				.val_size = 0,
				.val_buffer = (char *)get_buffer,
			};

			const char *error_message = NULL;
			par_get(dbs[db_id], &lookup_key, &lookup_value, &error_message);
			if (error_message) {
				std::cout << "[1]cannot find : " << key << " in DB " << db_id
					  << "got error: " << error_message << std::endl;
				assert(0);
				exit(EXIT_FAILURE);
			}

#if 0
        if(*(int32_t *)val > 16000){
          std::cout << "TOO LARGE VALUE SIZE IN READ!" << std::endl;
          std::cout << "[" << *(int32_t *)val << "]" << std::endl;
          exit(EXIT_FAILURE);
        }
#endif

			std::vector<std::string> tokens;
#if 0
        if(cnt != field_count){
          std::cout << "ERROR IN VALUE!" << std::endl;
          std::cout << "[" << value << "]" << std::endl;
          exit(EXIT_FAILURE);
        }
			for (auto f : values) {
				std::map<std::string, std::string>::iterator it = vmap.find(f.first);
				if (it == vmap.end()) {
					std::cout << "[2][UPDATE] Cannot find : " << f.first << " in DB " << db_id
						  << std::endl;
					exit(EXIT_FAILURE);
				}

				it->second = f.second;
			}

#endif
			std::vector<KVPair> new_values;

			return Insert(id, table, key, new_values);
#if 0
        std::string new_value;
        for(auto v : vmap){
          new_value.append(v.first);
          new_value.append(1, ' ');
          new_value.append(v.second);
          new_value.append(1, ' ');
        }
        new_value.pop_back();

        if((std::string::size_type)(*(int32_t *)val) != new_value.length()){
          std::cout << "ERROR IN UPDATE!" << std::endl;
          exit(EXIT_FAILURE);
        }

        memcpy(val + sizeof(int32_t), new_value.c_str(), *(int32_t *)val);
#endif
		} else {
			return Insert(id, table, key, values);
		}
	}

	int Insert(int id, const std::string &table, const std::string &key, std::vector<KVPair> &values)
	{
		std::vector<par_handle> dbs = getDBVector(id);

		std::hash<std::string> hash_fn;
		uint32_t db_id = hash_fn(key) % dbs.size();

		static std::string value3(1000, 'a');
		static std::string value2(100, 'a');
		static std::string value(5, 'a');
		int y = x % 10;
		++x;

		struct par_key_value KV_pair = { .k = { .size = 0, .data = NULL }, .v = { .val_buffer = NULL } };
		const char *error_message = NULL;

		KV_pair.k.size = key.length();
		KV_pair.k.data = key.c_str();
		switch (choose_wl(custom_workload, y)) {
		case 0:
			KV_pair.v.val_buffer = (char *)value.c_str();
			KV_pair.v.val_size = value.length();
			break;
		case 1:
			KV_pair.v.val_buffer = (char *)value2.c_str();
			KV_pair.v.val_size = value2.length();
			break;
		case 2:
			KV_pair.v.val_buffer = (char *)value3.c_str();
			KV_pair.v.val_size = value3.length();
			break;
		default:
			assert(0);
			std::cout << "Got Unknown value" << std::endl;
			exit(EXIT_FAILURE);
		}

		par_put(dbs[db_id], &KV_pair, &error_message);
		if (error_message != nullptr) {
			std::cerr << error_message << std::endl;
			exit(EXIT_FAILURE);
		}
#if 0
      if(cnt != field_count){
        std::cout << "[INSERT] ERROR IN VALUE!" << std::endl;
        std::cout << "[" << value << "]" << std::endl;
        exit(EXIT_FAILURE);
      }
#endif

		return 0;
	}
};
} // namespace ycsbc

#endif // YCSB_C_EUTROPIA_DB_H_

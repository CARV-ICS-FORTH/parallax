// -*-c++-*-

//
//  eutropia_db.h
//  YCSB-C
//
//  Created by Anastasios Papagiannis on 17/11/15.
//  Copyright (c) 2015 Anastasios Papagiannis <apapag@ics.forth.gr>.
//

#ifndef YCSB_C_EUTROPIA_DB_H_
#define YCSB_C_EUTROPIA_DB_H_

#include <iostream>
#include <string>
#include <mutex>
#include <algorithm>
#include <atomic>
#include <functional>
#include <sstream>
#include <iterator>

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <signal.h>

#include <boost/algorithm/string.hpp>

//#include "core/properties.h"
extern unsigned priv_thread_count;
extern "C" {
#include "../kreon_lib/allocator/allocator.h"
#include "../kreon_lib/btree/btree.h"
#include "../kreon_lib/btree/delete.h"
#include "../kreon_lib/scanner/scanner.h"
}

using std::cout;
using std::endl;

namespace ycsbc
{
class EutropiaDB : public YCSBDB {
    private:
	int db_num;
	int field_count;
	std::vector<db_handle *> dbs;

    public:
	EutropiaDB(int num, utils::Properties &props)
		: db_num(num), field_count(std::stoi(props.GetProperty(CoreWorkload::FIELD_COUNT_PROPERTY,
								       CoreWorkload::FIELD_COUNT_DEFAULT))),
		  dbs()
	{
		const char *pathname = "/dev/dmap/dmap1";
		//const char *pathname = "/usr/local/gesalous/mounts/kreon.dat";
		int64_t size;

		int fd = open(pathname, O_RDONLY);
		if (fd == -1) {
			perror("open");
			exit(EXIT_FAILURE);
		}

		if (ioctl(fd, BLKGETSIZE64, &size) == -1) {
			perror("ioctl");
			/*maybe we have a file?*/
			printf("[%s:%s:%d] querying file size\n", __FILE__, __func__, __LINE__);
			size = lseek(fd, 0, SEEK_END);
			if (size == -1) {
				printf("[%s:%s:%d] failed to determine volume size exiting...\n", __FILE__, __func__,
				       __LINE__);
				perror("ioctl");
				exit(EXIT_FAILURE);
			}
		}

		close(fd);

		for (int i = 0; i < db_num; ++i) {
			std::string db_name = "data" + std::to_string(i) + ".dat";
			db_handle *db = db_open((char *)pathname, 0, size, (char *)db_name.c_str(), CREATE_DB);
			dbs.push_back(db);
		}
	}

	virtual ~EutropiaDB()
	{
	}

    public:
	void Init()
	{
	}

	void Close()
	{
		snapshot(dbs[0]->volume_desc);
		//flush_volume(dbs[0]->volume_desc, SPILL_ALL_DBS_IMMEDIATELY);
	}

	int __read(int id, const std::string &table, const std::string &key, const std::vector<std::string> *fields,
		   std::vector<KVPair> &result)
	{
		std::hash<std::string> hash_fn;
		uint32_t db_id = hash_fn(key) % db_num;
		std::map<std::string, std::string> vmap;

		char *val = (char *)find_key(dbs[db_id], (void *)key.c_str(), key.length());
		if (val == NULL) {
			std::cout << "[1]cannot find : " << key << " in DB " << db_id << std::endl;
			return 0;
			exit(EXIT_FAILURE);
		}
		//     return 0;
#if 0
		if (*(int32_t *)val > 16000) {
			std::cout << "TOO LARGE VALUE SIZE IN READ!" << std::endl;
			std::cout << "[" << *(int32_t *)val << "]" << std::endl;
			exit(EXIT_FAILURE);
		}
		//#endif
		std::string value(val + sizeof(int32_t), *(int32_t *)val);

		std::vector<std::string> tokens;
		boost::split(tokens, value, boost::is_any_of(" "));

		int cnt = 0;
		for (std::map<std::string, std::string>::size_type i = 0; i + 1 < tokens.size(); i += 2) {
			vmap.insert(std::pair<std::string, std::string>(tokens[i], tokens[i + 1]));
			++cnt;
		}
		//#if 0
		if (cnt != field_count) {
			std::cout << "ERROR IN VALUE!" << std::endl;
			std::cout << "[" << value << "]" << std::endl;
			exit(EXIT_FAILURE);
		}


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
		char key_buf[512];
		int items = 0;
		std::hash<std::string> hash_fn;
		bool done = false;
		unsigned int iter = 0;

		int32_t klen = key.length();
		memcpy(key_buf, &klen, sizeof(int32_t));
		memcpy(key_buf + sizeof(int32_t), key.c_str(), key.length());

		struct scannerHandle *sh = (struct scannerHandle *)malloc(sizeof(struct scannerHandle));
		init_dirty_scanner(sh, dbs[hash_fn(key) % db_num], key_buf, GREATER_OR_EQUAL);
		//if (!isValid(&sh)) {
		//snapshot(dbs[0]->volume_desc);
		//initScanner(&sh, dbs[hash_fn(key) % db_num], key_buf, GREATER_OR_EQUAL);
		//}

		while (isValid(sh)) {
#if 0
        if(getKeySize(&sh) > 16000){
          std::cout << "TOO LARGE KEY SIZE! iter = " << iter << std::endl;
          std::cout << "[" << getKeySize(&sh) << "]" << std::endl;
          exit(EXIT_FAILURE);
        }

        if(getValueSize(&sh) > 16000){
          std::cout << "TOO LARGE VALUE SIZE!" << std::endl;
          std::cout << "[" << getValueSize(&sh) << "]" << std::endl;
          exit(EXIT_FAILURE);
        }


			std::string k((char *)getKeyPtr(&sh), getKeySize(&sh));
			std::string v((char *)getValuePtr(&sh), getValueSize(&sh));

			std::vector<std::string> tokens;
			boost::split(tokens, v, boost::is_any_of(" "));

        if(tokens.size() % 2 != 0){
          std::cout << "TOKENS ARRAY NOT MULTIPLE OF 2!" << std::endl;
          std::cout << "[" << v << "]" << std::endl;
          exit(EXIT_FAILURE);
        }

			std::map<std::string, std::string> vmap;
			int cnt = 0;
			for (std::map<std::string, std::string>::size_type i = 0; i + 1 < tokens.size(); i += 2) {
				vmap.insert(std::pair<std::string, std::string>(tokens[i], tokens[i + 1]));
				++cnt;
			}


        if(cnt != field_count){
          std::cout << "ERROR IN VALUE!" << (void *)getKeyPtr(&sh) << std::endl;
          std::cout << "[" << v << "]" << std::endl;
          exit(EXIT_FAILURE);
        }


			for (std::map<std::string, std::string>::iterator it = vmap.begin(); it != vmap.end(); ++it) {
				KVPair kv = std::make_pair(k + it->first, it->second);
				result.push_back(kv);

				if (++items >= len) {
					done = true;
					break;
				}
			}

			if (done)
				break;

#endif
			if (getNext(sh) == END_OF_DATABASE)
				break;

			if (++items >= len) {
				break;
			}
		}
		closeScanner(sh);
		free(sh);
		return 0;
	}

	int Update(int id, const std::string &table, const std::string &key, std::vector<KVPair> &values)
	{
		if (field_count > 1) { // this results in read-modify-write. Maybe we should use merge operator here
			std::hash<std::string> hash_fn;
			uint32_t db_id = hash_fn(key) % db_num;
			std::map<std::string, std::string> vmap;

			char *val = (char *)find_key(dbs[db_id], (void *)key.c_str(), key.length());
			if (val == NULL) {
				std::cout << "[1]cannot find : " << key << " in DB " << db_id << std::endl;
				exit(EXIT_FAILURE);
			}
#if 0
        if(*(int32_t *)val > 16000){
          std::cout << "TOO LARGE VALUE SIZE IN READ!" << std::endl;
          std::cout << "[" << *(int32_t *)val << "]" << std::endl;
          exit(EXIT_FAILURE);
        }
#endif
			std::string value(val + sizeof(int32_t), *(int32_t *)val);

			std::vector<std::string> tokens;
			boost::split(tokens, value, boost::is_any_of(" "));

			int cnt = 0;
			for (std::map<std::string, std::string>::size_type i = 0; i + 1 < tokens.size(); i += 2) {
				vmap.insert(std::pair<std::string, std::string>(tokens[i], tokens[i + 1]));
				++cnt;
			}
#if 0
        if(cnt != field_count){
          std::cout << "ERROR IN VALUE!" << std::endl;
          std::cout << "[" << value << "]" << std::endl;
          exit(EXIT_FAILURE);
        }
#endif
			for (auto f : values) {
				std::map<std::string, std::string>::iterator it = vmap.find(f.first);
				if (it == vmap.end()) {
					std::cout << "[2][UPDATE] Cannot find : " << f.first << " in DB " << db_id
						  << std::endl;
					exit(EXIT_FAILURE);
				}

				it->second = f.second;
			}

			std::vector<KVPair> new_values;
			for (std::map<std::string, std::string>::iterator it = vmap.begin(); it != vmap.end(); ++it) {
				KVPair kv = std::make_pair(it->first, it->second);
				new_values.push_back(kv);
			}

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
		std::hash<std::string> hash_fn;
		uint32_t db_id = hash_fn(key) % db_num;

		std::string value;
		int cnt = 0;
		for (auto v : values) {
			value.append(v.first);
			value.append(1, ' ');
			value.append(v.second);
			value.append(1, ' ');
			++cnt;
		}
		value.pop_back();

#if 0
      if(cnt != field_count){
        std::cout << "[INSERT] ERROR IN VALUE!" << std::endl;
        std::cout << "[" << value << "]" << std::endl;
        exit(EXIT_FAILURE);
      }
#endif

		insert_key_value(dbs[db_id], (void *)key.c_str(), (void *)value.c_str(), key.length(), value.size());

		return 0;
	}

	int Delete(int id, const std::string &table, const std::string &key)
	{
		std::hash<std::string> hash_fn;
		int8_t ret;
		uint32_t db_id = hash_fn(key) % db_num;

		ret = delete_key(dbs[db_id], (void *)key.c_str(), key.size());
		if (ret != 0) {
			std::cerr << "I could not delete " << key << std::endl;
			return 0;
		}
		return 0;
	}
};
} // namespace ycsbc

#endif // YCSB_C_EUTROPIA_DB_H_

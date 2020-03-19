//
//  basic_db.h
//  YCSB-C
//
//  Created by Jinglei Ren on 12/17/14.
//  Copyright (c) 2014 Jinglei Ren <jinglei@ren.systems>.
//

#ifndef YCSB_C_BASIC_DB_H_
#define YCSB_C_BASIC_DB_H_

#include "core/ycsbdb.h"

#include <iostream>
#include <string>
#include <mutex>
#include "core/properties.h"

using std::cout;
using std::endl;

namespace ycsbc {

	class BasicDB : public YCSBDB {
		private:
			uint64_t max_key_length;
			std::vector<std::string> keys;

		public:
			BasicDB() : max_key_length(0), keys() {}
			virtual ~BasicDB(){
				std::cout << "max key length is " << max_key_length << std::endl;
				std::sort(keys.begin(), keys.end());
				std::cout << keys[125000] << std::endl;
				std::cout << keys[250000] << std::endl;
				std::cout << keys[375000] << std::endl;
				std::cout << keys[500000] << std::endl;
				std::cout << keys[625000] << std::endl;
				std::cout << keys[750000] << std::endl;
				std::cout << keys[875000] << std::endl;

			}

			void Init() {
				std::lock_guard<std::mutex> lock(mutex_);
				cout << "A new thread begins working." << endl;
			}

			int Read(int id, const std::string &table, const std::string &key,
					const std::vector<std::string> *fields,
					std::vector<KVPair> &result) {
				std::lock_guard<std::mutex> lock(mutex_);
				cout << "READ " << table << ' ' << key;
				if (fields) {
					cout << " [ ";
					for (auto f : *fields) {
						cout << f << ' ';
					}
					cout << ']' << endl;
				} else {
					cout  << " < all fields >" << endl;
				}
				return 0;
			}

			int Scan(int id, const std::string &table, const std::string &key,
					int len, const std::vector<std::string> *fields,
					std::vector<std::vector<KVPair>> &result) {
				std::lock_guard<std::mutex> lock(mutex_);
				cout << "SCAN " << table << ' ' << key << " " << len;
				if (fields) {
					cout << " [ ";
					for (auto f : *fields) {
						cout << f << ' ';
					}
					cout << ']' << endl;
				} else {
					cout  << " < all fields >" << endl;
				}
				return 0;
			}

			int Update(int id, const std::string &table, const std::string &key,
					std::vector<KVPair> &values) {
				std::lock_guard<std::mutex> lock(mutex_);
				cout << "UPDATE " << table << ' ' << key << " [ ";
				for (auto v : values) {
					cout << v.first << '=' << v.second << ' ';
				}
				cout << ']' << endl;
				return 0;
			}

			int Insert(int id, const std::string &table, const std::string &key, std::vector<KVPair> &values) {
				std::lock_guard<std::mutex> lock(mutex_);
				if(key.length() > max_key_length)
					max_key_length = key.length();
				keys.push_back(key);

#if 0
				cout << "INSERT[" << id << "]" << table << ' ' << key << " [ ";
				for (auto v : values) {
					cout << v.first << '=' << v.second << ' ';
					cout << "key size = " << key.size() + v.first.size() << " value size = " << v.second.size() << endl;
				}
				cout << ']' << endl;
#endif
				return 0;
			}

			int Delete(int id, const std::string &table, const std::string &key) {
				std::lock_guard<std::mutex> lock(mutex_);
				cout << "DELETE " << table << ' ' << key << endl;
				return 0; 
			}

		private:
			std::mutex mutex_;
	};

} // ycsbc

#endif // YCSB_C_BASIC_DB_H_


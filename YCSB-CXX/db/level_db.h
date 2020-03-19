//
//  level_db.h
//  YCSB-C
//
//  Created by Anastasios Papagiannis on 17/11/15.
//  Copyright (c) 2015 Anastasios Papagiannis <apapag@ics.forth.gr>.
//

#ifndef YCSB_C_LEVEL_DB_H_
#define YCSB_C_LEVEL_DB_H_

#include "core/ycsbdb.h"

#include <iostream>
#include <string>
#include <mutex>
#include <algorithm>
#include <atomic>
#include <functional>
#include <set>

#include "core/properties.h"

#include <leveldb/db.h>
#include <leveldb/options.h>
#include <leveldb/comparator.h>
#include <leveldb/slice.h>
#include <leveldb/cache.h>
#include <leveldb/filter_policy.h>

#define FIELD_COUNT 10

using std::cout;
using std::endl;

namespace ycsbc {
	class LevelDB : public YCSBDB {
		private:
			int db_num;
			std::vector<leveldb::DB*> dbs;

		public:
			LevelDB(int num) : db_num(num), dbs() {
				for(int i = 0; i < db_num; ++i){
					leveldb::Options options;
					options.compression = leveldb::kNoCompression;
					options.create_if_missing = true;
					options.block_cache = leveldb::NewLRUCache(512 * 1024 * 1024); // 512MB
					options.write_buffer_size = 64 * 1024 * 1024; // 64MB
					options.max_open_files = INT32_MAX;
					options.filter_policy = leveldb::NewBloomFilterPolicy(100); // 100 bit bloom filter
				//	options.block_size = 5 * (16 * 1024);

					std::string db_name = "/root/HEutropia/YCSB-CXX/database/" + std::to_string(i);

					leveldb::DB *db;
					leveldb::Status status = leveldb::DB::Open(options, db_name, &db);
					if(!status.ok())
						std::cerr << status.ToString() << std::endl;

					dbs.push_back(db);
				}
			}

			virtual ~LevelDB(){
				cout << "Calling ~LevelDB()..." << endl;
				for(auto& d : dbs)
					delete d;
			}

		public:
			void Init(){}
			void Close(){}

			int Read(int id, const std::string &table, const std::string &key, const std::vector<std::string> *fields, std::vector<KVPair> &result)
			{
				std::hash<std::string> hash_;

				if(fields){
					for(auto f : *fields){
						std::string rowcol = key + f;
						std::string value;
						leveldb::Status ret = dbs[hash_(rowcol) % db_num]->Get(leveldb::ReadOptions(), rowcol, &value);
						if(ret.ok() != true)
							std::cout << "CANNOT FIND KEY!" << std::endl;
						KVPair k = std::make_pair(f, value);
						result.push_back(k);
					}
				}else{
					std::vector<std::string> __fields;
					for(int i = 0; i < FIELD_COUNT; ++i)
						__fields.push_back("field" + std::to_string(i));
					return Read(id, table, key, &__fields, result);
				}

				return 0;
			}
			int Scan(int id, const std::string &table, const std::string &key, int len, const std::vector<std::string> *fields, 
					std::vector<std::vector<KVPair>> &result)
			{
				std::hash<std::string> hash_;

				if(fields){
					for(auto f : *fields){
						int items = 0;
						std::string rowcol = key + f;
						std::vector<KVPair> tmp_result;

						leveldb::Iterator* it = dbs[hash_(rowcol) % db_num]->NewIterator(leveldb::ReadOptions());
						for(it->Seek(rowcol); it->Valid(); it->Next()){
							std::string value = it->value().ToString();
							KVPair kv = std::make_pair(f, value);
							tmp_result.push_back(kv);

							items++;
							if(items >= len)
								break;	
						}

						result.push_back(tmp_result);
						delete it;
					}

				}else{
					std::vector<std::string> __fields;
					for(int i = 0; i < FIELD_COUNT; ++i)
						__fields.push_back("field" + std::to_string(i));
					return Scan(id, table, key, len, &__fields, result);
				}

				return 0;
			}

			int Update(int id, const std::string &table, const std::string &key, std::vector<KVPair> &values)
			{
				return Insert(id, table, key, values);
			}

			int Insert(int id, const std::string &table, const std::string &key, std::vector<KVPair> &values)
			{
				std::hash<std::string> hash_;

				for(auto v : values){
					std::string rowcol = key + v.first;
					dbs[hash_(rowcol) % db_num]->Put(leveldb::WriteOptions(), rowcol, v.second);
				}

				return 0;
			}

			int Delete(int id, const std::string &table, const std::string &key)
			{
				std::cerr << "DELETE " << table << ' ' << key << std::endl;
				std::cerr << "Delete() not implemented [" << __FILE__ << ":" << __func__ << "():" << __LINE__ << "]" << std::endl;
				exit(EXIT_FAILURE);
			}
	};
} // ycsbc

#endif // YCSB_C_LEVEL_DB_H_


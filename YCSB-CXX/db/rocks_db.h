//
//  rocks_db.h
//  YCSB-C
//
//  Created by Anastasios Papagiannis on 17/11/15.
//  Copyright (c) 2015 Anastasios Papagiannis <apapag@ics.forth.gr>.
//

#ifndef YCSB_C_ROCKS_DB_H_
#define YCSB_C_ROCKS_DB_H_

#include "core/ycsbdb.h"

#include <iostream>
#include <string>
#include <mutex>
#include <algorithm>
#include <atomic>
#include <functional>
#include <set>

#include "core/properties.h"

#include <rocksdb/db.h>
#include <rocksdb/slice.h>
#include <rocksdb/options.h>
#include <rocksdb/cache.h>
#include <rocksdb/table.h>
#include <rocksdb/filter_policy.h>
#include <rocksdb/write_batch.h>

#include <boost/algorithm/string.hpp>

#define GB(x) (x * 1024LU * 1024LU * 1024LU)

using std::cout;
using std::endl;

namespace ycsbc {
	class RocksDB : public YCSBDB {
		private:
			int db_num;
			int field_count;
			std::vector<rocksdb::DB*> dbs;
			const unsigned long long cache_size = GB(16);
			std::shared_ptr<rocksdb::Cache> cache;

		public:
			RocksDB(int num, utils::Properties& props) : db_num(num), field_count(std::stoi(props.GetProperty(CoreWorkload::FIELD_COUNT_PROPERTY, CoreWorkload::FIELD_COUNT_DEFAULT))), dbs() {
					
				cache = rocksdb::NewLRUCache(cache_size);
						
				for(int i = 0; i < db_num; ++i){

					rocksdb::Options options;

					options.compression = rocksdb::kNoCompression;
					options.create_if_missing = true;
					options.max_open_files = -1;
					options.IncreaseParallelism();
					
					options.use_direct_reads = true;
					options.use_direct_io_for_flush_and_compaction = true;
					options.compaction_readahead_size = 2 * 1024 * 1024;
					options.writable_file_max_buffer_size = 1024 * 1024;
					
					rocksdb::BlockBasedTableOptions table_options;
					table_options.block_cache = cache;
					options.table_factory.reset(NewBlockBasedTableFactory(table_options));

					std::string db_name = "/mnt/datavol/" + std::to_string(i);

					rocksdb::DB *db;
					rocksdb::Status status = rocksdb::DB::Open(options, db_name, &db);
					if(!status.ok())
						std::cerr << status.ToString() << std::endl;

					dbs.push_back(db);
				}
			}

			virtual ~RocksDB(){
				cout << "Calling ~RocksDB()..." << endl;
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
					std::string value;
					rocksdb::Status ret = dbs[hash_(key) % db_num]->Get(rocksdb::ReadOptions(), key, &value);
					if(ret.ok() != true){
						std::cout << "CANNOT FIND KEY!" << std::endl;
						exit(EXIT_FAILURE);
					}

        	std::vector<std::string> tokens;
        	boost::split(tokens, value, boost::is_any_of(" "));

					std::map<std::string, std::string> vmap;
        	for(std::map<std::string, std::string>::size_type i = 0 ; i + 1 < tokens.size(); i += 2){
          	vmap.insert(std::pair<std::string, std::string>(tokens[i], tokens[i+1]));
        	}

        	for(auto f : *fields){
          	std::map<std::string, std::string>::iterator it = vmap.find(f);
          	if(it == vmap.end()){
            	std::cout << "cannot find : " << f << " in DB" << std::endl;
            	exit(EXIT_FAILURE);
          	}

          	KVPair k = std::make_pair(f, it->second);
          	result.push_back(k);
        	}
				}else{
					std::vector<std::string> __fields;
					for(int i = 0; i < field_count; ++i)
						__fields.push_back("field" + std::to_string(i));
					return Read(id, table, key, &__fields, result);
				}
				
				return 0;
			}

			int Scan(int id, const std::string &table, const std::string &key, int len, const std::vector<std::string> *fields, std::vector<KVPair> &result)
			{
				std::hash<std::string> hash_;
				int items = 0;
				bool done = false;

				rocksdb::Iterator* it = dbs[hash_(key) % db_num]->NewIterator(rocksdb::ReadOptions());
				it->Seek(key);
				if(it->status().ok() != true){
					std::cerr << "ERROR in status scan!" << std::endl;
					exit(EXIT_FAILURE);
				}

				while(it->Valid())
				{
					std::string kk = it->key().ToString();
					std::string value = it->value().ToString();

        	std::vector<std::string> tokens;
        	boost::split(tokens, value, boost::is_any_of(" "));

					std::map<std::string, std::string> vmap;
        	for(std::map<std::string, std::string>::size_type i = 0 ; i + 1 < tokens.size(); i += 2){
          	vmap.insert(std::pair<std::string, std::string>(tokens[i], tokens[i+1]));
        	}

					for(std::map<std::string, std::string>::iterator it = vmap.begin(); it != vmap.end(); ++it){
						KVPair kv = std::make_pair(kk + it->first, it->second);
						result.push_back(kv);
					
						if(++items >= len){
							done = true;
							break;	
						}
					}
					
					if(done)
						break;

					it->Next();
					if(it->status().ok() != true){
						std::cerr << "ERROR in status scan!" << std::endl;
						exit(EXIT_FAILURE);
					}
				}

				if(items == 0){
					std::cerr << "ERROR zero len scan!" << std::endl;
					exit(EXIT_FAILURE);
				}

				delete it;
				
				return 0;
			}

			int Update(int id, const std::string &table, const std::string &key, std::vector<KVPair> &values)
			{
				if(field_count > 1){ // this results in read-modify-write. Maybe we should use merge operator here
					std::hash<std::string> hash_;
					std::string value;
					rocksdb::Status ret = dbs[hash_(key) % db_num]->Get(rocksdb::ReadOptions(), key, &value);
					if(ret.ok() != true){
						std::cout << "CANNOT FIND KEY!" << std::endl;
						exit(EXIT_FAILURE);
					}

        	std::vector<std::string> tokens;
        	boost::split(tokens, value, boost::is_any_of(" "));

					std::map<std::string, std::string> vmap;
        	for(std::map<std::string, std::string>::size_type i = 0 ; i + 1 < tokens.size(); i += 2){
          	vmap.insert(std::pair<std::string, std::string>(tokens[i], tokens[i+1]));
        	}

					for(auto f : values){
          	std::map<std::string, std::string>::iterator it = vmap.find(f.first);
          	if(it == vmap.end()){
            	std::cout << "[2][UPDATE] Cannot find : " << f.first << " in DB" << std::endl;
            	exit(EXIT_FAILURE);
          	}

          	it->second = f.second;
        	}


					std::vector<KVPair> new_values;
					for(std::map<std::string, std::string>::iterator it = vmap.begin(); it != vmap.end(); ++it){
						KVPair kv = std::make_pair(it->first, it->second);
						new_values.push_back(kv);
					}

					return Insert(id, table, key, new_values);
				}else{
					return Insert(id, table, key, values);
				}
			}

			int Insert(int id, const std::string &table, const std::string &key, std::vector<KVPair> &values)
			{
				std::hash<std::string> hash_;

				std::string value;  
        for(auto v : values){
          value.append(v.first);
          value.append(1, ' ');
          value.append(v.second);
          value.append(1, ' ');
        }
        value.pop_back();
	
				rocksdb::Status ret = dbs[hash_(key) % db_num]->Put(rocksdb::WriteOptions(), key, value);
				if(ret.ok() != true){
					std::cout << "CANNOT INSERT KEY!" << std::endl;
					exit(EXIT_FAILURE);
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

#endif // YCSB_C_ROCKS_DB_H_


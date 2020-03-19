//
//  berkeley_db.h
//  YCSB-C
//
//  Created by Anastasios Papagiannis on 17/11/15.
//  Copyright (c) 2015 Anastasios Papagiannis <apapag@ics.forth.gr>.
//

#ifndef YCSB_C_BERKELEY_DB_H_
#define YCSB_C_BERKELEY_DB_H_

#include "core/ycsbdb.h"

#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <string>
#include <mutex>
#include <algorithm>
#include <atomic>
#include <functional>
#include <iomanip>
#include <set>

#include "core/properties.h"

#include <db_cxx.h>

#define FIELD_COUNT 10

using std::cout;
using std::cerr;
using std::endl;

namespace ycsbc {
	class BerkeleyDB : public YCSBDB {
		private:
			int db_num;
			std::vector<DbEnv*> envs;
			std::vector<Db*> dbs;
			std::mutex *mtx;

		public:
			BerkeleyDB(int num) : db_num(num), envs(), dbs() {
				mtx = new std::mutex[num];
				try{
					for(int i = 0; i < db_num; i++){
						Db* pdb;
						DbTxn *tid;
						int ret;

						DbEnv *env = new DbEnv(0);
						env->set_error_stream(&cerr);
						env->set_cachesize(4, 0, 1); // 4GB

						std::string env_name = "/root/HEutropia/YCSB-CXX/database/" + std::to_string(i);
						env->open(env_name.c_str(), DB_CREATE | DB_PRIVATE | DB_INIT_MPOOL | DB_INIT_TXN | DB_INIT_LOCK | DB_INIT_LOG, 0);

						pdb = new Db(env, 0);
						std::string db_name = env_name + "/data.db";

						if((ret = env->txn_begin(NULL, &tid, 0)) != 0){
							env->err(ret, "DB_ENV->txn_begin");
							exit(EXIT_FAILURE);
						}

						pdb->open(tid, db_name.c_str(), NULL, DB_BTREE, DB_CREATE, 0);

						if((ret = tid->commit(0)) != 0){
							env->err(ret, "DB_TXN->commit");
							exit(EXIT_FAILURE);
						}

						dbs.push_back(pdb);
						envs.push_back(env);
					}
				}catch(DbException& e){
					std::cerr << "DbException: " << e.what() << endl;
					exit(EXIT_FAILURE);
				}catch(std::exception& e){
					std::cerr << e.what() << endl;
					exit(EXIT_FAILURE);
				}
			}

			virtual ~BerkeleyDB(){
				cout << "Calling ~BerkeleyDB()..." << endl;

				for(auto& d : dbs){
					d->close(0);
					delete d;
				}

				for(auto& d : envs)
					d->close(0);

				delete[] mtx;
			}

		public:
			void Init(){}
			void Close(){}

			int Read(int id, const std::string &table, const std::string &key, const std::vector<std::string> *fields, std::vector<KVPair> &result)
			{
				std::hash<std::string> hash_;
				DbTxn *tid; 
				int ret; 

				if(fields){
					for(auto f : *fields){
						std::string rowcol = key + f;
						int32_t db_id = hash_(key) % db_num;

						Dbt key(const_cast<char*>(rowcol.data()), rowcol.size());
						Dbt data;

						if((ret = envs[db_id]->txn_begin(NULL, &tid, 0)) != 0){
							envs[db_id]->err(ret, "DB_ENV->txn_begin");
							exit(EXIT_FAILURE);
						}

						dbs[db_id]->get(tid, &key, &data, 0);
				
						if((ret = tid->commit(0)) != 0){
							envs[db_id]->err(ret, "DB_TXN->commit");
							exit(EXIT_FAILURE);
						}
						
						std::string value((const char *)data.get_data(), data.get_size());
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
#if 0
				std::hash<std::string> hash_;

				if(fields){
					for(auto f : *fields){
						int items = 0;
						std::string rowcol = key + f;
						std::vector<KVPair> tmp_result;

						int32_t db_id = hash_(rowcol) % db_num;
						Dbc *cursorp;
						Dbt key(const_cast<char*>(rowcol.data()), rowcol.size());
						Dbt data;

						mtx[db_id].lock();
						dbs[db_id]->cursor(NULL, &cursorp, 0);
						int ret = cursorp->get(&key, &data, DB_SET);
						while(ret != DB_NOTFOUND){
							std::string value((const char *)data.get_data(), data.get_size());
							KVPair kv = std::make_pair(f, value);
							tmp_result.push_back(kv);

							items++; 
							if(items >= len)
								break;

							ret = cursorp->get(&key, &data, DB_NEXT);
						}
						cursorp->close();
						mtx[db_id].unlock();

						result.push_back(tmp_result);
					}
				}else{
					std::vector<std::string> __fields;
					for(int i = 0; i < FIELD_COUNT; ++i)
						__fields.push_back("field" + std::to_string(i));
					return Scan(id, table, key, len, &__fields, result);
				}
#endif
				return 0;
			}

			int Update(int id, const std::string &table, const std::string &key, std::vector<KVPair> &values)
			{
				return Insert(id, table, key, values);
			}

			int Insert(int id, const std::string &table, const std::string &key, std::vector<KVPair> &values){
				std::hash<std::string> hash_;
				DbTxn *tid;
				int32_t db_id = hash_(key) % db_num;
				int ret;
					
				if((ret = envs[db_id]->txn_begin(NULL, &tid, 0)) != 0){
					envs[db_id]->err(ret, "DB_ENV->txn_begin");
					exit(EXIT_FAILURE);
				}

				for(auto v : values){
					std::string rowcol = key + v.first;

					Dbt key(const_cast<char*>(rowcol.data()), rowcol.size());
					Dbt value(const_cast<char*>(v.second.data()), v.second.size());

					dbs[db_id]->put(tid, &key, &value, 0);
				}

				if((ret = tid->commit(0)) != 0){
					envs[db_id]->err(ret, "DB_TXN->commit");
					exit(EXIT_FAILURE);
				}

				return 0;
			}

			int Delete(int id, const std::string &table, const std::string &key)
			{
				std::cerr << "DELETE " << table << ' ' << key << std::endl;
				std::cerr << "Delete() not implemented [" << __FILE__ << ":" << __func__ << "():" << __LINE__ << "]" << std::endl;
				exit(EXIT_FAILURE);
				return 0; 
			}
	};
} // ycsbc

#endif // YCSB_C_BERKELEY_DB_H_


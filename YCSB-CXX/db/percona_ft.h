//
//  percona_ft.h
//  YCSB-C
//
//  Created by Anastasios Papagiannis on 17/11/15.
//  Copyright (c) 2015 Anastasios Papagiannis <apapag@ics.forth.gr>.
//

#ifndef YCSB_C_PERCONA_FT_H_
#define YCSB_C_PERCONA_FT_H_

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
#include <algorithm>
#include <cassert>
#include <cstring>
#include <iostream>
#include <utility>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/properties.h"

#include <db.h>

#include <ftcxx/cursor.hpp>
#include <ftcxx/db.hpp>
#include <ftcxx/db_env.hpp>
#include <ftcxx/db_txn.hpp>
#include <ftcxx/slice.hpp>

#define FIELD_COUNT 10

using std::cout;
using std::cerr;
using std::endl;

#define assert_zero(expr) toku_do_assert((expr) == 0, #expr, __FUNCTION__, __FILE__, __LINE__, get_maybe_error_errno())

void toku_do_assert(int,const char*,const char *,const char*,int, int) __attribute__((__visibility__("default")));
int toku_os_mkdir(const char *, mode_t);

static inline int get_maybe_error_errno(void)
{ 
	return errno;
}

static __attribute__((__unused__)) int string_dbt_cmp (DB *db, const DBT *a, const DBT *b)
{
	std::string l((const char *)a->data, a->size);
	std::string r((const char *)b->data, b->size);
	return l.compare(r);
}

namespace ycsbc {
	class PerconaFT : public YCSBDB {
		private:
			int db_num;
			std::vector<ftcxx::DB*> dbs;
			std::vector<ftcxx::DBEnv*> envs;
			std::hash<std::string> hash_;

		public:
			PerconaFT(int num) : db_num(num), dbs(), envs(), hash_() {
				int r;
				for(int i = 0; i < db_num; i++){
					ftcxx::DB *pdb;
					ftcxx::DBEnv *env;

					std::string env_dir = "/root/HEutropia/YCSB-CXX/database/" + std::to_string(i);
					r = toku_os_mkdir(env_dir.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
					assert_zero(r);

					int env_open_flags = DB_CREATE | DB_INIT_MPOOL | DB_INIT_TXN | DB_INIT_LOCK | DB_INIT_LOG;
					ftcxx::DBEnv tmp_env = ftcxx::DBEnvBuilder() 
																		.set_default_bt_compare(string_dbt_cmp) 
																		.set_direct_io(false) 
																		.open(env_dir.c_str(), env_open_flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
					env = new ftcxx::DBEnv(std::move(tmp_env)); 

					const char *db_filename = "ftcxx_ycsb_data";

					ftcxx::DBTxn create_txn(*env);
					ftcxx::DB tmp_db = ftcxx::DBBuilder()
																.set_pagesize(16 * 1024)
																.open(*env, create_txn, db_filename, NULL, DB_BTREE, DB_CREATE, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
					create_txn.commit();
					pdb = new ftcxx::DB(std::move(tmp_db));
					
					dbs.push_back(pdb);
					envs.push_back(env);
				}
			}

			virtual ~PerconaFT(){
				cout << "Calling ~PerconaFT()..." << endl;

				for(auto& d : dbs){
					d->close();
					delete d;
				}

				for(auto& d : envs){
					d->close();
					delete d;
				}
#ifdef USE_LOCKS
				delete[] mtx;
#endif
			}

		public:
			void Init(){}
			void Close(){}

			int Read(int id, const std::string &table, const std::string &key, const std::vector<std::string> *fields, std::vector<KVPair> &result)
			{
				std::hash<std::string> hash_;
				int32_t db_id = hash_(key) % db_num;

				if(fields){
					ftcxx::DBTxn txn(*(envs[db_id])); 
					for(auto f : *fields){
						std::string rowcol = key + f;

						DBT key;
						key.data = (void *)rowcol.data();
						key.size = rowcol.size();
						DBT data;

						dbs[db_id]->get(txn, &key, &data);

						std::string value((const char *)data.data, data.size);
						KVPair k = std::make_pair(f, value);
						result.push_back(k);
					}
					txn.commit();
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

			int Insert(int id, const std::string &table, const std::string &key, std::vector<KVPair> &values)
			{
				int32_t db_id = hash_(key) % db_num;
				char key_buf[512];
				size_t key_len = key.length();
				memcpy(&key_buf[0], key.data(), key_len);

				ftcxx::DBTxn txn(*(envs[db_id]));
				for(auto v : values){
					memcpy(&key_buf[key.length()], v.first.data(), v.first.length());
					key_buf[key_len + v.first.length()] = '\0';
					ftcxx::Slice kk(&key_buf[0], key.length() + v.first.length());
					ftcxx::Slice vv(v.second.data(), v.second.size());
					dbs[db_id]->put(txn, kk, vv);
				}
				txn.commit();

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

#endif // YCSB_C_PERCONA_FT_H_


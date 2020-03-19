//
//  kyoto_db.h
//  YCSB-C
//
//  Created by Anastasios Papagiannis on 17/11/15.
//  Copyright (c) 2015 Anastasios Papagiannis <apapag@ics.forth.gr>.
//

#ifndef YCSB_C_KYOTO_DB_H_
#define YCSB_C_KYOTO_DB_H_

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

#include <kcpolydb.h>

#define FIELD_COUNT 10

using std::cout;
using std::cerr;
using std::endl;

namespace ycsbc {
	class KyotoDB : public YCSBDB {
		private:
			int db_num;
			std::vector<kyotocabinet::TreeDB*> dbs;
			std::atomic_uint_fast64_t found;
			std::atomic_uint_fast64_t not_found;

		public:
			KyotoDB(int num) : db_num(num), dbs(), found(0), not_found(0) {
				for(int i = 0; i < db_num; i++){
					kyotocabinet::TreeDB *db = new  kyotocabinet::TreeDB();
	
					db->tune_page_cache(1U << 19); // 512 MB
					db->tune_page(1U << 12); // 4 KB

					std::string db_name = "/root/HEutropia/YCSB-CXX/database/casket." + std::to_string(i) + ".kch";
					if(!db->open(db_name, kyotocabinet::PolyDB::OWRITER | kyotocabinet::PolyDB::OCREATE)){
						cerr << "open error: " << db->error().name() << endl;
					}

					dbs.push_back(db);
				}
			}

			virtual ~KyotoDB(){
				cout << "Calling ~KyotoDB()..." << endl;
				cout << "found : " << found << endl;
				cout << "not found : " << not_found << endl;

				for(auto& d : dbs){
					if(!d->close()){
						cerr << "close error: " << d->error().name() << endl;
					}
					delete d;
				}
			}

		public:
			void Init(){}
			void Close(){}

			int Read(int id, const std::string &table, const std::string &key, const std::vector<std::string> *fields, std::vector<KVPair> &result){
				std::hash<std::string> hash_;

				if(fields){
					for(auto f : *fields){
						std::string rowcol = key + f;
						std::string value;
						dbs[hash_(rowcol) % db_num]->get(rowcol, &value);
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

						kyotocabinet::DB::Cursor* cur = dbs[hash_(rowcol) % db_num]->cursor();
						cur->jump(rowcol);
						std::string ckey, cvalue;
						while(cur->get(&ckey, &cvalue, true)){
              KVPair kv = std::make_pair(f, cvalue);
              tmp_result.push_back(kv);

              items++;
              if(items >= len)
                break;  
            }

            result.push_back(tmp_result);
            delete cur; 
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
					dbs[hash_(rowcol) % db_num]->set(rowcol, v.second);
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

#endif // YCSB_C_KYOTO_DB_H_


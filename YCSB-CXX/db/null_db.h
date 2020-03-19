//
//  eutropia_db.h
//  YCSB-C
//
//  Created by Anastasios Papagiannis on 17/11/15.
//  Copyright (c) 2015 Anastasios Papagiannis <apapag@ics.forth.gr>.
//

#ifndef YCSB_C_NULL_DB_H_
#define YCSB_C_NULL_DB_H_

#include "core/ycsbdb.h"

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

#include <boost/algorithm/string.hpp>

#include "core/properties.h"

using std::cout;
using std::endl;

namespace ycsbc {
	class NullDB : public YCSBDB {
		private:
			int db_num;
			int field_count;
			std::string raw_key;
			std::string raw_value;
			std::vector<std::string> raw_fields;
			std::string value1;
			std::string value10;
			std::string find_value;

		public:
			NullDB(int num, utils::Properties& props) : 
										db_num(num), 
										field_count(std::stoi(props.GetProperty(CoreWorkload::FIELD_COUNT_PROPERTY, CoreWorkload::FIELD_COUNT_DEFAULT))),
										raw_key('w', 20),
										raw_value('a', 100)
			{
				
				std::cout << "fc[" << field_count << "]" << std::endl;
				for(int i = 0; i < field_count; ++i)
					raw_fields.push_back("field" + std::to_string(i));

				value1 = "field0 " + raw_value;
				
				for(auto rf : raw_fields){
					value10.append(rf);
					value10.append(1, ' ');
					value10.append(raw_value);
					value10.append(1, ' ');
				}
				value10.pop_back();

				std::cout << "value1 = [" << value1 << "]" << std::endl;
				std::cout << "value10 = [" << value10 << "]" << std::endl;

				if(field_count > 1)
					find_value = value10;
				else
					find_value = value1;
			}

			virtual ~NullDB(){}

		public:
			void Init(){}
			void Close(){}

			int __read(int id, const std::string &table, const std::string &key, const std::vector<std::string> *fields, std::vector<KVPair> &result)
			{
				return 0;
			}

			int Read(int id, const std::string &table, const std::string &key, const std::vector<std::string> *fields, std::vector<KVPair> &result)
			{
				if(fields){
					return __read(id, table, key, fields, result);
				}else{
					std::vector<std::string> __fields;
					for(int i = 0; i < field_count; ++i)
						__fields.push_back("field" + std::to_string(i));
					return __read(id, table, key, &__fields, result);
				}

				return 0;
			}

			int Scan(int id, const std::string &table, const std::string &key, int len, 
					const std::vector<std::string> *fields, 
					std::vector<KVPair> &result)
			{
				return 0;
			}

			int Update(int id, const std::string &table, const std::string &key, std::vector<KVPair> &values)
			{
				return Insert(id, table, key, values);
			}

			int Insert(int id, const std::string &table, const std::string &key, std::vector<KVPair> &values)
			{
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

#endif // YCSB_C_NULL_DB_H_


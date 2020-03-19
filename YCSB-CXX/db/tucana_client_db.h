//
//  eutropia_db.h
//  YCSB-C
//
//  Created by Anastasios Papagiannis on 17/11/15.
//  Copyright (c) 2015 Anastasios Papagiannis <apapag@ics.forth.gr>.
//

#ifndef YCSB_C_TUCANACLIENT_H_
#define YCSB_C_TUCANACLIENT_H_

#include "core/ycsbdb.h"

#include <iostream>
#include <string>
#include <mutex>
#include <algorithm>
#include <atomic>
#include <functional>

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <jni.h>

#include <boost/algorithm/string.hpp>

#include "core/properties.h"

extern "C" {
#include "../kreon/allocator/allocator.h"
#include "../kreon/btree/btree.h"
#include "../kreon/scanner/scanner.h"
#include "client_tucana_regions.h"
}

#define FIELD_COUNT 10

#define HASH 1
using std::cout;
using std::endl;

/*PILAR*/
//extern std::string prefix;  //To get the prefix for the keys to be able to have several clients
/****/



namespace ycsbc {

class TucanaClientDB : public YCSBDB {
private:
	int db_num;
	int field_count;
	std::vector<db_handle *> dbs;
	_Client_Regions *client_regions;
	double tinit, t1,t2;
	struct timeval tim;
	long long how_many = 0;
	int cu_num;
	pthread_mutex_t mutex_num;

public:
	TucanaClientDB(int num, utils::Properties& props) :
		db_num(num), field_count(std::stoi(props.GetProperty(CoreWorkload::FIELD_COUNT_PROPERTY, CoreWorkload::FIELD_COUNT_DEFAULT))), dbs()
	{
		struct timeval start;
		//cout << "TucanServer: 0...\n" << endl;
		client_regions = Allocate_Init_Client_Regions( );
		//cout << "TucanServer: 1...\n" << endl;

		cu_num = 0;
		pthread_mutex_init( &mutex_num, NULL);

		while ( client_regions->num_regions_connected < num ) 
		{

			//cout << "TucanServer: There are only " <<  client_regions->num_regions << " regions..." << endl;
			 sleep(1);
		}
		//cout << "TucanServer: More than 7 regions..." << endl;
		Client_Create_Receiving_Threads( client_regions );
		gettimeofday(&start, NULL);
		tinit=start.tv_sec+(start.tv_usec/1000000.0);
	}

	virtual ~TucanaClientDB()
	{
		cout << "Calling ~TucanaClientDB()..." << endl;
		//Client_Print_Stat_Client_Regions( client_regions );
		gettimeofday(&tim, NULL);
		t2=tim.tv_sec+(tim.tv_usec/1000000.0);
		fprintf(stderr, "ycsb=[%lf]sec\n", (t2-t1));
		fprintf(stderr, "start=[%lf]sec\n", (t1-tinit));

		#if TU_TIMING
		Clien_Print_Times_Regions( client_regions );
		#endif
		//Client_Flush_Volume( client_regions );
		Client_Flush_Volume_MultipleServers( client_regions );
		Free_Client_Regions( &client_regions );

#if 0
		int total_entries = 0;

		for(int i = 0; i < db_num; ++i){
			scannerHandle *scanner = initScanner(dbs[i], NULL);
			while(isValid(scanner)){
				total_entries++;
				std::cout << "[" << i << "][" << getKeySize(scanner) << "][" << (char *)getKeyPtr(scanner) << "]" << std::endl;
				getNextKV(scanner);
			}
			closeScanner(scanner);
		}

		std::cout << "DBs have " << total_entries << " in total." << std::endl;
#endif
	}

public:
	void Init(){}
	void Close(){}

	int Read(int id, const std::string &table, const std::string &key, const std::vector<std::string> *fields, std::vector<KVPair> &result)
	{
		if(fields){
			return __read(id, table, key, fields, result);
		}else{
			std::vector<std::string> __fields;
			for(int i = 0; i < field_count ; ++i)
				__fields.push_back("field" + std::to_string(i));
			return __read(id, table, key, &__fields, result);
		}

		return 0;
	}

	int __read(int id, const std::string &table, const std::string &key, const std::vector<std::string> *fields, std::vector<KVPair> &result)
	{
		int length = 0;
		struct tu_data_message *mr_message;
		struct tu_data_message *reply_data_message;
		_client_tucana_region *cli_tu_region;
		int mailbox;
		std::map<std::string, std::string> vmap;
		char *val;
		uint32_t len_val = 0 ;
		//std:: string key = prefix + auxkey;
		#if HASH
		std::hash<std::string> hash_fn;
		uint32_t db_id = hash_fn(key) % db_num;
//printf("DB %d\n",db_id);fflush(stdout);
		#else
		uint32_t db_id = 0;
		#endif

		#if TU_TIMING
		struct timeval start, end;
		gettimeofday(&start, NULL);
		if ( how_many == 0) 
		{
			//gettimeofday(&tim, NULL);
			t1=start.tv_sec+(start.tv_usec/1000000.0);
		}
		how_many++;
				//gettimeofday(&start, NULL);
				#else
		if ( how_many == 0)
						{
			struct timeval start;
								gettimeofday(&start, NULL);
								t1=start.tv_sec+(start.tv_usec/1000000.0);
						}
		how_many = 1;
		#endif


		cli_tu_region = Client_Get_Tu_Region_and_Mailbox( client_regions, (char *)key.c_str(), db_id, &mailbox );
		length += Client_GetSize_Key_WithLength( (uint32_t)key.length() );
//length+=1000;
//printf("Key %s Len %d\n",key.c_str(),length);fflush(stdout);
		mr_message = Client_Create_MessageGet_Key_Pairs_WithMR( length, cli_tu_region, mailbox );
		if ( ! Client_Push_Key_wl_In_Data_Message_WithMR( mr_message, (char*)key.c_str(), (uint32_t)key.length() ) )
		{
			perror("read: Client_Push_Key_In_Data_Message");
			exit(EXIT_FAILURE);
		}
		#if TU_TIMING
				gettimeofday( &end, NULL );
		Client_Update_Time_Prepare( cli_tu_region, &start, &end );
		Client_Update_Time_Application( cli_tu_region, &tim, &start );
		#endif

		reply_data_message = NULL;
		reply_data_message = Client_Send_RDMA_Message( cli_tu_region, mr_message, mailbox );
		#if !TU_FAKE_SEND
		if ( reply_data_message == NULL )
		{
			perror("read: Client_Send_RDMA_Message");
			exit(EXIT_FAILURE);
		}
		#endif
		len_val = Get_Value_and_Length_Tu_Data_Message( reply_data_message, &val ); 
//printf("Value %s Length %d\n", val, len_val); fflush(stdout);
		if ( len_val > 0 )
		{
			std::string value(val , len_val);

			std::vector<std::string> tokens;
			boost::split(tokens, value, boost::is_any_of(" "));

			int cnt = 0;
			for(std::map<std::string, std::string>::size_type i = 0 ; i + 1 < tokens.size(); i += 2){
				vmap.insert(std::pair<std::string, std::string>(tokens[i], tokens[i+1]));
				++cnt;
			}
			if(cnt != field_count){
							//printf("Val %d %s\n", len_val, val);fflush(stdout);
							//printf("VAL++ %d %s\n", value.length(), value.c_str());fflush(stdout);
			  std::cout << "ERROR IN VALUE!" << std::endl;
			  std::cout << "[" << value << "]" << std::endl;
			  //exit(EXIT_FAILURE);
			}

			for(auto f : *fields){
				std::map<std::string, std::string>::iterator it = vmap.find(f);
				if(it == vmap.end()){
				//printf("Value %d %s\n", len_val, val);fflush(stdout);
				std::cout << "[2]cannot find : " << f << " in DB " << db_id << std::endl;
				//exit(EXIT_FAILURE);
				break;
				}
				KVPair k = std::make_pair(f, it->second);
				result.push_back(k);
			}
		}
		Client_Free_Data_Message( &mr_message, cli_tu_region, mailbox );
		#if TU_TIMING
				gettimeofday( &tim, NULL );
		#endif
		return 0;
	}


	int Scan(int id, const std::string &table, const std::string &key, int len,
			const std::vector<std::string> *fields,
			std::vector<KVPair> &result)
	{
		int length = 0;
		struct tu_data_message *mr_message;
		struct tu_data_message *reply_data_message;
		_client_tucana_region *cli_tu_region;
		int mailbox;
		//std:: string key = prefix + auxkey;
		#if HASH
		std::hash<std::string> hash_fn;
		uint32_t db_id = hash_fn(key) % db_num;
//printf("DB %d L %d\n",(int)db_id,len);fflush(stdout);
		#else
		uint32_t db_id = 0;
		#endif

		#if TU_TIMING
		struct timeval start, end;
		gettimeofday(&start, NULL);
		if ( how_many == 0) 
		{
			t1=start.tv_sec+(start.tv_usec/1000000.0);
		}
		how_many++;
		#else
		if ( how_many == 0)
						{
			struct timeval start;
								gettimeofday(&start, NULL);
								t1=start.tv_sec+(start.tv_usec/1000000.0);
						}
		how_many = 1;
		#endif

		cli_tu_region = Client_Get_Tu_Region_and_Mailbox( client_regions, (char *)key.c_str(), db_id, &mailbox );
		length += Client_GetSize_Key_WithLength( (uint32_t)key.length() );
//printf("Key %s Len %d\n",key.c_str(),length);fflush(stdout);
		mr_message = Client_Create_MessageScan_Key_Pairs_WithMR( length, cli_tu_region, mailbox );
		Client_Push_Length_In_Data_Message_WithMR( mr_message, (int32_t) len );
		if ( ! Client_Push_Key_wl_In_Data_Message_WithMR( mr_message, (char*)key.c_str(), (uint32_t)key.length() ) )
		{
			perror("Scan: Client_Push_Key_In_Data_Message");
			exit(EXIT_FAILURE);
		}

		#if TU_TIMING
				gettimeofday( &end, NULL );
		Client_Update_Time_Prepare( cli_tu_region, &start, &end );
		Client_Update_Time_Application( cli_tu_region, &tim, &start );
		#endif

		reply_data_message = NULL;
		reply_data_message = Client_Send_RDMA_Message( cli_tu_region, mr_message, mailbox );
		if ( reply_data_message != NULL )
		{
			char *re_key, *re_value;
			uint32_t len_key, len_value;
			uint32_t remote=0; 	
			//printf("REPLY %d %d %p %p\n",reply_data_message->value, reply_data_message->pay_len, reply_data_message->data, reply_data_message->next); fflush(stdout);
			while ( ( len_key = Client_Get_Key_Value_WithLength_TuData_Message( reply_data_message, &len_value, &re_key, &re_value ) ) > 0 )
			{

				std::string k( (char *)re_key, len_key );
				std::string v( (char *)re_value, len_value );

				std::vector<std::string> tokens;
				boost::split(tokens, v, boost::is_any_of(" "));
				std::map<std::string, std::string> vmap;
				int cnt = 0;
				for(std::map<std::string, std::string>::size_type i = 0 ; i + 1 < tokens.size(); i += 2)
				{
					vmap.insert(std::pair<std::string, std::string>(tokens[i], tokens[i+1]));
					++cnt;
				}
				for(std::map<std::string, std::string>::iterator it = vmap.begin(); it != vmap.end(); ++it)
				{
					KVPair kv = std::make_pair(k + it->first, it->second);
					result.push_back(kv);

				}
				//printf("SKey %d %d %s V %d %s \n", remote,len_key, re_key,len_value, re_value);fflush(stdout);
				remote++;
			}
			if ( remote != reply_data_message->value )
			{
				printf("THEREISPROBLEMS %d %d\n", remote, reply_data_message->value) ;
				fflush(stdout);
			}
		}
		else {printf("REPLY NULL\n");fflush(stdout);}
		#if !TU_FAKE_SEND
		if ( reply_data_message == NULL )
		{
			perror("read: Client_Send_RDMA_Message");
			exit(EXIT_FAILURE);
		}
		#endif
		Client_Free_Data_Message( &mr_message, cli_tu_region, mailbox );
		#if TU_TIMING
				gettimeofday( &tim, NULL );
		#endif
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
#if 0
		char key_buf[512];
		int32_t tmp;
		std::hash<std::string> hash_fn;
		uint32_t db_id = hash_fn(key) % db_num;

		// A bit of cheat here.. We apply in-place updates as we are sure that 
		// all values have the same size. 
		for(auto v : values){
			std::string kk = key + v.first;

			tmp = kk.length() + 1;
			memcpy(key_buf, &tmp, sizeof(int32_t));
			memcpy(key_buf + sizeof(int32_t), kk.c_str(), kk.length());
			key_buf[sizeof(int32_t) + kk.length()] = '\0';

			char *val = (char *)findKey(dbs[db_id], key_buf); 

			//if(val == NULL){
			//	std::cout << "[UPDATE] : Cannot find key!" << std::endl;
			//	exit(EXIT_FAILURE);
			//}else if(*(int32_t *)val != v.second.size()){
			//	std::cout << "[UPDATE] : Values have different size!" << std::endl;
			//	exit(EXIT_FAILURE);
			//}else{
			memcpy((char *)val + sizeof(int32_t), v.second.c_str(), v.second.size());
			//}
		}

#endif
		return 0;
	}
	#if TU_RDMA_SINGLE_MESSAGE
	int Insert(int id, const std::string &table, const std::string &key, std::vector<KVPair> &values)
	{

		#if TU_FAKE_YCSB
		return 0;
		#endif
		int length = 0;
		int length_key = 0;
		int total_length = 0;
		struct tu_data_message *mr_message;
		struct tu_data_message *reply_data_message;
		_client_tucana_region *cli_tu_region;
		int mailbox;
		//std:: string key = prefix + auxkey;
		#if HASH
		std::hash<std::string> hash_fn;
		uint32_t db_id = hash_fn(key) % db_num;
		#if 0
		pthread_mutex_lock( &mutex_num );
		db_id = cu_num;
		cu_num++;
		cu_num %= db_num;
		pthread_mutex_unlock( &mutex_num );
		#endif
		//db_id=0;
		#else
		uint32_t db_id = 0;
		#endif

		#if TU_TIMING
		struct timeval start, end;
		gettimeofday(&start, NULL);
		if ( how_many == 0) 
		{
			t1=start.tv_sec+(start.tv_usec/1000000.0);
		}
		how_many++;
				//gettimeofday(&start, NULL);
		#else
		if ( how_many == 0)
						{
			struct timeval start;
								gettimeofday(&start, NULL);
								t1=start.tv_sec+(start.tv_usec/1000000.0);
						}
		how_many ++;
		#endif
		//printf("Put %d\n",db_id);fflush(stdout);
		//return 0;
		//printf("Insert %s\n",(char *)key.c_str() ); fflush(stdout);
		cli_tu_region = Client_Get_Tu_Region_and_Mailbox( client_regions, (char *)key.c_str(), db_id, &mailbox );
		//printf("cli_tu_region %p\n",cli_tu_region);fflush(stdout);
		#if !TU_FAKE_PAYLOAD
		length_key =  key.length();
		for(auto v : values) 
		{
			length += Client_GetSize_FieldValue_Pair_WithLength( (uint32_t)v.first.length(), (uint32_t)v.second.length() ) ;
		}
		//printf("Len %d\n",length);fflush(stdout);
		#else
		length = 1400;
		length_key = 32;
		//length = 840;
		#endif
		total_length =  length + length_key + ( sizeof(uint32_t) << 1 ) + 1;
		mr_message = Client_Create_MessagePut_KeyValue_Pairs_WithMR( total_length, cli_tu_region, mailbox );
		#if !TU_FAKE_PAYLOAD

		if ( ! Client_Push_Key_Lengths_Tu_Data_Message( mr_message, (char *)key.c_str(), length_key, length ) )
		{
			perror("Insert: Client_Push_Key_Lengths_Tu_Data_Message\n");
			exit(EXIT_FAILURE);
		}
		for(auto v : values) 
		{
			if ( ! Client_Push_Field_Value_Tu_Data_Message( mr_message, (char *)v.first.c_str(), (char *)v.second.c_str(), (uint32_t)v.first.length(), (uint32_t)v.second.length() ) )
			{
				perror("Insert: lient_Push_Field_Value_Tu_Data_Message\n");
				exit(EXIT_FAILURE);
			}
		}
		#else
		mr_message->value = 10;
		#endif
		#if TU_TIMING
		gettimeofday( &end, NULL );
		Client_Update_Time_Prepare( cli_tu_region, &start, &end );
		Client_Update_Time_Application( cli_tu_region, &tim, &start );
		#endif
//#if 0
		#if !TU_FAKE_SEND
		reply_data_message = NULL;
		reply_data_message = Client_Send_RDMA_Message( cli_tu_region, mr_message, mailbox );
		//printf("Inserted %s\n",(char *)key.c_str() ); fflush(stdout);
		#endif
		#if !TU_FAKE_SEND && !TU_FAKE_RECV
		if ( reply_data_message == NULL )
		{
			perror("Insert: Client_SendPut_Message");
			exit(EXIT_FAILURE);
		}
		#endif
//#endif

		Client_Free_Data_Message( &mr_message, cli_tu_region, mailbox );
		#if TU_TIMING
				gettimeofday( &tim, NULL );
		#endif
		//printf("FPut %d\n",db_id);fflush(stdout);
		return 0;
	}
	#else
	int Insert(int id, const std::string &table, const std::string &key, std::vector<KVPair> &values)
	{

		#if TU_FAKE_YCSB
		return 0;
		#endif
		int length = 0;
		struct tu_data_message *mr_message;
		struct tu_data_message *next_mr_message;
		struct tu_data_message *reply_data_message;
		_client_tucana_region *cli_tu_region;
		int mailbox;
		#if HASH
		std::hash<std::string> hash_fn;
		uint32_t db_id = hash_fn(key) % db_num;
		//db_id=0;
		#else
		uint32_t db_id = 0;
		#endif
		//printf("Put %d\n",db_id);fflush(stdout);
		//return 0;
		//printf("Insert\n"); fflush(stdout);
		cli_tu_region = Client_Get_Tu_Region_and_Mailbox( client_regions, (char *)key.c_str(), db_id, &mailbox );
		#if !TU_FAKE_PAYLOAD
		for(auto v : values) 
		{
			std::string kk = key + v.first;
			length += Client_GetSize_KeyValue_Pair_WithLength( (uint32_t)kk.length(), (uint32_t)v.second.length() ) ;
		}
		//printf("Len %d\n",length);fflush(stdout);
		#else
		length = 1400;
		#endif
		mr_message = Client_Create_N_Messages_Put_KeyValue_Pairs_WithMR( length, cli_tu_region, mailbox );
		#if !TU_FAKE_PAYLOAD
		next_mr_message = mr_message;
		for(auto v : values) 
		{
			std::string kk = key + v.first;
			if ( ! Client_Push_KV_wl_In_Data_N_Messages_WithMR( &next_mr_message, (char*)kk.c_str(), (char*)v.second.c_str(), (uint32_t)kk.length(), (uint32_t)v.second.length() ) )
			{
				perror("Insert: Client_Push_KV_In_Data_Message");
				exit(EXIT_FAILURE);
			}
		}
		#else
		mr_message->value = 10;
		#endif
		#if !TU_FAKE_SEND
		reply_data_message = NULL;
		reply_data_message = Client_Send_RDMA_N_Messages( cli_tu_region, mr_message, mailbox );
//printf("YCSB\n");fflush(stdout);
		#endif
		#if !TU_FAKE_SEND && !TU_FAKE_RECV
		if ( reply_data_message == NULL )
		{
			perror("Insert: Client_SendPut_Message");
			exit(EXIT_FAILURE);
		}
		#endif

		Client_Free_Data_Message( &mr_message, cli_tu_region, mailbox );
		return 0;
	}
	#endif

	int Delete(int id, const std::string &table, const std::string &key)
	{
		std::cerr << "DELETE " << table << ' ' << key << std::endl;
		std::cerr << "Delete() not implemented [" << __FILE__ << ":" << __func__ << "():" << __LINE__ << "]" << std::endl;
		exit(EXIT_FAILURE);
		return 0; 
	}
};
} // ycsbc

#endif // YCSB_C_EUTROPIA_DB_H_


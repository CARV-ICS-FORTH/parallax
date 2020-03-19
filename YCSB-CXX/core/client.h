//
//  client.h
//  YCSB-C
//
//  Created by Jinglei Ren on 12/10/14.
//  Copyright (c) 2014 Jinglei Ren <jinglei@ren.systems>.
//

#ifndef YCSB_C_CLIENT_H_
#define YCSB_C_CLIENT_H_

#include <string>

#include <time.h>
#include <sys/time.h>

#include "ycsbdb.h"
#include "core_workload.h"
#include "utils.h"

void timespec_diff(struct timespec *start, struct timespec *stop, struct timespec *result)
{
	if ((stop->tv_nsec - start->tv_nsec) < 0) {
		result->tv_sec = stop->tv_sec - start->tv_sec - 1;
		result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
	} else {
		result->tv_sec = stop->tv_sec - start->tv_sec;
		result->tv_nsec = stop->tv_nsec - start->tv_nsec;
	}

	return;
}

namespace ycsbc {
	class Client {
		public:
			Client(YCSBDB &db, CoreWorkload &wl) : db_(db), workload_(wl), id_(0) { }
			Client(YCSBDB &db, CoreWorkload &wl, int id) : db_(db), workload_(wl), id_(id) { }

			virtual bool DoInsert(uint64_t *us);
			virtual bool DoTransaction(uint64_t *us, int *op);

			virtual ~Client() { }

		public:  
			virtual int TransactionRead();
			virtual int TransactionReadModifyWrite();
			virtual int TransactionScan();
			virtual int TransactionUpdate();
			virtual int TransactionInsert();

		protected:
			YCSBDB &db_;
			CoreWorkload &workload_;
			int id_;
	};

	inline bool Client::DoInsert(uint64_t *us) 
	{
		std::string key = workload_.NextSequenceKey();
		std::vector<YCSBDB::KVPair> pairs;
		workload_.BuildValues(pairs);

		struct timespec beg_ts, end_ts, diff;
		clock_gettime(CLOCK_MONOTONIC, &beg_ts);

		bool retval = (db_.Insert(id_, workload_.NextTable(), key, pairs) == YCSBDB::kOK);

		clock_gettime(CLOCK_MONOTONIC, &end_ts);
		timespec_diff(&beg_ts, &end_ts, &diff);
		if(us != NULL)
			*us = (diff.tv_sec * 1000000) + (diff.tv_nsec / 1000);

		return retval;
	}

	inline bool Client::DoTransaction(uint64_t *us, int *op)
	{
		int status = -1;
	
		struct timespec beg_ts, end_ts, diff;
		clock_gettime(CLOCK_MONOTONIC, &beg_ts);

		switch(workload_.NextOperation()){
			case READ:
				status = TransactionRead();
				if(op != NULL){ *op = 0; }
				break;
			case UPDATE:
				status = TransactionUpdate();
				if(op != NULL){ *op = 1; }
				break;
			case INSERT:
				status = TransactionInsert();
				if(op != NULL){ *op = 2; }
				break;
			case SCAN:
				status = TransactionScan();
				if(op != NULL){ *op = 3; }
				break;
			case READMODIFYWRITE:
				status = TransactionReadModifyWrite();
				if(op != NULL){ *op = 4; }
				break;
			default:
				throw utils::Exception("Operation request is not recognized!");
		}
		
		clock_gettime(CLOCK_MONOTONIC, &end_ts);
		timespec_diff(&beg_ts, &end_ts, &diff);
		if(us != NULL)
			*us = (diff.tv_sec * 1000000) + (diff.tv_nsec / 1000);

		assert(status >= 0);
		return (status == YCSBDB::kOK);
	}

	inline int Client::TransactionRead() {
		const std::string &table = workload_.NextTable();
		const std::string &key = workload_.NextTransactionKey();
		std::vector<YCSBDB::KVPair> result;
		if (!workload_.read_all_fields()) {
			std::vector<std::string> fields;
			//			fields.push_back("field" + workload_.NextFieldName());
			fields.push_back(workload_.NextFieldName());
			return db_.Read(id_, table, key, &fields, result);
		} else {
			return db_.Read(id_, table, key, NULL, result);
		}
	}

	inline int Client::TransactionReadModifyWrite() {
		const std::string &table = workload_.NextTable();
		const std::string &key = workload_.NextTransactionKey();
		std::vector<YCSBDB::KVPair> result;

		if (!workload_.read_all_fields()) {
			std::vector<std::string> fields;
			//			fields.push_back("field" + workload_.NextFieldName());
			fields.push_back(workload_.NextFieldName());
			db_.Read(id_, table, key, &fields, result);
		} else {
			db_.Read(id_, table, key, NULL, result);
		}

		std::vector<YCSBDB::KVPair> values;
		if (workload_.write_all_fields()) {
			workload_.BuildValues(values);
		} else {
			workload_.BuildUpdate(values);
		}
		return db_.Update(id_, table, key, values);
	}

	inline int Client::TransactionScan()
	{
		const std::string &table = workload_.NextTable();
		const std::string &key = workload_.NextTransactionKey();
		int len = workload_.NextScanLength();
		std::vector<YCSBDB::KVPair> result(len);

		if (!workload_.read_all_fields()) {
			std::vector<std::string> fields;
			fields.push_back(workload_.NextFieldName());
			return db_.Scan(id_, table, key, len, &fields, result);
		} else {
			return db_.Scan(id_, table, key, len, NULL, result);
		}
	}

	inline int Client::TransactionUpdate() {
		const std::string &table = workload_.NextTable();
		const std::string &key = workload_.NextTransactionKey();
		std::vector<YCSBDB::KVPair> values;
		if (workload_.write_all_fields()) {
			workload_.BuildValues(values);
		} else {
			workload_.BuildUpdate(values);
		}
		return db_.Update(id_, table, key, values);
	}

	inline int Client::TransactionInsert() 
	{
		const std::string &table = workload_.NextTable();
#ifdef NEW_GENERATORS
		uint64_t keynum = workload_.transaction_insert_key_sequence_->nextValue();
		const std::string &key = workload_.BuildKeyName(keynum); 
#else
		const std::string &key = workload_.NextSequenceKey();
#endif
		std::vector<YCSBDB::KVPair> values;
		workload_.BuildValues(values);
		int ret = db_.Insert(id_, table, key, values);
#ifdef NEW_GENERATORS
		workload_.transaction_insert_key_sequence_->acknowledge(keynum);
#endif
		return ret;
	} 

} // ycsbc

#endif // YCSB_C_CLIENT_H_

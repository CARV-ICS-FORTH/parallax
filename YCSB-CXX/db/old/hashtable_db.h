//
//  hashtable_db.h
//  YCSB-C
//
//  Created by Jinglei Ren on 12/24/14.
//  Copyright (c) 2014 Jinglei Ren <jinglei@ren.systems>.
//

#ifndef YCSB_C_HASHTABLE_DB_H_
#define YCSB_C_HASHTABLE_DB_H_

#include "core/ycsbdb.h"

#include <string>
#include <vector>
#include "lib/string_hashtable.h"

namespace ycsbc {

class HashtableDB : public YCSBDB {
 public:
  typedef vmp::StringHashtable<const char *> FieldHashtable;
  typedef vmp::StringHashtable<FieldHashtable *> KeyHashtable;

  int Read(int id, const std::string &table, const std::string &key,
           const std::vector<std::string> *fields,
           std::vector<KVPair> &result);
  int Scan(int id, const std::string &table, const std::string &key,
           int len, const std::vector<std::string> *fields,
           std::vector<std::vector<KVPair>> &result);
  int Update(int id, const std::string &table, const std::string &key,
             std::vector<KVPair> &values);
  int Insert(int id, const std::string &table, const std::string &key,
             std::vector<KVPair> &values);
  int Delete(int id, const std::string &table, const std::string &key);

 protected:
  HashtableDB(KeyHashtable *table) : key_table_(table) { }

  virtual FieldHashtable *NewFieldHashtable() = 0;
  virtual void DeleteFieldHashtable(FieldHashtable *table) = 0;

  virtual const char *CopyString(const std::string &str) = 0;
  virtual void DeleteString(const char *str) = 0;

  KeyHashtable *key_table_;
};

} // ycsbc

#endif // YCSB_C_HASHTABLE_DB_H_

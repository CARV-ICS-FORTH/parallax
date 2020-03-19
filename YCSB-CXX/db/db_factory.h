//
//  db.h
//  YCSB-C
//
//  Created by Jinglei Ren on 12/18/14.
//  Copyright (c) 2014 Jinglei Ren <jinglei@ren.systems>.
//

#ifndef YCSB_C_DB_FACTORY_H_
#define YCSB_C_DB_FACTORY_H_

#include "ycsbdb.h"
#include "utils.h"
#include "core_workload.h"

namespace ycsbc {

class DBFactory
{
 public:
 	///
	/// @num works only for levelDB (and Eutropia in the future). 
	///	It specifies the number of distinct databases.
	///
  static YCSBDB* CreateDB(int num, utils::Properties& props);
};

} // ycsbc

#endif // YCSB_C_DB_FACTORY_H_


//
//  basic_db.cc
//  YCSB-C
//
//  Created by Jinglei Ren on 12/17/14.
//  Copyright (c) 2014 Jinglei Ren <jinglei@ren.systems>.
//

#include "db_factory.h"

#include "kreonR_async_client.h"

using ycsbc::DBFactory;
using ycsbc::YCSBDB;

YCSBDB *DBFactory::CreateDB(int num, utils::Properties &props)
{
	return new kreonRAsyncClientDB(num, props);
}

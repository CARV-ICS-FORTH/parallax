//
//  basic_db.cc
//  YCSB-C
//
//  Created by Jinglei Ren on 12/17/14.
//  Copyright (c) 2014 Jinglei Ren <jinglei@ren.systems>.
//

#include "db/db_factory.h"

#include "db/percona_ft.h"

using ycsbc::YCSBDB;
using ycsbc::DBFactory;

YCSBDB* DBFactory::CreateDB(int num)
{
  return new PerconaFT(num);
}


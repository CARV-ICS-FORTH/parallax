//
//  basic_db.cc
//  YCSB-C
//
//  Created by Jinglei Ren on 12/17/14.
//  Copyright (c) 2014 Jinglei Ren <jinglei@ren.systems>.
//

#include "db/db_factory.h"

#if 0
#include "db/basic_db.h"
#include "db/lock_stl_db.h"
#include "db/tbb_rand_db.h"
#include "db/tbb_scan_db.h"
#endif

#include "db/level_db.h"
#include "db/eutropia_db.h"
#include "db/kyoto_db.h"
//#include "db/berkeley_db.h"
#include "db/percona_ft.h"
#include "db/rocks_db.h"

using ycsbc::YCSBDB;
using ycsbc::DBFactory;

YCSBDB* DBFactory::CreateDB(const std::string name, int num)
{
#if 0
  if (name == "basic") {
    return new BasicDB;
  } else if (name == "lock_stl") {
    return new LockStlDB;
  } else if (name == "tbb_rand") {
    return new TbbRandDB;
  } else if (name == "tbb_scan") {
    return new TbbScanDB;
  } else
#endif
	if(name == "leveldb")
    return new LevelDB(num);
//  else if(name == "berkeleydb")
//    return new BerkeleyDB(num);
  else if(name == "perconaft")
    return new PerconaFT(num);
  else if(name == "rocksdb")
    return new RocksDB(num);
  else if(name == "kyotodb")
    return new KyotoDB(num);
  else if(name == "eutropiadb")
    return new EutropiaDB(num);
  else
		return NULL;
}


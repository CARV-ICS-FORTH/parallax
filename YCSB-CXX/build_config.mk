# -I/root/db-6.1.26.NC/build_unix
# /root/db-6.1.26.NC/build_unix/libdb_cxx.a
# -std=c++0x -D_REENTRANT -O2 -Wall -pthread  -lz -ldl -I./

CC=/usr/bin/g++



#CFLAGS=-std=c++0x -O2 -Wall -DCOMPUTE_TAIL
CFLAGS=-std=c++0x -O2 -Wall -g -ggdb3
LDFLAGS=-lpthread -ldl -lz -lrt


BDB_INC=/root/db-6.1.26.NC/build_unix
BDB_LIB=/root/db-6.1.26.NC/build_unix/libdb_cxx.a

EDB_INC=/home1/private/gesalous/carvgit/HEutropia/kreon
EDB_LIB=/home1/private/gesalous/carvgit/HEutropia/kreon/libtucana2.a

LDB_INC=/root/leveldb-1.18/include
LDB_LIB=/root/leveldb-1.18/libleveldb.a

KDB_INC=/root/kyotocabinet-1.2.76
KDB_LIB=/root/kyotocabinet-1.2.76/libkyotocabinet.a

PFT_INC=/root/percona-ft/prefix/include
PFT_LIB=/root/percona-ft/prefix/lib/libtokufractaltree_static.a /root/percona-ft/prefix/lib/libtokuportability_static.a /root/percona-ft/prefix/lib/libftcxx.a

#RDB_INC=/home1/public/gxanth/rocksdb-5.6.1/include
#RDB_LIB=/home1/public/gxanth/rocksdb-5.6.1/librocksdb.a

TUCDB_FLAGS=/home1/private/gesalous/zookeeper-3.4.10/src/c/include/  -I/home1/private/gesalous/zookeeper-3.4.10/src/c/generated/ -I $(JAVA_HOME)/include -I $(JAVA_HOME)/include/linux
TUCDB_INC=/home1/private/gesalous/carvgit/HEutropia/TucanaServer
TUCDB_LIB=/home1/private/gesalous/carvgit/HEutropia/TucanaServer/libTucanaClient.a
MAILLIB=/home1/private/gesalous/carvgit/HEutropia/network/libmb.a
RDMALIB=/home1/private/gesalous/carvgit/HEutropia/TuRDMA/libturdma.a
TUCDB_LIBS=-lpthread -lm  -lzookeeper_mt -lrdmacm -libverbs   -D_GNU_SOURCE
TUCDB_LFLAGS=-lpthread -lm -lzookeeper_mt -lrdmacm -libverbs -D_GNU_SOURCE


#INCLUDES=-I../ -I/root/tbb44_20150728oss/include 
#LDFLAGS=-Wl,-rpath,/root/tbb44_20150728oss/build/linux_intel64_gcc_cc4.4.7_libc2.12_kernel3.12.43_release -L/root/tbb44_20150728oss/build/linux_intel64_gcc_cc4.4.7_libc2.12_kernel3.12.43_release/ -lpthread -ltbb

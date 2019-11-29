STATIC_LIB=../libtucana2.a
INC=-I..
CFLAGS=-std=c++1y -g -ggdb3 -O3
MISC =-std=c++1y -O3
default: all

all: updates inserts deletes scan find misc

updates: updates.cc
	g++ ${CFLAGS} ${INC} -o updates updates.cc ${STATIC_LIB} -lrt -pthread -lm

inserts: inserts.cc
	g++ ${CFLAGS} ${INC} -o inserts inserts.cc ${STATIC_LIB} -lrt -pthread -lm

deletes: deletes.cc
	g++ ${CFLAGS} ${INC} -o deletes deletes.cc ${STATIC_LIB} -lrt -pthread -lm

scan: scan.cc
	g++ ${CFLAGS} ${INC} -o scan scan.cc ${STATIC_LIB} -lrt -pthread -lm

find: find.cc
	g++ ${CFLAGS} ${INC} -o find find.cc ${STATIC_LIB} -lrt -pthread -lm

misc:
	g++ ${MISC} -o createfindkeys createfindkeys.c

clean:
	rm -f updates inserts deletes scan find insert.txt *.txt

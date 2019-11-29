CC=gcc
UTHASH=uthash-master
LOGGING=log
LIBS=-pthread

FLAGS=-O3 -std=gnu11  -fPIC -Wfatal-errors #-Werror
#-DNEW_LEAF_LAYOUT

#DEBUG=-g -ggdb3 -fbuiltin
DEBUG=-DNDEBUG

default: tucana2

all: default

dependencies:
	if [ ! -d "./$(UTHASH)" ];then 	\
		git clone https://github.com/troydhanson/uthash.git uthash-master; 	\
	fi

	if [ ! -d "./$(LOGGING)" ];then	\
		git clone https://github.com/rxi/log.c.git log; 	\
	fi

tucana2: dependencies
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) allocator/list.c -fPIC -o allocator/list.o
	$(CC) $(DEBUG) -Wall  -c  -O0 allocator/spin_loop.c -fPIC -o allocator/spin_loop.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) allocator/allocator.c -fPIC -o allocator/allocator.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) allocator/recovery.c -fPIC -o allocator/recovery.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) btree/btree.c -fPIC -o btree/btree.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) btree/gc.c -fPIC -o btree/gc.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) btree/locks.c -fPIC -o btree/locks.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) btree/delete.c -fPIC -o btree/delete.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) btree/replica.c -fPIC -o btree/replica.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) scanner/stack.c -fPIC -o scanner/stack.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) scanner/min_max_heap.c -fPIC -o scanner/min_max_heap.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) scanner/scanner.c -fPIC -o scanner/scanner.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) -DLOG_USE_COLOR log/src/log.c -fPIC -o log/log.o
	$(CC) $(DEBUG) -Wl,--no-as-needed allocator/list.o allocator/spin_loop.o allocator/recovery.o allocator/allocator.o btree/delete.o btree/btree.o btree/gc.o btree/locks.o  btree/replica.o log/log.o scanner/stack.o scanner/min_max_heap.o scanner/scanner.o -shared  -o libtucana2.so $(LIBS)
	ar rcs libtucana2.a allocator/list.o allocator/recovery.o allocator/spin_loop.o allocator/allocator.o btree/delete.o btree/btree.o btree/gc.o btree/locks.o btree/replica.o scanner/stack.o scanner/min_max_heap.o scanner/scanner.o log/log.o
	$(CC)  $(FLAGS) -o mkfs.eutropia allocator/mkfs_Eutropia.c btree/locks.o allocator/spin_loop.o allocator/allocator.c allocator/list.c -lrt -lm -pthread

install:tucana2
	cp libtucana2.a libtucana2.so /usr/local/lib/
	make clean
	cd ..;cp -r kreon /usr/local/include/
	sudo ln -s /usr/local/lib/libtucana2.a /usr/lib/libtucana2.a
	sudo ln -s /usr/local/lib/libtucana2.so /usr/lib/libtucana2.so


clean:
	rm -f allocator/*.o
	rm -f scanner/*.o
	rm -f btree/*.o
	rm -f libtucana2.a
	rm -f libtucana2.so
	rm -f mkfs.eutropia
	rm -f log/*.o

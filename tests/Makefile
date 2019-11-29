FAKE_BLK_HEADER=/home/gesalous/carvgit/HEutropia
CC=gcc
FLAGS=-O3 -DSTANDALONE   -I  $(FAKE_BLK_HEADER)/fake_blk/include/ 
DEBUG=-g

FAKE_BLK_HEADER=/home1/public/gxanth/HEutropia



LIBS=-lpthread -lm
readersondirtytree:
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) ../allocator/list.c -fPIC -o list.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) ../allocator/allocator.c -fPIC -o allocator.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) ../btree/btree.c -fPIC -o btree.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) ../scanner/stack.c -fPIC -o stack.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) ../scanner/scanner.c -fPIC -o scanner.o
	$(CC) $(DEBUG) -Wall -c   $(FLAGS) $(LIBS) lookup3.c -fPIC -o lookup3.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) readersondirty.c -fPIC -o readersondirty.o
	$(CC) -Wall   $(FLAGS) -o readerstest list.o allocator.o  btree.o stack.o lookup3.o scanner.o  readersondirty.o  $(LIBS)

default: clean readersondirtytree

coverage: clean flags test1

flags:
FLAGS=-fprofile-arcs -ftest-coverage -O0 -DSTANDALONE -Wfatal-errors  -I  $(FAKE_BLK_HEADER)/fake_blk/include/


test1:
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) ../allocator/list.c -fPIC -o list.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) ../allocator/allocator.c -fPIC -o allocator.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) ../btree/btree.c -fPIC -o btree.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) ../scanner/stack.c -fPIC -o stack.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) ../scanner/scanner.c -fPIC -o scanner.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS)  lookup3.c -fPIC -o lookup3.o
	$(CC) $(DEBUG) -Wall  -c  $(FLAGS) $(LIBS) test1.c -fPIC -o test1.o
	$(CC) -Wall   $(FLAGS) -o test1 list.o  allocator.o btree.o stack.o scanner.o lookup3.o test1.o  $(LIBS)


clean:
	rm -f *.o
	rm -f *.gcna
	rm -f *.gcda
	rm -f *.gcno
	rm -f test1
	rm -f readerstest





























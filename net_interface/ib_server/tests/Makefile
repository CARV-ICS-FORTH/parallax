CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -libverbs -lrdmacm -lpthread

all: ib_simple_test

ib_simple_test: ib_simple_test.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f ib_simple_test

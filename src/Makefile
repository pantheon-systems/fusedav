CC=gcc
CFLAGS=-g -Wall -pipe -O0 -I/usr/include/neon
LIBS=/usr/lib/libfuse.a -lpthread -lneon

all: fusexmp fusedav

fusexmp: fusexmp.o
	$(CC) -o $@ $^ $(LIBS)

fusedav: fusedav.o statcache.o filecache.o session.o openssl-thread.o
	$(CC) -o $@ $^ $(LIBS)

clean:
	rm -f *.o fusexmp fusedav

.PHONY: clean all

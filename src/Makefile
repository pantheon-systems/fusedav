CC=gcc
CFLAGS=-g -Wall -pipe -O0 -I/usr/include/neon -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -ansi
LIBS=/usr/lib/libfuse.a -lpthread -lneon

all: fusedav

fusedav: fusedav.o statcache.o filecache.o session.o openssl-thread.o
	$(CC) -o $@ $^ $(LIBS)

clean:
	rm -f *.o fusedav

.PHONY: clean all

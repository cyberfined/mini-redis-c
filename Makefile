CC=gcc
CFLAGS=-std=c11 -Wall -D_POSIX_C_SOURCE=200809L -O0 -g
LDFLAGS=-O0 -g

FLOAT_ENDIANESS=$(shell ./float_endianess_test.sh $(CC))
CFLAGS+=$(FLOAT_ENDIANESS)

.PHONY: all clean
all: server client
server: server.o hashtable.o event.o zset.o object.o util.o
	$(CC) $(LDFLAGS) server.o event.o hashtable.o zset.o object.o util.o -o server
client: client.o util.o
	$(CC) $(LDFLAGS) client.o util.o -o client
event.o: event.c event_epoll.c event_kqueue.c
	$(CC) $(CFLAGS) -c event.c -o event.o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -f server client hashtable.o server.o event.o client.o zset.o object.o \
		util.o float_endianess_test

CC=gcc
CFLAGS=-std=c11 -Wall -D_POSIX_C_SOURCE=200809L -O0 -g
LDFLAGS=-O0 -g
.PHONY: all clean
all: server client
server: server.o hashtable.o event.o
	$(CC) $(LDFLAGS) server.o event.o hashtable.o -o server
client: client.o
	$(CC) $(LDFLAGS) client.o -o client
event.o: event.c event_epoll.c event_kqueue.c
	$(CC) $(CFLAGS) -c event.c -o event.o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -f $(OBJ) server client hashtable.o server.o event.o client.o

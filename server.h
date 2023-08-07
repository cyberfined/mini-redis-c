#pragma once

#define MAX_CLIENTS        1024
#define RESERVED_FDS       256
#define PORT               5000
#define INIT_KEYS_CAPACITY 2048
#define MAX_ACCEPTS        20

#include <stdint.h>
#include <stdbool.h>
#include "config.h"
#include "proto.h"
#include "event.h"
#include "hashtable.h"

typedef struct {
    int      fd;
    size_t   rbuf_offset, cmd_len, rbuf_size;
    uint32_t read_strings;
    uint8_t  *rbuf;
    uint8_t  *wbuf;
    size_t   wbuf_offset, wbuf_size;
    bool     is_array_response;
    size_t   array_response_offset;
    bool     should_close;
} Conn;

typedef struct {
    size_t    max_clients;
    uint16_t  port;
    EventLoop *event_loop;
    int       accept_sock;
    Conn      *current_client;
    Conn      *connections;
    HashTable *keys;
    HashTable *commands;
} State;

extern State state;

typedef void (*command_handler)(void);

typedef struct {
    unsigned int    arity;
    command_handler handler;
} Command;

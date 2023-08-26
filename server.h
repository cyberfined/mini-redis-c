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
#include "object.h"

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
    unsigned int    min_args;
    unsigned int    max_args;
    command_handler handler;
} Command;

typedef struct {
    char     *saveptr;
    char     bak;
    uint32_t num_strings;
} CmdArgState;

#define INIT_CMD_ARG_STATE {NULL, 0, 0}

char* next_cmd_arg(CmdArgState *arg_state);
void cmd_restore(CmdArgState *arg_state);

bool send_nil(void);
bool send_str(const char *msg, uint32_t msg_len);
bool send_int(int32_t val);
bool send_double(double val);
bool send_err(ErrorCode code);
bool send_arr(void);
void end_arr(uint32_t size);

// key-value commands
void get_handler(void);
void set_handler(void);
void del_handler(void);
void keys_handler(void);

// zset commands
void zadd_handler(void);
void zrange_handler(void);
void zrem(void);

#pragma once

#define MAX_CLIENTS        1024
#define RESERVED_FDS       256
#define PORT               5000
#define INIT_KEYS_CAPACITY 2048
#define INIT_TTL_CAPACITY  2048
#define MAX_ACCEPTS        20

#include <stdint.h>
#include <stdbool.h>
#include "config.h"
#include "proto.h"
#include "event.h"
#include "hashtable.h"
#include "object.h"
#include "zset.h"
#include "hashtable.h"
#include "bheap.h"

typedef struct {
    int      fd;
    size_t   rbuf_offset, cmd_len, rbuf_size;
    uint32_t read_tokens;
    uint8_t  *rbuf;
    uint8_t  *wbuf;
    size_t   wbuf_offset, wbuf_size;
    bool     is_array_response;
    size_t   array_response_offset;
    bool     should_close;
} Conn;

typedef uint64_t mstime;

typedef struct {
    size_t    max_clients;
    uint16_t  port;
    EventLoop *event_loop;
    int       accept_sock;
    Conn      *current_client;
    Conn      *connections;
    HashTable *keys;
    HashTable *commands;
    BHeap     *ttl_heap;
    mstime    cmd_start_time;
} State;

extern State state;

typedef void (*command_handler)(void);

typedef struct {
    unsigned int    min_args;
    unsigned int    max_args;
    command_handler handler;
} Command;

typedef enum {
    ARG_INT,
    ARG_DOUBLE,
    ARG_STRING
} ArgType;

typedef struct {
    ArgType type;
    union {
        uint32_t int_arg;
        double   double_arg;
        char     *str_arg;
    };
} Arg;

typedef struct {
    uint8_t  *saveptr;
    uint8_t  bak;
    uint32_t num_tokens;
} CmdArgState;

#define INIT_CMD_ARG_STATE {NULL, 0, 0}

bool next_cmd_arg(CmdArgState *arg_state, Arg *arg);
bool next_int_arg(CmdArgState *arg_state, uint32_t *arg);
bool next_double_arg(CmdArgState *arg_state, double *arg);
bool next_string_arg(CmdArgState *arg_state, char **arg);
void cmd_restore(CmdArgState *arg_state);

bool send_nil(void);
bool send_str(const char *msg, uint32_t msg_len);
bool send_int(int32_t val);
bool send_uint(uint32_t val);
bool send_double(double val);
bool send_err(ErrorCode code);
bool send_arr(void);
void end_arr(uint32_t size);

HashTableNode* lookup_key(HashTable *htable, const char *key);
bool get_string_by_key(HashTable *htable, const char *key, char **string);
bool get_zset_by_key(HashTable *htable, const char *key, ZSet **zset);

// key-value commands
void get_handler(void);
void set_handler(void);
void del_handler(void);
void keys_handler(void);

// zset commands
void zadd_handler(void);
void zrange_handler(void);
void zrem_handler(void);
void zcard_handler(void);
void zscore_handler(void);

// ttl commands
void expire_handler(void);
void ttl_handler(void);
void persist_handler(void);

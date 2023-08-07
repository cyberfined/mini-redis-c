#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "server.h"
#include "hashtable.h"

#define RBUF_SIZE              MAX_COMMAND_LEN + 1
#define WBUF_SIZE              MAX_RESPONSE_LEN + MAX_ERROR_LEN + 1
#define NUM_SUPPORTED_COMMANDS sizeof(commands) / sizeof(*commands)

// errors
#define ERROR_LEN(e)                sizeof(e) - 1
#define RESPONSE_IS_TOO_LONG_ERROR "response is too long"
#define COMMAND_IS_TOO_LONG_ERROR  "command is too long"
#define ZERO_SEGMENT_ERROR         "command contains zero length segment"
#define UNDEFINED_COMMAND_ERROR    "undefined command"
#define OUT_OF_MEMORY_ERROR        "out of memory"

State state;

static void get_handler(void);
static void set_handler(void);
static void del_handler(void);
static void keys_handler(void);

struct {
    char    *name;
    Command command;
} commands[] = {
    { "GET",  { 1, get_handler } },
    { "SET",  { 2, set_handler } },
    { "DEL",  { 1, del_handler } },
    { "KEYS", { 0, keys_handler } },
};

typedef enum {
    CommandPartiallyRead,
    CommandIsTooLong,
    ZeroSegment,
    CommandReadSuccess
} PrepareResult;

typedef enum {
    UndefinedCommand,
    OutOfMemory
} ServerError;

static inline PrepareResult prepare_command(size_t *_next_cmd_len) {
    Conn *conn = state.current_client;

    if(conn->rbuf_size < 2 * SIZE_SEGMENT_LEN) {
        *_next_cmd_len = 2 * SIZE_SEGMENT_LEN + 1;
        return CommandPartiallyRead;
    }

    uint32_t num_strings;
    memcpy(&num_strings, &conn->rbuf[conn->rbuf_offset], SIZE_SEGMENT_LEN);
    if(conn->cmd_len == 0) {
        num_strings = ntohl(num_strings);
        memcpy(&conn->rbuf[conn->rbuf_offset], &num_strings, SIZE_SEGMENT_LEN);
        conn->cmd_len = SIZE_SEGMENT_LEN;
        conn->read_strings = 0;
    }

    if(num_strings == 0)
        return ZeroSegment;

    while(conn->cmd_len < conn->rbuf_size && conn->read_strings < num_strings) {
        size_t cur = conn->rbuf_offset + conn->cmd_len;
        uint32_t str_len;
        memcpy(&str_len, &conn->rbuf[cur], SIZE_SEGMENT_LEN);
        str_len = ntohl(str_len);
        if(str_len == 0)
            return ZeroSegment;

        size_t segment_len = str_len + SIZE_SEGMENT_LEN;
        size_t next_cmd_len = conn->cmd_len + segment_len;
        if(next_cmd_len > MAX_COMMAND_LEN) {
            return CommandIsTooLong;
        } else if(next_cmd_len > conn->rbuf_size) {
            *_next_cmd_len = next_cmd_len;
            return CommandPartiallyRead;
        }
        memcpy(&conn->rbuf[cur], &str_len, SIZE_SEGMENT_LEN);
        conn->cmd_len = next_cmd_len;
        conn->read_strings++;
    }

    if(conn->read_strings != num_strings) {
        size_t next_cmd_len = conn->cmd_len + SIZE_SEGMENT_LEN + 1;
        if(next_cmd_len > MAX_COMMAND_LEN)
            return CommandIsTooLong;

        *_next_cmd_len = next_cmd_len;
        return CommandPartiallyRead;
    }

    return CommandReadSuccess;
}

static inline void close_connection(void) {
    close(state.current_client->fd);
}

static inline bool current_client_to_write(void) {
    Conn *conn = state.current_client;

    conn->wbuf_offset = 0;
    conn->wbuf_size = 0;
    bool result = set_event_mask(state.event_loop, conn->fd, EVENT_WRITE, true);
    if(!result)
        close_connection();
    return result;
}

static inline bool current_client_to_read(void) {
    Conn *conn = state.current_client;
    bool result = set_event_mask(state.event_loop, conn->fd, EVENT_READ, true);
    if(!result)
        close_connection();
    return result;
}

static inline bool check_response_size_or_send_error(uint32_t response_len) {
    Conn *conn = state.current_client;
    if(MAX_RESPONSE_LEN - conn->wbuf_size < response_len) {
        if(conn->is_array_response) {
            conn->wbuf_size = conn->array_response_offset;
            conn->is_array_response = false;
        }

        char *buf = (char*)&conn->wbuf[conn->wbuf_size];
        char *response = RESPONSE_IS_TOO_LONG_ERROR;
        response_len = ERROR_LEN(RESPONSE_IS_TOO_LONG_ERROR);
        conn->wbuf_size += RESPONSE_TYPE_LEN + SIZE_SEGMENT_LEN + response_len;

        uint32_t type = htonl(RES_ERR);
        memcpy(buf, &type, RESPONSE_TYPE_LEN);
        memcpy(&buf[RESPONSE_TYPE_LEN + SIZE_SEGMENT_LEN], response, response_len);
        response_len = htonl(response_len);
        memcpy(&buf[SIZE_SEGMENT_LEN], &response_len, SIZE_SEGMENT_LEN);

        conn->should_close = true;
        return false;
    }
    return true;
}

static inline bool send_nil(void) {
    if(!check_response_size_or_send_error(RESPONSE_TYPE_LEN))
        return false;

    uint32_t type = htonl(RES_NIL);
    Conn *conn = state.current_client;
    memcpy(&conn->wbuf[conn->wbuf_size], &type, RESPONSE_TYPE_LEN);
    conn->wbuf_size += RESPONSE_TYPE_LEN;
    return true;
}

static inline bool generic_send_str(uint32_t type, const char *msg, uint32_t msg_len) {
    uint32_t response_size = RESPONSE_TYPE_LEN + SIZE_SEGMENT_LEN + msg_len;
    if(!check_response_size_or_send_error(response_size))
        return false;

    Conn *conn = state.current_client;
    char *buf = (char*)&conn->wbuf[conn->wbuf_size];
    type = htonl(type);
    memcpy(buf, &type, RESPONSE_TYPE_LEN);
    memcpy(&buf[RESPONSE_TYPE_LEN + SIZE_SEGMENT_LEN], msg, msg_len);
    msg_len = htonl(msg_len);
    memcpy(&buf[RESPONSE_TYPE_LEN], &msg_len, SIZE_SEGMENT_LEN);
    conn->wbuf_size += response_size;
    return true;
}

static inline bool send_err(char *msg, uint32_t msg_len) {
    return generic_send_str(RES_ERR, msg, msg_len);
}

static inline bool send_str(char *msg, uint32_t msg_len) {
    return generic_send_str(RES_STR, msg, msg_len);
}

static inline bool generic_send_int(uint32_t type, uint32_t val) {
    uint32_t response_size = RESPONSE_TYPE_LEN + INT_LEN;
    if(!check_response_size_or_send_error(response_size))
        return false;

    Conn *conn = state.current_client;
    char *buf = (char*)&conn->wbuf[conn->wbuf_size];
    type = htonl(type);
    val = htonl(val);
    memcpy(buf, &type, RESPONSE_TYPE_LEN);
    memcpy(&buf[RESPONSE_TYPE_LEN], &val, INT_LEN);
    conn->wbuf_size += response_size;
    return true;
}

static inline bool send_int(int32_t val) {
    return generic_send_int(RES_INT, val);
}

static inline bool send_arr(uint32_t size) {
    Conn *conn = state.current_client;
    size_t array_response_offset = conn->wbuf_size;
    bool result = generic_send_int(RES_ARR, size);
    if(result) {
        conn->is_array_response = true;
        conn->array_response_offset = array_response_offset;
    }
    return result;
}

static inline void end_arr(void) {
    Conn *conn = state.current_client;
    conn->is_array_response = false;
}

 __attribute__ ((format (printf, 1, 2)))
static inline void send_format_error(char *restrict fmt, ...) {
    Conn *conn = state.current_client;
    char *buf = (char*)&conn->wbuf[conn->wbuf_size];

    va_list ap;
    size_t wbuf_remain = MAX_RESPONSE_LEN - conn->wbuf_size -
                         RESPONSE_TYPE_LEN - SIZE_SEGMENT_LEN;
    va_start(ap, fmt);
    int write_bytes = vsnprintf(
        &buf[RESPONSE_TYPE_LEN + SIZE_SEGMENT_LEN],
        wbuf_remain,
        fmt,
        ap
    );
    va_end(ap);
    size_t response_len;

    if(write_bytes > wbuf_remain) {
        response_len = ERROR_LEN(RESPONSE_IS_TOO_LONG_ERROR);
        memcpy(
            &buf[RESPONSE_TYPE_LEN + SIZE_SEGMENT_LEN],
            RESPONSE_IS_TOO_LONG_ERROR,
            response_len
        );
        conn->should_close = true;
    } else {
        response_len = write_bytes;
    }

    size_t response_size = RESPONSE_TYPE_LEN + SIZE_SEGMENT_LEN + response_len;
    conn->wbuf_size += response_size;

    uint32_t type = htonl(RES_ERR);
    memcpy(buf, &type, RESPONSE_TYPE_LEN);
    response_len = htonl(response_len);
    memcpy(&buf[RESPONSE_TYPE_LEN], &response_len, SIZE_SEGMENT_LEN);
}

static inline void send_prepare_error(PrepareResult error) {
    Conn *conn = state.current_client;
    char *response;
    size_t response_len;
    switch(error) {
    case CommandIsTooLong:
        response = COMMAND_IS_TOO_LONG_ERROR;
        response_len = ERROR_LEN(COMMAND_IS_TOO_LONG_ERROR);
        break;
    case ZeroSegment:
        response = ZERO_SEGMENT_ERROR;
        response_len = ERROR_LEN(ZERO_SEGMENT_ERROR);
        break;
    default:
        return;
    }

    send_err(response, response_len);
    conn->should_close = true;
}

static inline void send_server_error(ServerError error) {
    char *response;
    size_t response_len;
    switch(error) {
    case UndefinedCommand:
        response = UNDEFINED_COMMAND_ERROR;
        response_len = ERROR_LEN(UNDEFINED_COMMAND_ERROR);
        break;
    case OutOfMemory:
        response = OUT_OF_MEMORY_ERROR;
        response_len = ERROR_LEN(OUT_OF_MEMORY_ERROR);
        break;
    }
    send_err(response, response_len);
}

static inline void send_arity_error(unsigned int expected, unsigned int given) {
    send_format_error(
        "wrong number of arguments (given %u, expected %u)",
        given,
        expected
    );
}

static inline void add_connection(void) {
    for(int i = 0; i < MAX_ACCEPTS; i++) {
        int clientfd = accept(state.accept_sock, NULL, NULL);
        if(clientfd < 0) {
            if(errno != EWOULDBLOCK && errno != EAGAIN)
                perror("add_connection (accept)");
            goto error;
        }
        if(clientfd >= state.event_loop->max_events)
            goto error;

        if(fcntl(clientfd, F_SETFL, O_NONBLOCK) < 0) {
            perror("add_connection (fcntl)");
            goto error;
        }

        Conn *conn = &state.connections[clientfd];
        conn->fd = clientfd;
        conn->rbuf_offset = 0;
        conn->cmd_len = 0;
        conn->rbuf_size = 0;
        conn->read_strings = 0;
        conn->wbuf_offset = 0;
        conn->wbuf_size = 0;
        conn->is_array_response = false;
        conn->should_close = false;

        if(!conn->rbuf) {
            conn->rbuf = malloc(RBUF_SIZE);
            if(!conn->rbuf) {
                perror("add_connection (malloc)");
                goto error;
            }
        }

        if(!conn->wbuf) {
            conn->wbuf = malloc(WBUF_SIZE);
            if(!conn->wbuf) {
                perror("add_connection (malloc)");
                goto error;
            }
        }

        if(!set_event_mask(state.event_loop, clientfd, EVENT_READ, false))
            goto error;

        continue;
    error:
        if(clientfd >= 0) close(clientfd);
        break;
    }
}

static inline bool write_response(void) {
    Conn *conn = state.current_client;
    int clientfd = conn->fd;

    ssize_t write_bytes = 0;

    do {
        write_bytes = send(clientfd, &conn->wbuf[conn->wbuf_offset], conn->wbuf_size, 0);
    } while(write_bytes < 0 && errno == EINTR);

    if(write_bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return false;

    if(write_bytes < 0) {
        perror("write_response (send)");
        close_connection();
        return false;
    }

    conn->wbuf_size -= write_bytes;

    if(conn->wbuf_size == 0) {
        conn->wbuf_offset = 0;
        return true;
    } else {
        conn->wbuf_offset += write_bytes;
        return false;
    }
}

static inline void handle_write_event(void) {
    if(write_response())
        current_client_to_read();
}

static inline bool check_arity(Command *cmd) {
    Conn *conn = state.current_client;
    if(conn->read_strings != cmd->arity + 1) {
        send_arity_error(cmd->arity, conn->read_strings - 1);
        return false;
    }
    return true;
}

typedef struct {
    char     *saveptr;
    char     bak;
    uint32_t num_strings;
} CmdArgState;

#define INIT_CMD_ARG_STATE {NULL, 0, 0}

static inline void cmd_restore(CmdArgState *arg_state) {
    *arg_state->saveptr = arg_state->bak;
}

static inline char* next_cmd_arg(CmdArgState *arg_state) {
    Conn *conn = state.current_client;
    if(!arg_state->saveptr) {
        uint32_t cmd_len;
        memcpy(
            &cmd_len,
            &conn->rbuf[conn->rbuf_offset + SIZE_SEGMENT_LEN],
            SIZE_SEGMENT_LEN
        );
        size_t arg_offset = conn->rbuf_offset + 2 * SIZE_SEGMENT_LEN + cmd_len;
        arg_state->saveptr = (char*)&conn->rbuf[arg_offset];
        arg_state->num_strings = conn->read_strings;
    } else {
        *arg_state->saveptr = arg_state->bak;
        if(arg_state->num_strings == 1)
            return NULL;
    }

    uint32_t tok_len;
    memcpy(&tok_len, arg_state->saveptr, SIZE_SEGMENT_LEN);
    arg_state->saveptr += SIZE_SEGMENT_LEN;
    char *tok = arg_state->saveptr;
    arg_state->bak = tok[tok_len];
    tok[tok_len] = 0;
    arg_state->saveptr += tok_len;
    arg_state->num_strings--;
    return tok;
}

static void get_handler(void) {
    CmdArgState arg_state = INIT_CMD_ARG_STATE;
    char *key = next_cmd_arg(&arg_state);
    HashTableNode *value_node = hash_table_get(state.keys, key);
    if(!value_node) {
        send_nil();
    } else {
        send_str(value_node->value, strlen(value_node->value));
    }
    next_cmd_arg(&arg_state);
}

static void set_handler(void) {
    CmdArgState arg_state = INIT_CMD_ARG_STATE;
    char *key = NULL, *value = NULL;

    key = strdup(next_cmd_arg(&arg_state));
    if(!key)
        goto out_of_memory;

    value = strdup(next_cmd_arg(&arg_state));
    if(!value)
        goto out_of_memory;

    if(!hash_table_set(state.keys, key, value))
        goto out_of_memory;

    next_cmd_arg(&arg_state);
    send_nil();
    return;

out_of_memory:
    if(key) free(key);
    if(value) free(value);
    cmd_restore(&arg_state);
    send_server_error(OutOfMemory);
}

static void del_handler(void) {
    CmdArgState arg_state = INIT_CMD_ARG_STATE;
    char *key = next_cmd_arg(&arg_state);
    HashTableNode *value_node = hash_table_get(state.keys, key);
    int32_t result;
    if(value_node) {
        hash_table_remove(state.keys, value_node);
        result = 1;
    } else {
        result = 0;
    }
    next_cmd_arg(&arg_state);
    send_int(result);
}

static void keys_handler(void) {
    if(state.keys->size == 0) {
        send_nil();
        return;
    }

    if(!send_arr(state.keys->size))
        return;

    for(HashTableIterator it = hash_table_begin(state.keys);
        hash_table_has_next(&it);
        hash_table_next(&it))
    {
        if(!send_str(it.node->key, strlen(it.node->key)))
            return;
    }

    end_arr();
}

static inline bool read_command(void) {
    int clientfd = state.current_client->fd;
    Conn *conn = state.current_client;
    ssize_t read_bytes = 0;

    do {
        read_bytes = recv(
            clientfd,
            &conn->rbuf[conn->rbuf_offset + conn->rbuf_size],
            MAX_COMMAND_LEN - conn->rbuf_offset - conn->rbuf_size,
            0
        );
    } while(read_bytes < 0 && errno == EINTR);

    if(read_bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return false;

    if(read_bytes < 0 || read_bytes == 0) {
        if(read_bytes < 0)
            perror("read_command (recv)");
        close_connection();
        return false;
    }

    conn->rbuf_size += read_bytes;

    size_t next_cmd_len;
    PrepareResult prepare_result = prepare_command(&next_cmd_len);
    switch(prepare_result) {
    case CommandPartiallyRead:
        if(conn->rbuf_offset + next_cmd_len > MAX_COMMAND_LEN) {
            memmove(conn->rbuf, &conn->rbuf[conn->rbuf_offset], conn->rbuf_size);
            conn->rbuf_offset = 0;
        }
        return false;
    case CommandReadSuccess:
        return true;
    default:
        send_prepare_error(prepare_result);
        return false;
    }
}

static inline void process_request(void) {
    Conn *conn = state.current_client;
    uint32_t cmd_name_len;
    memcpy(
        &cmd_name_len,
        &conn->rbuf[conn->rbuf_offset + SIZE_SEGMENT_LEN],
        SIZE_SEGMENT_LEN
    );
    char *cmd_name = (char*)&conn->rbuf[conn->rbuf_offset + 2 * SIZE_SEGMENT_LEN];
    char bak = cmd_name[cmd_name_len];
    cmd_name[cmd_name_len] = 0;

    HashTableNode *command_node = hash_table_get(state.commands, cmd_name);
    cmd_name[cmd_name_len] = bak;

    if(!command_node) {
        send_server_error(UndefinedCommand);
    } else {
        Command *command = command_node->value;
        if(check_arity(command))
            command->handler();
    }

    conn->rbuf_size -= conn->cmd_len;
    conn->rbuf_offset += conn->cmd_len;
    if(conn->rbuf_size == 0) {
        conn->rbuf_offset = 0;
    } else if(MAX_COMMAND_LEN - conn->rbuf_offset <= 2 * SIZE_SEGMENT_LEN) {
        memmove(conn->rbuf, &conn->rbuf[conn->rbuf_offset], conn->rbuf_size);
        conn->rbuf_offset = 0;
    }
    conn->cmd_len = 0;
}

static inline void handle_read_event(void) {
    Conn *conn = state.current_client;
    bool can_process_more = read_command();

    if(can_process_more) {
        process_request();
        can_process_more = !conn->should_close;
    }

    PrepareResult prepare_result = CommandReadSuccess;

    while(can_process_more && conn->rbuf_size > 2 * SIZE_SEGMENT_LEN) {
        size_t next_cmd_len;
        prepare_result = prepare_command(&next_cmd_len);

        if(prepare_result == CommandPartiallyRead) {
            if(conn->rbuf_offset + next_cmd_len > MAX_COMMAND_LEN) {
                memmove(conn->rbuf, &conn->rbuf[conn->rbuf_offset], conn->rbuf_size);
                conn->rbuf_offset = 0;
            }
            break;
        } else if(prepare_result != CommandReadSuccess) {
            send_prepare_error(prepare_result);
            break;
        }

        process_request();
        can_process_more = !conn->should_close;
    }

    if(conn->wbuf_size == 0)
        return;

    if(!write_response()) {
        current_client_to_write();
        return;
    }

    if(conn->should_close) {
        close_connection();
        return;
    }
}

static inline void handle_connection(Event *event) {
    state.current_client = &state.connections[event->fd];

    if(event->mask == EVENT_READ) {
        handle_read_event();
    } else if(event->mask == EVENT_WRITE) {
        handle_write_event();
    }

    state.current_client = NULL;
}

static void handle_event(Event *event) {
    if(event->fd == state.accept_sock) {
        add_connection();
    } else {
        handle_connection(event);
    }
}

static inline bool init_commands(void) {
    for(size_t i = 0; i < NUM_SUPPORTED_COMMANDS; i++) {
        if(!hash_table_set(state.commands, commands[i].name, &commands[i].command))
            return false;
    }
    return true;
}

static void free_server(void) {
    if(state.accept_sock >= 0) close(state.accept_sock);
    if(state.event_loop) {
        if(state.connections) {
            for(size_t i = 0; i < state.event_loop->max_events; i++) {
                Conn *conn = &state.connections[i];
                if(conn->rbuf) free(conn->rbuf);
                if(conn->wbuf) free(conn->wbuf);
            }
            free(state.connections);
        }

        free_event_loop(state.event_loop);
    }
    if(state.keys) hash_table_free(state.keys);
    if(state.commands) hash_table_free(state.commands);
}

static inline bool init_server(void) {
    const int reuseaddr = 1;
    int setopt_result = 0;

    state.max_clients = MAX_CLIENTS;
    state.port = PORT;

    state.event_loop = create_event_loop(state.max_clients + RESERVED_FDS);
    if(!state.event_loop)
        return false;

    state.connections = calloc(sizeof(Conn), state.event_loop->max_events);
    if(!state.connections) {
        perror("init_server (calloc)");
        return false;
    }

#ifdef HAVE_SOCK_NONBLOCK
    state.accept_sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
#else
    state.accept_sock = socket(AF_INET, SOCK_STREAM, 0);
#endif
    if(state.accept_sock < 0) {
        perror("init_server (socket)");
        return false;
    }

#ifndef HAVE_SOCK_NONBLOCK
    if(fcntl(state.accept_sock, F_SETFL, O_NONBLOCK) < 0) {
        perror("init_server (fcntl)");
        return false;
    }
#endif

    setopt_result = setsockopt(
        state.accept_sock,
        SOL_SOCKET,
        SO_REUSEADDR,
        &reuseaddr,
        sizeof(reuseaddr)
    );
    if(setopt_result < 0) {
        perror("init_server (setsockopt)");
        return false;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(state.port);
    memset(&addr.sin_addr, 0, sizeof(addr.sin_addr));
    if(bind(state.accept_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("init_server (bind)");
        return false;
    }

    if(listen(state.accept_sock, 1024) < 0) {
        perror("init_server (listen)");
        return false;
    }

    if(!set_event_mask(state.event_loop, state.accept_sock, EVENT_READ, false))
        return false;

    state.keys = hash_table_new(free, free, INIT_KEYS_CAPACITY);
    if(!state.keys)
        return false;

    state.commands = hash_table_new(NULL, NULL, NUM_SUPPORTED_COMMANDS);
    if(!state.commands)
        return false;

    if(!init_commands())
        return false;

    return true;
}

static void sigint_handler(int signum) {
    free_server();
    exit(0);
}

static inline bool set_signal_handlers(void) {
    struct sigaction act = {0};
    act.sa_handler = sigint_handler;
    if(sigaction(SIGINT, &act, NULL) < 0) {
        perror("set_signal_handlers (sigaction)");
        return false;
    }
    return true;
}

int main(void) {
    int result = 2;

    if(!set_signal_handlers())
        goto exit;

    if(!init_server())
        goto exit;

    for(;;) {
        int num_events = poll_events(state.event_loop, NULL);
        for(int i = 0; i < num_events; i++)
            handle_event(&state.event_loop->events[i]);
    }

    result = 0;
exit:
    free_server();
    return result;
}

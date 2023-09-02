#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "server.h"
#include "hashtable.h"
#include "util.h"

#define RBUF_SIZE              MAX_COMMAND_LEN + 1
#define WBUF_SIZE              MAX_RESPONSE_LEN + ERROR_RESPONSE_LEN + 1
#define NUM_SUPPORTED_COMMANDS sizeof(commands) / sizeof(*commands)
#define MIN_TOKEN_SIZE         REQUEST_TYPE_LEN + INT_LEN

State state;

static struct {
    char    *name;
    Command command;
} commands[] = {
    { "GET",    { .min_args = 1, .max_args = 1, .handler = get_handler    } },
    { "SET",    { .min_args = 2, .max_args = 2, .handler = set_handler    } },
    { "DEL",    { .min_args = 1, .max_args = 1, .handler = del_handler    } },
    { "KEYS",   { .min_args = 0, .max_args = 0, .handler = keys_handler   } },
    { "ZADD",   { .min_args = 3, .max_args = 3, .handler = zadd_handler   } },
    { "ZRANGE", { .min_args = 3, .max_args = 6, .handler = zrange_handler } },
    { "ZREM",   { .min_args = 2, .max_args = 2, .handler = zrem_handler   } },
    { "ZCARD",  { .min_args = 1, .max_args = 1, .handler = zcard_handler  } },
    { "ZSCORE", { .min_args = 2, .max_args = 2, .handler = zscore_handler } }
};

typedef enum {
    CommandPartiallyRead,
    CommandIsTooLong,
    UnknownTokenType,
    ZeroSegment,
    CommandNameIsNotString,
    CommandReadSuccess
} CommandCheckResult;

static inline CommandCheckResult check_command_was_read(size_t *_next_cmd_len) {
    Conn *conn = state.current_client;

    size_t next_cmd_len = SIZE_SEGMENT_LEN + REQUEST_TYPE_LEN + SIZE_SEGMENT_LEN + 1;
    if(conn->rbuf_size < next_cmd_len) {
        // First time.
        // Command header is NUM_TOKENS + REQUEST_TYPE + STRING_LENGTH + char
        *_next_cmd_len = next_cmd_len;
        return CommandPartiallyRead;
    }

    uint32_t num_tokens;
    bool is_first_token;
    memcpy(&num_tokens, &conn->rbuf[conn->rbuf_offset], SIZE_SEGMENT_LEN);
    if(conn->cmd_len == 0) {
        num_tokens = ntohl(num_tokens);
        memcpy(&conn->rbuf[conn->rbuf_offset], &num_tokens, SIZE_SEGMENT_LEN);
        conn->cmd_len = SIZE_SEGMENT_LEN;
        conn->read_tokens = 0;
        is_first_token = true;
    } else {
        is_first_token = false;
    }

    if(num_tokens == 0)
        return ZeroSegment;

    while(conn->cmd_len + MIN_TOKEN_SIZE <= conn->rbuf_size &&
          conn->read_tokens < num_tokens)
    {
        size_t cur = conn->rbuf_offset + conn->cmd_len;
        uint8_t token_type = conn->rbuf[cur];

        uint32_t str_len, token_len;
        switch(token_type) {
        case REQ_INT:
            token_len = INT_LEN;
            break;
        case REQ_DOUBLE:
            token_len = DOUBLE_LEN;
            break;
        case REQ_STR:
            memcpy(&str_len, &conn->rbuf[cur + REQUEST_TYPE_LEN], SIZE_SEGMENT_LEN);
            str_len = ntohl(str_len);
            if(str_len == 0)
                return ZeroSegment;
            token_len = str_len + SIZE_SEGMENT_LEN;
            break;
        default:
            return UnknownTokenType;
        }
        token_len += REQUEST_TYPE_LEN;

        if(is_first_token) {
            if(token_type != REQ_STR)
                return CommandNameIsNotString;
            is_first_token = false;
        }

        next_cmd_len = conn->cmd_len + token_len;
        if(next_cmd_len > MAX_COMMAND_LEN) {
            return CommandIsTooLong;
        } else if(next_cmd_len > conn->rbuf_size) {
            *_next_cmd_len = next_cmd_len;
            return CommandPartiallyRead;
        }

        conn->cmd_len = next_cmd_len;
        conn->read_tokens++;
    }

    if(conn->read_tokens != num_tokens) {
        next_cmd_len = conn->cmd_len + MIN_TOKEN_SIZE;
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
        conn->wbuf_size += RESPONSE_TYPE_LEN + INT_LEN;

        uint32_t type = htonl(RES_ERR);
        uint32_t code = htonl(ERR_RESPONSE_IS_TOO_LONG);
        memcpy(buf, &type, RESPONSE_TYPE_LEN);
        memcpy(&buf[RESPONSE_TYPE_LEN], &code, INT_LEN);
        conn->should_close = true;
        return false;
    }
    return true;
}

bool send_nil(void) {
    if(!check_response_size_or_send_error(RESPONSE_TYPE_LEN))
        return false;

    Conn *conn = state.current_client;
    conn->wbuf[conn->wbuf_size++] = RES_NIL;
    return true;
}

bool send_str(const char *msg, uint32_t msg_len) {
    uint32_t response_size = RESPONSE_TYPE_LEN + SIZE_SEGMENT_LEN + msg_len;
    if(!check_response_size_or_send_error(response_size))
        return false;

    Conn *conn = state.current_client;
    uint8_t *buf = &conn->wbuf[conn->wbuf_size];
    *buf = RES_STR;
    memcpy(&buf[RESPONSE_TYPE_LEN + SIZE_SEGMENT_LEN], msg, msg_len);
    msg_len = htonl(msg_len);
    memcpy(&buf[RESPONSE_TYPE_LEN], &msg_len, SIZE_SEGMENT_LEN);
    conn->wbuf_size += response_size;
    return true;
}

static inline bool generic_send_int(uint8_t type, uint32_t val) {
    uint32_t response_size = RESPONSE_TYPE_LEN + INT_LEN;
    if(!check_response_size_or_send_error(response_size))
        return false;

    Conn *conn = state.current_client;
    uint8_t *buf = &conn->wbuf[conn->wbuf_size];
    val = htonl(val);
    *buf = type;
    memcpy(&buf[RESPONSE_TYPE_LEN], &val, INT_LEN);
    conn->wbuf_size += response_size;
    return true;
}

bool send_int(int32_t val) {
    return generic_send_int(RES_INT, val);
}

bool send_err(ErrorCode code) {
    return generic_send_int(RES_ERR, code);
}

bool send_double(double val) {
    uint32_t response_size = RESPONSE_TYPE_LEN + DOUBLE_LEN;
    if(!check_response_size_or_send_error(response_size))
        return false;

    Conn *conn = state.current_client;
    uint8_t *buf = &conn->wbuf[conn->wbuf_size];
    val = htond(val);
    *buf = RES_DOUBLE;
    memcpy(&buf[RESPONSE_TYPE_LEN], &val, DOUBLE_LEN);
    conn->wbuf_size += response_size;
    return true;
}

bool send_arr(void) {
    Conn *conn = state.current_client;
    uint32_t response_size = RESPONSE_TYPE_LEN + INT_LEN;
    if(!check_response_size_or_send_error(response_size))
        return false;

    conn->is_array_response = true;
    conn->array_response_offset = conn->wbuf_size;
    conn->wbuf_size += response_size;
    return true;
}

void end_arr(uint32_t size) {
    Conn *conn = state.current_client;
    conn->is_array_response = false;
    uint8_t *buf = &conn->wbuf[conn->array_response_offset];
    size = htonl(size);
    *buf = RES_ARR;
    memcpy(&buf[RESPONSE_TYPE_LEN], &size, SIZE_SEGMENT_LEN);
}

static inline void send_command_error(CommandCheckResult error) {
    Conn *conn = state.current_client;
    ErrorCode code;
    switch(error) {
    case CommandIsTooLong:
        code = ERR_COMMAND_IS_TOO_LONG;
        break;
    case UnknownTokenType:
        code = ERR_UNKNOWN_TOKEN_TYPE;
        break;
    case ZeroSegment:
        code = ERR_ZERO_SEGMENT;
        break;
    case CommandNameIsNotString:
        code = ERR_COMMAND_NAME_IS_NOT_STRING;
        break;
    default:
        return;
    }

    send_err(code);
    conn->should_close = true;
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
        conn->read_tokens = 0;
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
    if(conn->read_tokens < cmd->min_args + 1 ||
       conn->read_tokens > cmd->max_args + 1)
    {
        send_err(ERR_ARITY);
        return false;
    }
    return true;
}

bool next_cmd_arg(CmdArgState *arg_state, Arg *arg) {
    Conn *conn = state.current_client;
    if(!arg_state->saveptr) {
        uint32_t cmd_len;
        memcpy(
            &cmd_len,
            &conn->rbuf[conn->rbuf_offset + SIZE_SEGMENT_LEN + REQUEST_TYPE_LEN],
            SIZE_SEGMENT_LEN
        );
        cmd_len = ntohl(cmd_len);
        size_t arg_offset = conn->rbuf_offset + REQUEST_TYPE_LEN +
                            2 * SIZE_SEGMENT_LEN + cmd_len;
        arg_state->saveptr = &conn->rbuf[arg_offset];
        arg_state->num_tokens = conn->read_tokens;
    } else {
        *arg_state->saveptr = arg_state->bak;
        if(arg_state->num_tokens == 1)
            return false;
    }

    uint8_t token_type = *arg_state->saveptr++;
    uint32_t str_len;
    switch(token_type) {
    case REQ_INT:
        arg->type = ARG_INT;
        memcpy(&arg->int_arg, arg_state->saveptr, INT_LEN);
        arg->int_arg = ntohl(arg->int_arg);
        arg_state->saveptr += INT_LEN;
        arg_state->bak = *arg_state->saveptr;
        break;
    case REQ_DOUBLE:
        arg->type = ARG_DOUBLE;
        memcpy(&arg->double_arg, arg_state->saveptr, DOUBLE_LEN);
        arg->double_arg = ntohd(arg->double_arg);
        arg_state->saveptr += DOUBLE_LEN;
        arg_state->bak = *arg_state->saveptr;
        break;
    case REQ_STR:
        arg->type = ARG_STRING;
        memcpy(&str_len, arg_state->saveptr, SIZE_SEGMENT_LEN);
        str_len = ntohl(str_len);
        arg->str_arg = (char*)(arg_state->saveptr + SIZE_SEGMENT_LEN);
        arg_state->saveptr = (uint8_t*)(arg->str_arg + str_len);
        arg_state->bak = *arg_state->saveptr;
        *arg_state->saveptr = 0;
        break;
    }

    arg_state->num_tokens--;
    return true;
}

bool next_int_arg(CmdArgState *arg_state, uint32_t *arg) {
    Arg arg_struct;
    if(!next_cmd_arg(arg_state, &arg_struct))
        return false;
    if(arg_struct.type != ARG_INT) {
        send_err(ERR_VALUE_IS_NOT_INT);
        return false;
    }
    *arg = arg_struct.int_arg;
    return true;
}

bool next_double_arg(CmdArgState *arg_state, double *arg) {
    Arg arg_struct;
    if(!next_cmd_arg(arg_state, &arg_struct))
        return false;
    if(arg_struct.type != ARG_DOUBLE) {
        send_err(ERR_VALUE_IS_NOT_FLOAT);
        return false;
    }
    *arg = arg_struct.double_arg;
    return true;
}

bool next_string_arg(CmdArgState *arg_state, char **arg) {
    Arg arg_struct;
    if(!next_cmd_arg(arg_state, &arg_struct))
        return false;
    if(arg_struct.type != ARG_STRING) {
        send_err(ERR_VALUE_IS_NOT_STRING);
        return false;
    }
    *arg = arg_struct.str_arg;
    return true;
}

void cmd_restore(CmdArgState *arg_state) {
    *arg_state->saveptr = arg_state->bak;
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
    CommandCheckResult check_result = check_command_was_read(&next_cmd_len);
    switch(check_result) {
    case CommandPartiallyRead:
        if(conn->rbuf_offset + next_cmd_len > MAX_COMMAND_LEN) {
            memmove(conn->rbuf, &conn->rbuf[conn->rbuf_offset], conn->rbuf_size);
            conn->rbuf_offset = 0;
        }
        return false;
    case CommandReadSuccess:
        return true;
    default:
        send_command_error(check_result);
        return false;
    }
}

static inline void process_request(void) {
    Conn *conn = state.current_client;
    uint32_t cmd_name_len;
    size_t offset = conn->rbuf_offset + SIZE_SEGMENT_LEN + REQUEST_TYPE_LEN;
    char *buf = (char*)&conn->rbuf[offset];
    memcpy(&cmd_name_len, buf, SIZE_SEGMENT_LEN);
    cmd_name_len = ntohl(cmd_name_len);
    char *cmd_name = &buf[SIZE_SEGMENT_LEN];
    char bak = cmd_name[cmd_name_len];
    cmd_name[cmd_name_len] = 0;

    HashTableNode *command_node = hash_table_get(state.commands, cmd_name);
    cmd_name[cmd_name_len] = bak;

    if(!command_node) {
        send_err(ERR_UNDEFINED_COMMAND);
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

    CommandCheckResult check_result = CommandReadSuccess;

    while(can_process_more && conn->rbuf_size > 2 * SIZE_SEGMENT_LEN) {
        size_t next_cmd_len;
        check_result = check_command_was_read(&next_cmd_len);

        if(check_result == CommandPartiallyRead) {
            if(conn->rbuf_offset + next_cmd_len > MAX_COMMAND_LEN) {
                memmove(conn->rbuf, &conn->rbuf[conn->rbuf_offset], conn->rbuf_size);
                conn->rbuf_offset = 0;
            }
            break;
        } else if(check_result != CommandReadSuccess) {
            send_command_error(check_result);
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

    state.keys = hash_table_new(free, freeObject, INIT_KEYS_CAPACITY);
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <math.h>
#include <limits.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "proto.h"
#include "util.h"
#include "hashtable.h"

#define MAX_ERROR_LEN               256
#define OUTPUT_BUF_SIZE             (2 * (MAX_RESPONSE_LEN + MAX_ERROR_LEN))
#define RESPONSE_IS_TOO_LONG_ERROR  "ERR: response is too long\n"
#define WRONG_RESPONSE_TYPE_ERROR   "ERR: wrong response status type\n"
#define COMMAND_IS_TOO_LONG_ERROR   "ERR: command is too long\n"
#define EMPTY_REQUEST_ERROR         "ERR: empty request\n"
#define UNDEFINED_COMMAND           "undefined command"
#define UNDEFINED_COMMAND_ERROR     "ERR: " UNDEFINED_COMMAND "\n"
#define WRONG_ARGUMENTS_COUNT       "wrong number of arguments"
#define WRONG_ARGUMENTS_COUNT_ERROR "ERR: " WRONG_ARGUMENTS_COUNT "\n"
#define UNKNOWN_ERROR_CODE          "unknown"
#define VALUE_IS_NOT_INT            "value is not an integer"
#define VALUE_IS_NOT_INT_ERROR      "ERR: " VALUE_IS_NOT_INT "\n"
#define VALUE_IS_NOT_FLOAT          "value is not a float"
#define VALUE_IS_NOT_FLOAT_ERROR    "ERR: " VALUE_IS_NOT_FLOAT "\n"
#define MAX_ARGUMENTS               10
#define ARRAY_SIZE(arr)             sizeof(arr)/sizeof(*arr)

typedef struct {
    char   *message;
    size_t len;
} ErrorMessage;

typedef enum {
    ARG_UINT,
    ARG_INT,
    ARG_DOUBLE,
    ARG_STR
} ArgType;

typedef struct {
    bool    is_enabled;
    ArgType args[MAX_ARGUMENTS];
} ArgsList;

static struct {
    char     *name;
    ArgsList args_lists[MAX_ARGUMENTS];
} commands_info[] = {
    { "GET", { [0] = { true, { ARG_STR } } } },
    { "SET", { [1] = { true, { ARG_STR, ARG_STR } } } },
    { "DEL", { [0] = { true, { ARG_STR } } } },
    { "KEYS", { } },
    { "ZADD", { [2] = { true, { ARG_STR, ARG_DOUBLE, ARG_STR } } } },
    { "ZRANGE", {
        [2] = { true, { ARG_STR, ARG_DOUBLE, ARG_DOUBLE } },
        [3] = { true, { ARG_STR, ARG_DOUBLE, ARG_DOUBLE, ARG_STR } },
        [4] = { true, { ARG_STR, ARG_DOUBLE, ARG_DOUBLE, ARG_UINT, ARG_UINT } },
        [5] = { true, { ARG_STR, ARG_DOUBLE, ARG_DOUBLE, ARG_UINT, ARG_UINT, ARG_STR } }
    } },
    { "ZREM", { [1] = { true, { ARG_STR, ARG_STR } } } },
    { "ZCARD", { [0] = { true, { ARG_STR } } } },
    { "ZSCORE", { [1] = { true, { ARG_STR, ARG_STR } } } }
};

static HashTable* init_commands(void) {
    HashTable *commands = hash_table_new(NULL, NULL, ARRAY_SIZE(commands_info));
    if(!commands)
        return NULL;

    for(size_t i = 0; i < ARRAY_SIZE(commands_info); i++) {
        HashTableNode *node = hash_table_set(
            commands,
            commands_info[i].name,
            commands_info[i].args_lists
        );
        if(!node) {
            hash_table_free(commands);
            return NULL;
        }
    }

    return commands;
}

#define ERROR_MESSAGE(type, msg) [type] = { msg, sizeof(msg) - 1 }

static const ErrorMessage error_messages[] = {
    ERROR_MESSAGE(ERR_COMMAND_IS_TOO_LONG, "command is too long"),
    ERROR_MESSAGE(ERR_ZERO_SEGMENT, "command contains zero length segment"),
    ERROR_MESSAGE(ERR_UNDEFINED_COMMAND, UNDEFINED_COMMAND),
    ERROR_MESSAGE(ERR_OUT_OF_MEMORY, "out of memory"),
    ERROR_MESSAGE(ERR_ARITY, WRONG_ARGUMENTS_COUNT),
    ERROR_MESSAGE(ERR_RESPONSE_IS_TOO_LONG, "response is too long"),
    ERROR_MESSAGE(ERR_TYPE_MISMATCH,
        "trying to perform operation against key with wrong type"
    ),
    ERROR_MESSAGE(ERR_VALUE_IS_NOT_FLOAT, VALUE_IS_NOT_FLOAT),
    ERROR_MESSAGE(ERR_VALUE_IS_NOT_INT, VALUE_IS_NOT_INT),
    ERROR_MESSAGE(ERR_VALUE_IS_NOT_STRING, "value is not a string"),
    ERROR_MESSAGE(ERR_UNKNOWN_TOKEN_TYPE, "token type is unknown"),
    ERROR_MESSAGE(ERR_COMMAND_NAME_IS_NOT_STRING, "command name must be a string")
};

static_assert(ARRAY_SIZE(error_messages) == ERR_MAX);

typedef enum {
    REQ_OK,
    REQ_WARN,
    REQ_ERR,
} RequestStatus;

typedef struct {
    char   *buf;
    size_t buf_size;
} Output;

static inline bool init_output(Output *out) {
    out->buf = malloc(OUTPUT_BUF_SIZE);
    if(!out->buf) {
        perror("init_output (malloc)");
        return false;
    }
    out->buf_size = 0;
    return true;
}

static inline void free_output(Output *out) {
    if(out->buf)
        free(out->buf);
}

static bool write_all(int sockfd, void *buf, size_t size) {
    size_t write_bytes = 0;
    while(write_bytes < size) {
        ssize_t wb = write(sockfd, (char*)buf + write_bytes, size - write_bytes);
        if(wb < 0) {
            perror("send");
            return false;
        }
        write_bytes += wb;
    }

    return true;
}

static inline void reverse(char *buf, size_t size) {
    for(size_t i = 0, j = size - 1; j > i; i++, j--) {
        char tmp = buf[i];
        buf[i] = buf[j];
        buf[j] = tmp;
    }
}

static size_t itoa(ssize_t num, char *buf) {
    size_t size = 0;
    if(num < 0) {
        num = -num;
        buf[size++] = '-';
    }

    do {
        buf[size++] = '0' + num % 10;
        num /= 10;
    } while(num != 0);

    size_t rev_size;
    if(*buf == '-') {
        buf++;
        rev_size = size - 1;
    } else {
        rev_size = size;
    }
    reverse(buf, rev_size);

    return size;
}

static size_t utoa(size_t num, char *buf) {
    size_t size = 0;
    do {
        buf[size++] = '0' + num % 10;
        num /= 10;
    } while(num != 0);
    reverse(buf, size);
    return size;
}

static bool string2d(const char *str, double *d) {
    char *endpptr;
    size_t len = strlen(str);
    *d = strtod(str, &endpptr);
    if(isspace(str[0]) ||
       (endpptr - str) != len ||
       (errno == ERANGE &&
        (*d == HUGE_VAL || *d == -HUGE_VAL || fpclassify(*d) == FP_ZERO)))
    {
        return false;
    }
    return true;
}

static bool string2l(const char *str, long *i) {
    char *endpptr;
    size_t len = strlen(str);
    *i = strtol(str, &endpptr, 10);
    if(isspace(str[0]) ||
       (endpptr - str) != len ||
       (errno == ERANGE && (*i == LONG_MAX || *i == LONG_MIN)))
    {
        return false;
    }
    return true;
}

static bool string2ul(const char *str, unsigned long *i) {
    char *endpptr;
    size_t len = strlen(str);
    *i = strtoul(str, &endpptr, 10);
    if(isspace(str[0]) || str[0] == '-' ||
       (endpptr - str) != len ||
       (errno == ERANGE && *i == ULONG_MAX))
    {
        return false;
    }
    return true;
}

static size_t chrcnt(char *str, char c) {
    size_t result = 0;
    while(*str != 0) {
        if(*str == c)
            result++;
        str++;
    }
    return result;
}

static bool write_to_output(Output *out, const char *buf, size_t size) {
    size_t new_size = out->buf_size + size;
    if(new_size <= OUTPUT_BUF_SIZE) {
        memcpy(&out->buf[out->buf_size], buf, size);
        out->buf_size = new_size;
        return true;
    }

    if(size > OUTPUT_BUF_SIZE) {
        fputs(RESPONSE_IS_TOO_LONG_ERROR, stderr);
        return false;
    }
    size_t copy_size = OUTPUT_BUF_SIZE - out->buf_size;
    memcpy(&out->buf[out->buf_size], buf, copy_size);

    if(!write_all(1, out->buf, OUTPUT_BUF_SIZE))
        return false;

    out->buf_size = size - copy_size;
    memcpy(out->buf, &buf[copy_size], out->buf_size);
    return true;
}

static inline bool print_response(
    uint32_t type,
    size_t msg_len,
    size_t element_number,
    char *buf,
    Output *out
) {
    char num_buf[128];
    size_t num_size;
    if(element_number) {
        size_t num_size = utoa(element_number, num_buf);
        num_buf[num_size++] = ')';
        num_buf[num_size++] = ' ';
        if(!write_to_output(out, num_buf, num_size))
            return false;
    }

    bool res = true;
    switch(type) {
    case RES_NIL:
        res = write_to_output(out, "nil", 3);
        break;
    case RES_ERR:
        uint32_t code;
        memcpy(&code, &buf[RESPONSE_TYPE_LEN], INT_LEN);
        code = ntohl(code);

        const char *error_message;
        size_t error_message_len;
        if(code >= ERR_MAX) {
            error_message = UNKNOWN_ERROR_CODE;
            error_message_len = sizeof(UNKNOWN_ERROR_CODE) - 1;
        } else {
            error_message = error_messages[code].message;
            error_message_len = error_messages[code].len;
        }

        res = write_to_output(out, "ERR: ", 5);
        res &= write_to_output(
            out,
            error_message,
            error_message_len
        );
        break;
    case RES_STR:
        res = write_to_output(out, "\"", 1);
        res &= write_to_output(
            out,
            &buf[RESPONSE_TYPE_LEN + SIZE_SEGMENT_LEN],
            msg_len - SIZE_SEGMENT_LEN
        );
        res &= write_to_output(out, "\"", 1);
        break;
    case RES_INT:
    case RES_UINT:
        uint32_t ival;
        memcpy(&ival, &buf[RESPONSE_TYPE_LEN], INT_LEN);
        ival = ntohl(ival);
        if(type == RES_INT)
            num_size = itoa((int32_t)ival, num_buf);
        else
            num_size = utoa(ival, num_buf);
        res = write_to_output(out, num_buf, num_size);
        break;
    case RES_DOUBLE:
        double dval;
        memcpy(&dval, &buf[RESPONSE_TYPE_LEN], DOUBLE_LEN);
        dval = ntohd(dval);
        num_size = snprintf(num_buf, sizeof(num_buf), "%lf", dval);
        res = write_to_output(out, num_buf, num_size);
        break;
    case RES_ARR:
        res = write_to_output(out, "(empty array)", 13);
        break;
    }

    res &= write_to_output(out, "\n", 1);

    return res;
}

static inline bool print_output(Output *out) {
    if(!out->buf_size)
        return true;

    return write_all(1, out->buf, out->buf_size);
}

static bool read_and_print_response(
    int sockfd,
    char *buf,
    Output *out,
    size_t num_responses
) {
    uint8_t type;
    size_t msg_len;
    size_t arr_size = 0;
    size_t buf_size = 0, buf_offset = 0, cur_len;
    size_t element_number = 0;
    out->buf_size = 0;

    do {
        cur_len = 0;
        bool is_type_set = false, is_msg_len_set = false;

        for(;;) {
            while(buf_size < RESPONSE_TYPE_LEN ||
                  (is_msg_len_set && buf_size < RESPONSE_TYPE_LEN + msg_len))
            {
                ssize_t rb = recv(
                    sockfd,
                    &buf[buf_offset + buf_size],
                    MAX_RESPONSE_LEN - buf_offset - buf_size,
                    0
                );
                if(rb < 0) {
                    perror("recv");
                    return -1;
                }
                buf_size += rb;
            }

            if(!is_type_set) {
                type = buf[buf_offset];
                if(type >= RES_MAX) {
                    fputs(WRONG_RESPONSE_TYPE_ERROR, stderr);
                    return -1;
                }
                is_type_set = true;
            }

            if(!is_msg_len_set) {
                if(type == RES_NIL) {
                    msg_len = 0;
                    is_msg_len_set = true;
                } else if(type == RES_INT || type == RES_UINT || type == RES_ERR) {
                    msg_len = INT_LEN;
                    is_msg_len_set = true;
                } else if(type == RES_DOUBLE) {
                    msg_len = DOUBLE_LEN;
                    is_msg_len_set = true;
                } else if(buf_size >= RESPONSE_TYPE_LEN + SIZE_SEGMENT_LEN) {
                    uint32_t msg_len32;
                    memcpy(
                        &msg_len32,
                        &buf[buf_offset + RESPONSE_TYPE_LEN],
                        SIZE_SEGMENT_LEN
                    );
                    msg_len32 = ntohl(msg_len32);

                    if(type == RES_ARR) {
                        arr_size = msg_len32;
                        arr_size++;

                        msg_len = INT_LEN; 
                    } else {
                        msg_len = SIZE_SEGMENT_LEN + msg_len32;
                        is_msg_len_set = true;
                    }
                }

                cur_len += RESPONSE_TYPE_LEN + msg_len;
                if(buf_offset + cur_len > MAX_RESPONSE_LEN + ERROR_RESPONSE_LEN) {
                    fputs(RESPONSE_IS_TOO_LONG_ERROR, stderr);
                    return false;
                }
            }

            if(buf_size >= cur_len) {
                bool is_array = arr_size > 0;

                if((!is_array || element_number > 0 || arr_size == 1) &&
                   !print_response(type, msg_len, element_number, &buf[buf_offset], out))
                    return false;

                if(is_array) {
                    arr_size--;
                    element_number++;
                }

                if(arr_size == 0) {
                    element_number = 0;
                    num_responses--;
                }

                break;
            }
        }

        buf_offset += cur_len;
        buf_size -= cur_len;
    } while(num_responses != 0);

    return print_output(out);
}

static inline char* readline(char *buf, size_t size, FILE *file) {
    write(1, "> ", 2);
    return fgets(buf, size, file);
}

static RequestStatus request(
    int sockfd,
    char *cmd_buf,
    char *request_buf,
    size_t *num_requests_res,
    HashTable *commands
) {
    char *cmd_save, *tok_save;
    size_t req_size = 0;
    size_t num_requests = 0;
    char *cmd_new_line = strchr(cmd_buf, '\n');
    if(cmd_new_line) {
        *cmd_new_line = 0;
    } else {
        fputs(COMMAND_IS_TOO_LONG_ERROR, stderr);
        return REQ_WARN;
    }

    char *cmd = strtok_r(cmd_buf, ";", &cmd_save);
    while(cmd) {
        size_t args_count = chrcnt(cmd, ' ');
        if(args_count >= MAX_ARGUMENTS) {
            fputs(WRONG_ARGUMENTS_COUNT_ERROR, stderr);
            return REQ_WARN;
        }

        ArgType *args = NULL;
        uint32_t num_tokens = 0;
        char *token = strtok_r(cmd, " ", &tok_save);
        size_t cur_cmd_offset = req_size;
        req_size += SIZE_SEGMENT_LEN;
        while(token) {
            ArgType arg_type;
            if(num_tokens == 0) {
                HashTableNode *node = hash_table_get(commands, token);
                if(!node) {
                    fputs(UNDEFINED_COMMAND_ERROR, stderr);
                    return REQ_WARN;
                }
                ArgsList *args_lists = node->value;
                if(args_count != 0) {
                    if(!args_lists[args_count - 1].is_enabled) {
                        fputs(WRONG_ARGUMENTS_COUNT_ERROR, stderr);
                        return REQ_WARN;
                    } else {
                        args = args_lists[args_count - 1].args;
                    }
                }
                arg_type = ARG_STR;
            } else {
                arg_type = *args++;
            }

            size_t next_req_size, str_len;
            switch(arg_type) {
            case ARG_STR:
                str_len = strlen(token);
                next_req_size = req_size + SIZE_SEGMENT_LEN + str_len;
                break;
            case ARG_INT:
            case ARG_UINT:
                next_req_size = req_size + INT_LEN;
                break;
            case ARG_DOUBLE:
                next_req_size = req_size + DOUBLE_LEN;
                break;
            }
            next_req_size += REQUEST_TYPE_LEN;

            if(next_req_size > MAX_COMMAND_LEN) {
                fputs(COMMAND_IS_TOO_LONG_ERROR, stderr);
                return REQ_WARN;
            }

            uint32_t str_len_32;
            double double_val;
            long int_val;
            unsigned long uint_val;
            uint32_t int32_val;
            char *buf = &request_buf[req_size];
            uint8_t token_type;
            switch(arg_type) {
            case ARG_STR:
                token_type = REQ_STR;
                str_len_32 = str_len;
                str_len_32 = htonl(str_len_32);
                memcpy(&buf[REQUEST_TYPE_LEN], &str_len_32, SIZE_SEGMENT_LEN);
                memcpy(&buf[REQUEST_TYPE_LEN + SIZE_SEGMENT_LEN], token, str_len);
                break;
            case ARG_INT:
                if(!string2l(token, &int_val)) {
                    fputs(VALUE_IS_NOT_INT_ERROR, stderr);
                    return REQ_WARN;
                }
                int32_val = int_val;
                int32_val = htonl(int32_val);
                memcpy(&buf[REQUEST_TYPE_LEN], &int32_val, INT_LEN);
                token_type = REQ_INT;
                break;
            case ARG_UINT:
                if(!string2ul(token, &uint_val)) {
                    fputs(VALUE_IS_NOT_INT_ERROR, stderr);
                    return REQ_WARN;
                }
                int32_val = uint_val;
                int32_val = htonl(int32_val);
                memcpy(&buf[REQUEST_TYPE_LEN], &int32_val, INT_LEN);
                token_type = REQ_INT;
                break;
            case ARG_DOUBLE:
                if(!string2d(token, &double_val)) {
                    fputs(VALUE_IS_NOT_FLOAT_ERROR, stderr);
                    return REQ_WARN;
                }
                double_val = htond(double_val);
                memcpy(&buf[REQUEST_TYPE_LEN], &double_val, DOUBLE_LEN);
                token_type = REQ_DOUBLE;
                break;
            }
            *buf = token_type;

            req_size = next_req_size;
            num_tokens++;
            token = strtok_r(NULL, " ", &tok_save);
        }

        if(num_tokens == 0) {
            fputs(EMPTY_REQUEST_ERROR, stderr);
            return REQ_WARN;
        }

        num_tokens = htonl(num_tokens);
        memcpy(&request_buf[cur_cmd_offset], &num_tokens, SIZE_SEGMENT_LEN);
        cmd = strtok_r(NULL, ";", &cmd_save);
        num_requests++;
    }

    if(req_size > 0 && !write_all(sockfd, request_buf, req_size))
        return REQ_ERR;

    *num_requests_res = num_requests;
    return REQ_OK;
}

static inline int connect_to_server() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5000);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    //inet_pton(AF_INET, "192.168.0.102", &addr.sin_addr.s_addr);

    if(connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int main(void) {
    char *line = NULL, *request_buf = NULL;
    size_t num_requests;
    char *response_buf = NULL;
    HashTable *commands = NULL;
    Output output = {0};
    int result = EXIT_FAILURE;

    line = malloc(MAX_COMMAND_LEN + 1);
    if(!line) {
        perror("malloc");
        goto exit;
    }

    request_buf = malloc(MAX_COMMAND_LEN);
    if(!request_buf) {
        perror("malloc");
        goto exit;
    }

    response_buf = malloc(MAX_RESPONSE_LEN + ERROR_RESPONSE_LEN + 1);
    if(!response_buf) {
        perror("malloc");
        goto exit;
    }

    if(!init_output(&output))
        goto exit;

    commands = init_commands();
    if(!commands)
        goto exit;

    bool is_end = false;
    while(!is_end) {
        int sockfd = connect_to_server();
        if(sockfd < 0)
            break;

        for(;;) {
            char *read_res = readline(line, MAX_COMMAND_LEN + 1, stdin);
            is_end = !read_res;
            if(is_end)
                break;

            RequestStatus status = request(
                sockfd,
                line,
                request_buf,
                &num_requests,
                commands
            );
            if(status == REQ_WARN)
                continue;
            else if(status == REQ_ERR)
                break;

            if(!read_and_print_response(sockfd, response_buf, &output, num_requests))
                goto response_err;
        }

response_err:
        close(sockfd);
    }
    
    result = EXIT_SUCCESS;
exit:
    if(line) free(line);
    if(request_buf) free(request_buf);
    if(response_buf) free(response_buf);
    if(commands) hash_table_free(commands);
    free_output(&output);
    return result;
}

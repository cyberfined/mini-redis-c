#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "proto.h"

#define OUTPUT_BUF_SIZE            (2 * (MAX_RESPONSE_LEN + MAX_ERROR_LEN))
#define RESPONSE_IS_TOO_LONG_ERROR "ERR: response is too long\n"
#define WRONG_RESPONSE_TYPE_ERROR  "ERR: wrong response status type\n"
#define ZERO_SIZE_ARRAY_ERROR      "ERR: zero size arrays are not supported\n"
#define COMMAND_IS_TOO_LONG_ERROR  "ERR: command is too long\n"
#define EMPTY_REQUEST_ERROR        "ERR: empty request\n"

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

static bool write_to_output(Output *out, char *buf, size_t size) {
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
    char num_buf[32];
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
        res = write_to_output(out, "ERR: ", 5);
        res &= write_to_output(
            out,
            &buf[RESPONSE_TYPE_LEN + SIZE_SEGMENT_LEN],
            msg_len - RESPONSE_TYPE_LEN
        );
        break;
    case RES_STR:
        res = write_to_output(out, "\"", 1);
        res &= write_to_output(
            out,
            &buf[RESPONSE_TYPE_LEN + SIZE_SEGMENT_LEN],
            msg_len - RESPONSE_TYPE_LEN
        );
        res &= write_to_output(out, "\"", 1);
        break;
    case RES_INT:
        uint32_t val;
        memcpy(&val, &buf[RESPONSE_TYPE_LEN], INT_LEN);
        val = ntohl(val);
        size_t num_size = itoa((int32_t)val, num_buf);
        res = write_to_output(out, num_buf, num_size);
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
    uint32_t type;
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
                memcpy(&type, &buf[buf_offset], RESPONSE_TYPE_LEN);
                type = ntohl(type);
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
                } else if(type == RES_INT) {
                    msg_len = INT_LEN;
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
                        if(arr_size == 0) {
                            fputs(ZERO_SIZE_ARRAY_ERROR, stderr);
                            return -1;
                        }
                        arr_size++;

                        msg_len = INT_LEN; 
                    } else {
                        msg_len = SIZE_SEGMENT_LEN + msg_len32;
                        is_msg_len_set = true;
                    }
                }

                cur_len += RESPONSE_TYPE_LEN + msg_len;
                if(buf_offset + cur_len > MAX_RESPONSE_LEN + MAX_ERROR_LEN) {
                    fputs(RESPONSE_IS_TOO_LONG_ERROR, stderr);
                    return false;
                }
            }

            if(buf_size >= cur_len) {
                bool is_array = arr_size > 0;

                if((!is_array || element_number > 0) &&
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
    size_t *num_requests_res
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
        uint32_t num_strings = 0;
        char *token = strtok_r(cmd, " ", &tok_save);
        size_t cur_cmd_offset = req_size;
        req_size += SIZE_SEGMENT_LEN;
        while(token) {
            num_strings++;
            size_t len = strlen(token);
            size_t segment_len = SIZE_SEGMENT_LEN + len;
            size_t next_req_size = req_size + segment_len;
            if(next_req_size > MAX_COMMAND_LEN) {
                fputs(COMMAND_IS_TOO_LONG_ERROR, stderr);
                return REQ_WARN;
            }

            uint32_t len32 = len;
            len32 = htonl(len32);
            memcpy(&request_buf[req_size], &len32, SIZE_SEGMENT_LEN);
            memcpy(&request_buf[req_size + SIZE_SEGMENT_LEN], token, len);
            req_size = next_req_size;
            token = strtok_r(NULL, " ", &tok_save);
        }

        if(num_strings == 0) {
            fputs(EMPTY_REQUEST_ERROR, stderr);
            return REQ_WARN;
        }

        num_strings = htonl(num_strings);
        memcpy(&request_buf[cur_cmd_offset], &num_strings, SIZE_SEGMENT_LEN);
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

    response_buf = malloc(MAX_RESPONSE_LEN + MAX_ERROR_LEN + 1);
    if(!response_buf) {
        perror("malloc");
        goto exit;
    }

    if(!init_output(&output))
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
                &num_requests
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
    free_output(&output);
    return result;
}

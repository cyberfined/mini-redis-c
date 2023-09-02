#pragma once

#include <stdint.h>

#define MAX_COMMAND_LEN    4096
#define MAX_RESPONSE_LEN   4096
#define SIZE_SEGMENT_LEN   sizeof(uint32_t)
#define RESPONSE_TYPE_LEN  sizeof(uint8_t)
#define REQUEST_TYPE_LEN   sizeof(uint8_t)
#define INT_LEN            sizeof(uint32_t)
#define DOUBLE_LEN         sizeof(double)
#define ERROR_RESPONSE_LEN RESPONSE_TYPE_LEN + INT_LEN

typedef enum {
    REQ_STR = 0,
    REQ_INT,
    REQ_DOUBLE,
    REQ_MAX
} RequestType;

typedef enum {
    RES_NIL = 0,
    RES_ERR,
    RES_STR,
    RES_INT,
    RES_UINT,
    RES_DOUBLE,
    RES_ARR,
    RES_MAX
} ResponseType;

typedef enum {
    ERR_COMMAND_IS_TOO_LONG = 0,
    ERR_ZERO_SEGMENT,
    ERR_UNDEFINED_COMMAND,
    ERR_OUT_OF_MEMORY,
    ERR_ARITY,
    ERR_RESPONSE_IS_TOO_LONG,
    ERR_TYPE_MISMATCH,
    ERR_VALUE_IS_NOT_FLOAT,
    ERR_VALUE_IS_NOT_INT,
    ERR_VALUE_IS_NOT_STRING,
    ERR_UNKNOWN_TOKEN_TYPE,
    ERR_COMMAND_NAME_IS_NOT_STRING,
    ERR_MAX
} ErrorCode;

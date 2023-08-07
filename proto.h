#pragma once

#include <stdint.h>

#define MAX_COMMAND_LEN   4096
#define MAX_RESPONSE_LEN  4096
#define MAX_ERROR_LEN     256
#define SIZE_SEGMENT_LEN  sizeof(uint32_t)
#define RESPONSE_TYPE_LEN sizeof(uint32_t)
#define INT_LEN           sizeof(uint32_t)

typedef enum {
    RES_NIL = 0,
    RES_ERR,
    RES_STR,
    RES_INT,
    RES_ARR,
    RES_MAX
} ResponseType;

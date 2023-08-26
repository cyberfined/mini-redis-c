#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <ctype.h>

#include "util.h"

bool string2d(const char *str, double *d) {
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

bool string2umax(const char *str, uintmax_t *i) {
    char *endpptr;
    size_t len = strlen(str);
    *i = strtoumax(str, &endpptr, 10);
    if(isspace(str[0]) ||
       (endpptr - str) != len ||
       (errno == ERANGE && *i == UINTMAX_MAX))
    {
        return false;
    }
    return true;
}

#ifdef LITTLE_ENDIAN_FLOAT
double htond(double hostdouble) {
    uint64_t tmp;
    memcpy(&tmp, &hostdouble, sizeof(tmp));
    tmp =
      ((tmp & 0xFF00000000000000u) >> 56u) |
      ((tmp & 0x00FF000000000000u) >> 40u) |
      ((tmp & 0x0000FF0000000000u) >> 24u) |
      ((tmp & 0x000000FF00000000u) >>  8u) |
      ((tmp & 0x00000000FF000000u) <<  8u) |      
      ((tmp & 0x0000000000FF0000u) << 24u) |
      ((tmp & 0x000000000000FF00u) << 40u) |
      ((tmp & 0x00000000000000FFu) << 56u);
    memcpy(&hostdouble, &tmp, sizeof(tmp));
    return hostdouble;
}
#endif

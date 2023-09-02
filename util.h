#pragma once

#include <stdbool.h>

#ifdef LITTLE_ENDIAN_FLOAT
double htond(double hostdouble);
static inline double ntohd(double netdouble) { return htond(netdouble); }
#elif BIG_ENDIAN_FLOAT
static inline double htond(double hostdouble) { return hostdouble; }
static inline double ntohd(double netdouble) { return netdouble; }
#else
#error "Float endianness is undefined"
#endif

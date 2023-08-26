#pragma once

#include <stdbool.h>

bool string2d(const char *str, double *d);
bool string2umax(const char *str, uintmax_t *i);

#ifdef LITTLE_ENDIAN_FLOAT
double htond(double hostdouble);
static inline double ntohd(double netdouble) { return htond(netdouble); }
#else
static inline double htond(double hostdouble) { return hostdouble; }
static inline double ntohd(double netdouble) { return netdouble; }
#endif

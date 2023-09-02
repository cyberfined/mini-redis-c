#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "util.h"

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

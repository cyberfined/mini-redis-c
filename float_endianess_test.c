#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

int main(void) {
    double x = -INFINITY;
    uint64_t xint, t = 1;
    t <<= 63;
    memcpy(&xint, &x, sizeof(x));
    if(xint & t)
        puts("-DLITTLE_ENDIAN_FLOAT");
    else
        puts("-DBIG_ENDIAN_FLOAT");
}

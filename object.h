#pragma once

#include "zset.h"
#include "bheap.h"

typedef enum {
    OBJ_STRING,
    OBJ_ZSET
} ObjectType;

typedef struct {
    ObjectType type;
    void       *ptr;
    size_t     ttl_idx;
} Object;

Object* createStringObject(char *str);
Object* createZSetObject(ZSet *zset);
void freeObject(void *obj);

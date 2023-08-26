#pragma once

#include "zset.h"

typedef enum {
    OBJ_STRING,
    OBJ_ZSET
} ObjectType;

typedef struct {
    ObjectType type;
    void       *ptr;
} Object;

Object* createStringObject(char *str);
Object* createZSetObject(ZSet *zset);
void freeObject(void *obj);

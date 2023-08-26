#include <stdio.h>
#include <stdlib.h>
#include "object.h"

Object* createStringObject(char *str) {
    Object *obj = malloc(sizeof(Object));
    if(!obj) {
        perror("createStringObject (malloc)");
        return NULL;
    }
    obj->type = OBJ_STRING;
    obj->ptr = str;
    return obj;
}

Object* createZSetObject(ZSet *zset) {
    Object *obj = malloc(sizeof(Object));
    if(!obj) {
        perror("createZSetObject (malloc)");
        return NULL;
    }
    obj->type = OBJ_ZSET;
    obj->ptr = zset;
    return obj;
}

void freeObject(void *_obj) {
    Object *obj = _obj;
    switch(obj->type) {
    case OBJ_STRING: free(obj->ptr);      break;
    case OBJ_ZSET:   zset_free(obj->ptr); break;
    }
    free(obj);
}

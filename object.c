#include <stdio.h>
#include <stdlib.h>

#include "object.h"
#include "server.h"

Object* createStringObject(char *str) {
    Object *obj = malloc(sizeof(Object));
    if(!obj) {
        perror("createStringObject (malloc)");
        return NULL;
    }
    obj->type = OBJ_STRING;
    obj->ptr = str;
    obj->ttl_idx = 0;
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
    obj->ttl_idx = 0;
    return obj;
}

void freeObject(void *_obj) {
    Object *obj = _obj;
    switch(obj->type) {
    case OBJ_STRING: free(obj->ptr);      break;
    case OBJ_ZSET:   zset_free(obj->ptr); break;
    }

    if(obj->ttl_idx)
        bheap_delete(state.ttl_heap, obj->ttl_idx - 1);

    free(obj);
}

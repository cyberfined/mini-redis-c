#include "bheap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "server.h"

#define MIN_CAPACITY 2048

#define PARENT(i)    ((i - 1) / 2)
#define IS_ROOT(i)   (i == 0)
#define LEFT(i)      ((i * 2) + 1)
#define RIGHT(i)     ((i * 2) + 2)

BHeap* bheap_new(size_t capacity) {
    uint64_t capacity64 = capacity;
    if(capacity64 < MIN_CAPACITY) {
        capacity64 = MIN_CAPACITY;
    } else if(capacity64 & (capacity64 - 1)) {
        capacity64--;
        capacity64 |= capacity64 >> 1;
        capacity64 |= capacity64 >> 2;
        capacity64 |= capacity64 >> 4;
        capacity64 |= capacity64 >> 8;
        capacity64 |= capacity64 >> 16;
        capacity64 |= capacity64 >> 32;
        capacity64++;
    }

    BHeap *bheap = malloc(sizeof(BHeap));
    if(!bheap) {
        perror("bheap_new (malloc)");
        return NULL;
    }

    bheap->elems = malloc(sizeof(BHeapElem) * capacity64);
    if(!bheap->elems) {
        perror("bheap_new (malloc)");
        free(bheap);
        return NULL;
    }

    bheap->capacity = capacity64;
    bheap->size = 0;
    return bheap;
}

void bheap_free(BHeap *bheap) {
    free(bheap->elems);
    free(bheap);
}

static inline size_t fixup_l(BHeap *bheap, size_t i) {
    BHeapElem tmp;
    while(!IS_ROOT(i)) {
        size_t p = PARENT(i);
        if(bheap->elems[i].expires_at >= bheap->elems[p].expires_at)
            break;

        memcpy(&tmp, &bheap->elems[i], sizeof(BHeapElem));
        memcpy(&bheap->elems[i], &bheap->elems[p], sizeof(BHeapElem));
        memcpy(&bheap->elems[p], &tmp, sizeof(BHeapElem));
        ((Object*)bheap->elems[i].node->value)->ttl_idx = i + 1;
        i = p;
    }
    ((Object*)bheap->elems[i].node->value)->ttl_idx = i + 1;
    return i;
}

static inline void fixup_g(BHeap *bheap, size_t p) {
    size_t next_p;
    BHeapElem tmp;
    for(;;) {
        size_t l = LEFT(p);
        size_t r = RIGHT(p);

        if(l < bheap->size) {
            uint64_t min = bheap->elems[l].expires_at;

            if(bheap->elems[p].expires_at > bheap->elems[l].expires_at)  {
                min = bheap->elems[l].expires_at;
                next_p = l;
            } else {
                min = bheap->elems[p].expires_at;
                next_p = p;
            }

            if(r < bheap->size) {
                if(min > bheap->elems[r].expires_at)
                    next_p = r;
            }

            if(next_p == p)
                break;
        } else {
            break;
        }

        memcpy(&tmp, &bheap->elems[p], sizeof(BHeapElem));
        memcpy(&bheap->elems[p], &bheap->elems[next_p], sizeof(BHeapElem));
        memcpy(&bheap->elems[next_p], &tmp, sizeof(BHeapElem));
        ((Object*)bheap->elems[p].node->value)->ttl_idx = p + 1;

        p = next_p;
    }
    ((Object*)bheap->elems[p].node->value)->ttl_idx = p + 1;
}

size_t bheap_insert(BHeap *bheap, uint64_t expires_at, HashTableNode *node) {
    if(bheap->size == bheap->capacity) {
        size_t new_capacity = bheap->capacity * 2;
        BHeapElem *new_elems = realloc(bheap->elems, sizeof(BHeapElem) * new_capacity);
        if(!new_elems) {
            perror("bheap_insert (realloc)");
            return 0;
        }
        bheap->elems = new_elems;
        bheap->capacity = new_capacity;
    }

    bheap->elems[bheap->size].expires_at = expires_at;
    bheap->elems[bheap->size].node = node;

    size_t idx = fixup_l(bheap, bheap->size);

    bheap->size++;
    return idx + 1;
}

static inline void reduce_if_needed(BHeap *bheap) {
    if(bheap->size <= bheap->capacity / 4 && bheap->capacity > MIN_CAPACITY) {
        size_t new_capacity = bheap->capacity / 2;
        BHeapElem *new_elems = realloc(bheap->elems, sizeof(BHeapElem) * new_capacity);
        if(new_elems) {
            bheap->elems = new_elems;
            bheap->capacity = new_capacity;
        } else {
            perror("bheap_extract_min (realloc)");
        }
    }
}

bool bheap_extract_min(BHeap *bheap, BHeapElem *elem) {
    if(bheap->size == 0)
        return false;

    memcpy(elem, &bheap->elems[0], sizeof(BHeapElem));
    ((Object*)elem->node->value)->ttl_idx = 0;
    
    bheap->size--;
    if(bheap->size == 0)
        return true;

    memcpy(&bheap->elems[0], &bheap->elems[bheap->size], sizeof(BHeapElem));
    fixup_g(bheap, 0);
    reduce_if_needed(bheap);

    return true;
}

void bheap_change_expires_at(BHeap *bheap, size_t idx, uint64_t expires_at) {
    BHeapElem *elem = &bheap->elems[idx];
    uint64_t prev_expires_at = elem->expires_at;
    elem->expires_at = expires_at;

    if(elem->expires_at < prev_expires_at)
        fixup_l(bheap, idx);
    else
        fixup_g(bheap, idx);
}

void bheap_delete(BHeap *bheap, size_t idx) {
    BHeapElem *elem = &bheap->elems[idx];
    bheap->size--;
    ((Object*)elem->node->value)->ttl_idx = 0;
    if(bheap->size == idx)
        return;

    uint64_t prev_expires_at = elem->expires_at;
    memcpy(elem, &bheap->elems[bheap->size], sizeof(BHeapElem));
    if(elem->expires_at < prev_expires_at)
        fixup_l(bheap, idx);
    else
        fixup_g(bheap, idx);
    reduce_if_needed(bheap);
}

// EXPIRE key seconds
void expire_handler(void) {
    CmdArgState arg_state = INIT_CMD_ARG_STATE;
    char *key;
    if(!next_string_arg(&arg_state, &key))
        return;

    HashTableNode *node = lookup_key(state.keys, key);
    uint32_t seconds;
    if(!next_int_arg(&arg_state, &seconds)) {
        cmd_restore(&arg_state);
        return;
    }

    uint32_t result;
    if(!node) {
        result = 0;
    } else if(seconds > 0) {
        mstime expires_at = state.cmd_start_time + seconds * 1000;
        Object *obj = node->value;

        if(obj->ttl_idx) {
            bheap_change_expires_at(state.ttl_heap, obj->ttl_idx - 1, expires_at);
            result = 1;
        } else {
            bheap_insert(state.ttl_heap, expires_at, node);
            if(obj->ttl_idx) {
                result = 1;
            } else {
                result = 0;
            }
        }
    } else {
        hash_table_remove(state.keys, node);
        result = 1;
    }
    send_uint(result);
}

// TTL key
void ttl_handler(void) {
    CmdArgState arg_state = INIT_CMD_ARG_STATE;
    char *key;
    if(!next_string_arg(&arg_state, &key))
        return;

    HashTableNode *node = lookup_key(state.keys, key);
    cmd_restore(&arg_state);

    if(!node) {
        send_int(-2);
        return;
    }

    Object *obj = node->value;
    if(!obj->ttl_idx) {
        send_int(-1);
        return;
    }

    uint64_t expires_at = state.ttl_heap->elems[obj->ttl_idx - 1].expires_at;
    send_int((expires_at - state.cmd_start_time) / 1000);
}

// PERSIST handler
void persist_handler(void) {
    CmdArgState arg_state = INIT_CMD_ARG_STATE;
    char *key;
    if(!next_string_arg(&arg_state, &key))
        return;

    HashTableNode *node = lookup_key(state.keys, key);
    cmd_restore(&arg_state);

    uint32_t result;
    if(!node) {
        result = 0;
    } else {
        Object *obj = node->value;
        if(!obj->ttl_idx) {
            result = 0;
        } else {
            bheap_delete(state.ttl_heap, obj->ttl_idx - 1);
            result = 1;
        }
    }

    send_uint(result);
}

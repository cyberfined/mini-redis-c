#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "hashtable.h"

typedef struct BHeapElem {
    uint64_t      expires_at;
    HashTableNode *node;
} BHeapElem;

typedef struct {
    BHeapElem *elems;
    size_t    capacity;
    size_t    size;
} BHeap;

BHeap* bheap_new(size_t capacity);
void bheap_free(BHeap *bheap);
static inline BHeapElem* bheap_peek_min(BHeap *bheap) {
    return bheap->size > 0 ? bheap->elems : NULL;
}

size_t bheap_insert(BHeap *bheap, uint64_t expires_at, HashTableNode *node);
bool bheap_extract_min(BHeap *bheap, BHeapElem *elem);
void bheap_change_expires_at(BHeap *bheap, size_t idx, uint64_t expires_at);
void bheap_delete(BHeap *bheap, size_t idx);

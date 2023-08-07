#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct HashTableNode {
    char                 *key;
    void                 *value;
    uint32_t             hash;
    struct HashTableNode *next;
    struct HashTableNode *prev;
} HashTableNode;

typedef void (*hash_table_key_free_func)(void*);
typedef void (*hash_table_value_free_func)(void*);

typedef struct {
    HashTableNode              **buckets;
    size_t                     size;
    size_t                     capacity;
    int                        capacity_index;
    hash_table_key_free_func   key_free_func;
    hash_table_value_free_func value_free_func;
} HashTable;

typedef struct {
    HashTableNode *node;
    HashTable     *htable;
    size_t        bucket;
} HashTableIterator;

HashTable* hash_table_new(
    hash_table_key_free_func key_free_func,
    hash_table_value_free_func value_free_func,
    size_t capacity
);
void hash_table_free(HashTable *htable);
HashTableIterator hash_table_begin(HashTable *htable);
__attribute__((always_inline))
static inline bool hash_table_has_next(HashTableIterator *it) {
    return it->node != NULL;
}
void hash_table_next(HashTableIterator *it);
HashTableNode* hash_table_get(HashTable *htable, char *key);
HashTableNode* hash_table_set(HashTable *htable, char *key, void *value);
void hash_table_remove(HashTable *htable, HashTableNode *node);

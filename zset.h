#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "hashtable.h"

typedef struct AvlNode {
    struct AvlNode *parent;
    struct AvlNode *left;
    struct AvlNode *right;
    int8_t         bfactor;
    double         key;
    HashTableNode  *node;
    void           *value;
} AvlNode;

typedef struct {
    AvlNode *root;
    size_t  size;
} AvlTree;

AvlTree* avl_new(void);
void avl_free(AvlTree *tree);
AvlNode* avl_insert(AvlTree *tree, double key, void *value);
AvlNode* avl_find(AvlTree *tree, double key);
void avl_remove(AvlTree *tree, AvlNode *node);

typedef struct {
    AvlTree   *tree;
    HashTable *htable;
} ZSet;

typedef bool(*zset_iter_func)(AvlNode*, void*);

ZSet* zset_new(hash_table_key_free_func value_free_func);
void zset_free(ZSet *zset);
AvlNode* zset_add(ZSet *zset, double score, char *value);
AvlNode* zset_find(ZSet *zset, char *value);
void zset_range(
    ZSet *zset,
    double min,
    double max,
    size_t offset,
    zset_iter_func iter_func,
    void *arg
);
void zset_remove(ZSet *zset, AvlNode *node);

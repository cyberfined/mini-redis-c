#include "hashtable.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM_CAPACITIES 29
size_t capacities[NUM_CAPACITIES] = {
    11, 23, 47, 97, 197, 397, 797, 1597, 3203, 6421,
    12853, 25717, 51437, 102877, 205759, 411527, 823117, 1646237, 3292489, 6584983,
    13169977, 26339969, 52679969, 210719881, 421439783, 842879579, 1685759167,
    3371518343, 4294967291
};

HashTable* hash_table_new(
    hash_table_key_free_func key_free_func,
    hash_table_value_free_func value_free_func,
    size_t capacity
) {
    HashTable *htable = malloc(sizeof(HashTable));
    if(!htable) {
        perror("hash_table_new (malloc)");
        return NULL;
    }

    if(capacity > 0) {
        int capacity_index;
        for(capacity_index = 0; capacity_index < NUM_CAPACITIES; capacity_index++) {
            if(capacities[capacity_index] >= capacity)
                break;
        }

        if(capacity_index >= NUM_CAPACITIES) {
            fprintf(
                stderr,
                "hash_table_new: capacity %lu is too big, "
                "max supported capacity is %lu\n",
                capacity,
                capacities[NUM_CAPACITIES - 1]
            );
            free(htable);
            return NULL;
        }

        capacity = capacities[capacity_index];
        htable->buckets = calloc(capacity, sizeof(HashTableNode*));
        if(!htable->buckets) {
            perror("hash_table_new (calloc)");
            free(htable);
            return NULL;
        }
        htable->capacity = capacity;
        htable->capacity_index = capacity_index;
    } else {
        htable->buckets = NULL;
        htable->capacity = 0;
        htable->capacity_index = -1;
    }

    htable->size = 0;
    htable->key_free_func = key_free_func;
    htable->value_free_func = value_free_func;

    return htable;
}

HashTableIterator hash_table_begin(HashTable *htable) {
    if(htable->size > 0) {
        for(size_t i = 0; i < htable->capacity; i++) {
            if(htable->buckets[i]) {
                return (HashTableIterator) {
                    .node   = htable->buckets[i],
                    .htable = htable,
                    .bucket = i,
                };
            }
        }
    }

    return (HashTableIterator) { .node = NULL };
}

__attribute__((always_inline))
static inline void node_free(HashTable *htable, HashTableNode *node) {
    if(htable->key_free_func)
        htable->key_free_func(node->key);
    if(htable->value_free_func)
        htable->value_free_func(node->value);
    free(node);
}

void hash_table_free(HashTable *htable) {
    for(size_t i = 0; i < htable->capacity; i++) {
        HashTableNode *node = htable->buckets[i];
        while(node) {
            HashTableNode *next = node->next;
            node_free(htable, node);
            node = next;
        }
    }
    free(htable->buckets);
    free(htable);
}

void hash_table_next(HashTableIterator *it) {
    if(it->node->next) {
        it->node = it->node->next;
    } else {
        it->node = NULL;
        size_t max_bucket = it->htable->capacity - 1;
        while(it->bucket < max_bucket) {
            it->bucket++;
            it->node = it->htable->buckets[it->bucket];
            if(it->node)
                break;
        }
    }
}

static uint32_t jenkins_hash(const void *_key, size_t length) {
    size_t i = 0;
    uint32_t hash = 0;
    const uint8_t *key = _key;
    while(i != length) {
        hash += key[i++];
        hash += hash << 10;
        hash ^= hash >> 6;
    }
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;
    return hash;
}

HashTableNode* hash_table_get(HashTable *htable, char *key) {
    if(htable->size == 0)
        return NULL;
    
    uint32_t hash = jenkins_hash(key, strlen(key));
    size_t bucket = hash % htable->capacity;

    for(HashTableNode *node = htable->buckets[bucket]; node != NULL; node = node->next) {
        if(node->hash == hash && !strcmp(node->key, key))
            return node;
    }

    return NULL;
}

__attribute__((always_inline))
static inline void remove_node(HashTable *htable, HashTableNode *node, size_t bucket) {
    if(!node->prev)
        htable->buckets[bucket] = node->next;
    else
        node->prev->next = node->next;
    if(node->next)
        node->next->prev = node->prev;
}

__attribute__((always_inline))
static inline void insert_node(HashTable *htable, HashTableNode *node, size_t bucket) {
    node->prev = NULL;
    node->next = htable->buckets[bucket];
    if(node->next)
        node->next->prev = node;
    htable->buckets[bucket] = node;
}

static void rehash(HashTable *htable, int next_capacity_index) {
    size_t current_capacity = htable->capacity;
    size_t next_capacity = 0;

    if(next_capacity_index > htable->capacity_index) {
        if(htable->capacity_index + 1 == NUM_CAPACITIES)
            return;

        next_capacity = capacities[next_capacity_index];
        HashTableNode **new_buckets = realloc(
            htable->buckets,
            next_capacity * sizeof(HashTableNode**)
        );
        if(!new_buckets) {
            perror("hash_table_rehash (realloc)");
            return;
        }
        htable->buckets = new_buckets;
        memset(
            &htable->buckets[current_capacity],
            0,
            (next_capacity - current_capacity) * sizeof(HashTableNode*)
        );
    } else {
        next_capacity = capacities[next_capacity_index];
    }

    for(size_t i = 0; i < current_capacity; i++) {
        HashTableNode *node = htable->buckets[i];
        while(node) {
            size_t new_bucket = node->hash % next_capacity;
            HashTableNode *next = node->next;
            if(new_bucket != i) {
                remove_node(htable, node, i);
                insert_node(htable, node, new_bucket);
            }
            node = next;
        }
    }

    if(next_capacity_index < htable->capacity_index) {
        HashTableNode **new_buckets = realloc(
            htable->buckets,
            next_capacity * sizeof(HashTableNode*)
        );
        if(!new_buckets) {
            perror("hash_table_rehash (realloc)");
            htable->capacity_index = next_capacity_index;
            htable->capacity = next_capacity;
            return;
        }
        htable->buckets = new_buckets;
    }

    htable->capacity_index = next_capacity_index;
    htable->capacity = next_capacity;
}

HashTableNode* hash_table_set(HashTable *htable, char *key, void *value) {
    if(htable->capacity_index < 0) {
        htable->capacity_index = 0;
        htable->capacity = capacities[0];
        htable->buckets = calloc(htable->capacity, sizeof(HashTableNode*));
        if(!htable->buckets) {
            perror("hash_table_set (calloc)");
            return NULL;
        }
    }

    uint32_t hash = jenkins_hash(key, strlen(key));
    size_t bucket = hash % htable->capacity;

    HashTableNode *last = NULL;
    for(HashTableNode *node = htable->buckets[bucket]; node != NULL; node = node->next) {
        if(node->hash == hash && !strcmp(node->key, key)) {
            if(htable->key_free_func)
                htable->key_free_func(key);
            if(htable->value_free_func)
                htable->value_free_func(node->value);
            node->value = value;
            return node;
        }
        last = node;
    }

    HashTableNode *new_node = malloc(sizeof(HashTableNode));
    if(!new_node) {
        perror("hash_table_set (malloc)");
        return NULL;
    }
    new_node->key = key;
    new_node->value = value;
    new_node->hash = hash;
    new_node->next = NULL;
    new_node->prev = last;

    if(!last)
        htable->buckets[bucket] = new_node;
    else
        last->next = new_node;

    if(htable->size == htable->capacity)
        rehash(htable, htable->capacity_index + 1);

    htable->size++;
    return new_node;
}

void hash_table_remove(HashTable *htable, HashTableNode *node) {
    size_t bucket = node->hash % htable->capacity;
    remove_node(htable, node, bucket);
    node_free(htable, node);
    htable->size--;

    if(htable->capacity_index > 0 &&
       htable->size <= capacities[htable->capacity_index - 1] / 2)
    {
        rehash(htable, htable->capacity_index - 1);
    }
}

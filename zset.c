#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "server.h"
#include "util.h"

#include "zset.h"

#define Nil                (&nil)
#define ZSET_HASH_MIN_SIZE 11

static AvlNode nil = {NULL, NULL, NULL, 0, 0, NULL};

__attribute__((always_inline))
static inline bool is_root(AvlTree *tree, AvlNode *node) {
    return tree->root == node;
}

__attribute__((always_inline))
static inline bool is_left(AvlNode *node) {
    return node->parent->left == node;
}

__attribute__((always_inline))
static inline bool is_nil(AvlNode *node) {
    return node == Nil;
}

static inline AvlNode* rotate_left(AvlTree *tree, AvlNode *node) {
    AvlNode *r = node->right;
    if(is_root(tree, node))
        tree->root = r;
    else if(is_left(node))
        node->parent->left = r;
    else
        node->parent->right = r;
    r->parent = node->parent;
    node->right = r->left;
    r->left->parent = node;
    r->left = node;
    node->parent = r;
    return r;
}

static inline AvlNode* rotate_right(AvlTree *tree, AvlNode *node) {
    AvlNode *l = node->left;
    if(is_root(tree, node))
        tree->root = l;
    else if(is_left(node))
        node->parent->left = l;
    else
        node->parent->right = l;
    l->parent = node->parent;
    node->left = l->right;
    l->right->parent = node;
    l->right = node;
    node->parent = l;
    return l;
}

AvlTree* avl_new(void) {
    AvlTree *tree = malloc(sizeof(AvlTree));
    if(!tree) {
        perror("avl_new (malloc)");
        return NULL;
    }
    tree->root = Nil;
    tree->size = 0;
    return tree;
}

static void avl_node_free(AvlNode *node) {
    if(!is_nil(node->left))
        avl_node_free(node->left);

    if(!is_nil(node->right))
        avl_node_free(node->right);

    free(node);
}

void avl_free(AvlTree *tree) {
    if(!is_nil(tree->root))
        avl_node_free(tree->root);
    free(tree);
}

static inline void insert_fixup(AvlTree *tree, AvlNode *node) {
    while(!is_root(tree, node)) {
        bool is_l = is_left(node);
        node = node->parent;
        if(is_l) {
            node->bfactor++;
            if(node->bfactor == 2) {
                if(node->left->bfactor < 0) {
                    rotate_left(tree, node->left);
                    node = rotate_right(tree, node);
                    node->left->bfactor = node->bfactor < 0 ? 1 : 0;
                    node->right->bfactor = node->bfactor > 0 ? -1 : 0;
                } else {
                    node = rotate_right(tree, node);
                    node->right->bfactor = 0;
                }
                node->bfactor = 0;
                break;
            }
        } else {
            node->bfactor--;
            if(node->bfactor == -2) {
                if(node->right->bfactor > 0) {
                    rotate_right(tree, node->right);
                    node = rotate_left(tree, node);
                    node->left->bfactor = node->bfactor < 0 ? 1 : 0;
                    node->right->bfactor = node->bfactor > 0 ? -1 : 0;
                } else {
                    node = rotate_left(tree, node);
                    node->left->bfactor = 0;
                }
                node->bfactor = 0;
                break;
            }
        }

        if(node->bfactor == 0)
            break;
    }
}

AvlNode* avl_insert(AvlTree *tree, double key, void *value) {
    AvlNode **place = &tree->root;
    AvlNode *i = tree->root;
    AvlNode *p = Nil;
    while(!is_nil(i)) {
        p = i;
        if(i->key > key || (i->key == key && i->value > value)) {
            place = &i->left;
            i = i->left;
        } else if(i->key < key || (i->key == key && i->value < value)) {
            place = &i->right;
            i = i->right;
        } else {
            return i;
        }
    }

    AvlNode *new_node = malloc(sizeof(AvlNode));
    if(!new_node) {
        perror("avl_insert (malloc)");
        return NULL;
    }
    new_node->parent = p;
    new_node->left = Nil;
    new_node->right = Nil;
    new_node->bfactor = 0;
    new_node->key = key;
    new_node->value = value;
    *place = new_node;
    insert_fixup(tree, new_node);

    tree->size++;
    return new_node;
}

AvlNode* avl_find(AvlTree *tree, double key) {
    AvlNode *node = tree->root;
    while(!is_nil(node)) {
        if(node->key > key) {
            node = node->left;
        } else if(node->key < key) {
            node = node->right;
        } else {
            return node;
        }
    }
    return NULL;
}

static inline void remove_fixup(AvlTree *tree, AvlNode *node) {
    for(;;) {
        if(node->bfactor == -2) {
            if(node->right->bfactor > 0) {
                rotate_right(tree, node->right);
                node = rotate_left(tree, node);
                node->left->bfactor = node->bfactor < 0 ? 1 : 0;
                node->right->bfactor = node->bfactor > 0 ? -1 : 0;
                node->bfactor = 0;
            } else {
                node = rotate_left(tree, node);
                node->bfactor = node->bfactor == 0 ? 1 : 0;
                node->left->bfactor = -node->bfactor;
            }
        } else if(node->bfactor == 2) {
            if(node->left->bfactor < 0) {
                rotate_left(tree, node->left);
                node = rotate_right(tree, node);
                node->left->bfactor = node->bfactor < 0 ? 1 : 0;
                node->right->bfactor = node->bfactor > 0 ? -1 : 0;
                node->bfactor = 0;
            } else {
                node = rotate_right(tree, node);
                node->bfactor = node->bfactor == 0 ? -1 : 0;
                node->right->bfactor = -node->bfactor;
            }
        } else if(node->bfactor == 0 && !is_root(tree, node)) {
            if(is_left(node))
                node->parent->bfactor--;
            else
                node->parent->bfactor++;
            node = node->parent;
        } else {
            break;
        }
    }
}

void avl_remove(AvlTree *tree, AvlNode *node) {
    AvlNode *replace, *fixup_node;
    if(is_nil(node->left)) {
        replace = node->right;
        fixup_node = node->parent;
    } else if(is_nil(node->right)) {
        replace = node->left;
        fixup_node = node->parent;
    } else {
        for(replace = node->right; !is_nil(replace->left); replace = replace->left);

        replace->bfactor = node->bfactor;
        replace->left = node->left;
        replace->left->parent = replace;
        if(replace != node->right) {
            replace->parent->bfactor--;
            replace->parent->left = replace->right;
            replace->right->parent = replace->parent;
            replace->right = node->right;
            replace->right->parent = replace;
            fixup_node = replace->parent;
        } else {
            replace->bfactor++;
            fixup_node = replace;
        }
    }

    if(is_root(tree, node)) {
        tree->root = replace;
    } else {
        if(is_left(node)) {
            if(fixup_node == node->parent)
                fixup_node->bfactor--;
            node->parent->left = replace;
        } else {
            if(fixup_node == node->parent)
                fixup_node->bfactor++;
            node->parent->right = replace;
        }
    }

    replace->parent = node->parent;
    free(node);

    if(!is_nil(fixup_node))
        remove_fixup(tree, fixup_node);
    tree->size--;
}

ZSet* zset_new(hash_table_key_free_func value_free_func) {
    ZSet *zset = calloc(1, sizeof(ZSet));
    if(!zset) {
        perror("zset_new (calloc)");
        goto error;
    }

    zset->tree = avl_new();
    if(!zset->tree)
        goto error;

    zset->htable = hash_table_new(value_free_func, NULL, ZSET_HASH_MIN_SIZE);
    if(!zset->htable)
        goto error;

    return zset;
error:
    if(zset) {
        if(zset->tree) avl_free(zset->tree);
        free(zset);
    }
    return NULL;
}

void zset_free(ZSet *zset) {
    avl_free(zset->tree);
    hash_table_free(zset->htable);
    free(zset);
}

AvlNode* zset_add(ZSet *zset, double score, char *value) {
    HashTableNode *h_node = hash_table_get(zset->htable, value);
    if(!h_node) {
        h_node = hash_table_set(zset->htable, value, NULL);
        if(!h_node)
            return NULL;
    }

    if(h_node->value != NULL) {
        if(zset->htable->key_free_func)
            zset->htable->key_free_func(value);
        avl_remove(zset->tree, h_node->value);
    }

    AvlNode *t_node = avl_insert(zset->tree, score, h_node);
    if(!t_node) {
        hash_table_remove(zset->htable, h_node);
        return NULL;
    }

    h_node->value = t_node;

    return t_node;
}

AvlNode* zset_find(ZSet *zset, char *value) {
    HashTableNode *h_node = hash_table_get(zset->htable, value);
    if(!h_node)
        return NULL;

    return (AvlNode*)h_node->value;
}

static size_t avl_node_range(
    AvlNode *node,
    double min,
    double max,
    size_t offset,
    size_t cur_offset,
    bool *should_continue,
    zset_iter_func iter_func,
    void *arg
) {
    if(node->key >= min && !is_nil(node->left)) {
        cur_offset = avl_node_range(
            node->left,
            min,
            max,
            offset,
            cur_offset,
            should_continue,
            iter_func,
            arg
        );
    }

    if(!*should_continue)
        return cur_offset;

    if(min <= node->key && node->key <= max) {
        if(cur_offset >= offset) {
            if(!iter_func(node, arg)) {
                *should_continue = false;
                return cur_offset;
            }
        }
        cur_offset++;
    }

    if(node->key <= max && !is_nil(node->right)) {
        cur_offset = avl_node_range(
            node->right,
            min,
            max,
            offset,
            cur_offset,
            should_continue,
            iter_func,
            arg
        );
    }

    return cur_offset;
}

void zset_range(
    ZSet *zset,
    double min,
    double max,
    size_t offset,
    zset_iter_func iter_func,
    void *arg
) {
    if(zset->tree->size == 0)
        return;

    bool should_continue = true;
    avl_node_range(
        zset->tree->root,
        min,
        max,
        offset,
        0,
        &should_continue,
        iter_func,
        arg
    );
}

void zset_remove(ZSet *zset, AvlNode *node) {
    hash_table_remove(zset->htable, (HashTableNode*)node->value);
    avl_remove(zset->tree, node);
}

// ZADD key score member
void zadd_handler(void) {
    CmdArgState arg_state = INIT_CMD_ARG_STATE;
    char *key = NULL, *member = NULL;
    ZSet *zset = NULL;
    bool should_send_error = true;
    bool zset_exists = false;

    if(!next_string_arg(&arg_state, &key)) {
        should_send_error = false;
        goto error;
    }

    if(!get_zset_by_key(state.keys, key, &zset)) {
        should_send_error = false;
        goto error;
    }

    if(!zset) {
        key = strdup(key);
        if(!key)
            goto error;

        zset = zset_new(free);
        if(!zset)
            goto error;
    } else {
        zset_exists = true;
    }

    double score;
    if(!next_double_arg(&arg_state, &score)) {
        should_send_error = false;
        goto error;
    }

    if(!next_string_arg(&arg_state, &member)) {
        should_send_error = false;
        goto error;
    }
    member = strdup(member);
    if(!member)
        goto error;

    if(!zset_add(zset, score, member)) {
        free(member);
        member = NULL;
        goto error;
    }

    if(!zset_exists) {
        Object *value_obj = createZSetObject(zset);
        if(!value_obj)
            goto error;

        if(!hash_table_set(state.keys, key, value_obj)) {
            free(value_obj);
            goto error;
        }
    }
    cmd_restore(&arg_state);
    send_nil();
    return;

error:
    if(!zset_exists) {
        if(zset) {
            if(key) free(key);
            zset_free(zset);
        }
        else if(member)
            free(member);
    }
    cmd_restore(&arg_state);
    if(should_send_error)
        send_err(ERR_OUT_OF_MEMORY);
}

typedef struct {
    size_t count;
    size_t max_count;
    bool   is_error;
} RangeIter;

static bool zrange_iter(AvlNode *a_node, void *arg) {
    RangeIter *iter = arg;
    HashTableNode *h_node = a_node->value;
    size_t len = strlen(h_node->key);
    if(!send_str(h_node->key, len)) {
        iter->is_error = true;
        return false;
    }
    iter->count++;
    return true;
}

static bool zrange_iter_with_scores(AvlNode *a_node, void *arg) {
    RangeIter *iter = arg;
    HashTableNode *h_node = a_node->value;
    size_t len = strlen(h_node->key);
    if(!send_str(h_node->key, len)) {
        iter->is_error = true;
        return false;
    }
    if(!send_double(a_node->key)) {
        iter->is_error = true;
        return false;
    }
    iter->count++;
    return true;
}

static bool zrange_iter_count(AvlNode *a_node, void *arg) {
    RangeIter *iter = arg;
    if(iter->count + 1 > iter->max_count)
        return false;

    HashTableNode *h_node = a_node->value;
    size_t len = strlen(h_node->key);
    if(!send_str(h_node->key, len)) {
        iter->is_error = true;
        return false;
    }
    iter->count++;
    return true;
}

static bool zrange_iter_count_with_scores(AvlNode *a_node, void *arg) {
    RangeIter *iter = arg;
    if(iter->count + 1 > iter->max_count)
        return false;

    HashTableNode *h_node = a_node->value;
    size_t len = strlen(h_node->key);
    if(!send_str(h_node->key, len)) {
        iter->is_error = true;
        return false;
    }
    if(!send_double(a_node->key)) {
        iter->is_error = true;
        return false;
    }
    iter->count++;
    return true;
}

// ZRANGE key start end [offset count] [WITHSCORES]
void zrange_handler(void) {
    Conn *conn = state.current_client;
    CmdArgState arg_state = INIT_CMD_ARG_STATE;
    char *key = NULL;
    ZSet *zset = NULL;
    bool with_scores = false;

    if(!next_string_arg(&arg_state, &key))
        goto end;

    if(!get_zset_by_key(state.keys, key, &zset))
        goto end;

    if(!zset) {
        if(!send_arr())
            goto end;
        end_arr(0);
        goto end;
    }

    double start, end;
    if(!next_double_arg(&arg_state, &start))
        goto end;
    if(!next_double_arg(&arg_state, &end))
        goto end;

    uint32_t offset = 0;
    zset_iter_func iter_func;
    RangeIter iter = (RangeIter) { .count = 0, .max_count = 0, .is_error = false };
    if(conn->read_tokens == 5) {
        char *with_str;
        if(!next_string_arg(&arg_state, &with_str))
            goto end;
        if(strcmp(with_str, "WITHSCORES") != 0) {
            send_err(ERR_ARITY);
            goto end;
        }

        with_scores = true;
        iter_func = zrange_iter_with_scores;
    } else if(conn->read_tokens > 5) {
        if(!next_int_arg(&arg_state, &offset))
            goto end;

        uint32_t max_count;
        if(!next_int_arg(&arg_state, &max_count))
            goto end;

        iter.max_count = max_count;

        if(conn->read_tokens == 6) {
            iter_func = zrange_iter_count;
        } else {
            char *with_str;
            if(!next_string_arg(&arg_state, &with_str))
                goto end;
            if(strcmp(with_str, "WITHSCORES") != 0) {
                send_err(ERR_ARITY);
                goto end;
            }
            with_scores = true;
            iter_func = zrange_iter_count_with_scores;
        }
    } else {
        iter_func = zrange_iter;
    }

    if(!send_arr())
        goto end;

    zset_range(zset, start, end, offset, iter_func, &iter);

    if(!iter.is_error) {
        if(with_scores)
            iter.count *= 2;
        end_arr(iter.count);
    }

end:
    cmd_restore(&arg_state);
}

// ZREM key member
void zrem_handler(void) {
    CmdArgState arg_state = INIT_CMD_ARG_STATE;
    ZSet *zset = NULL;
    uint32_t result;
    char *key, *member;

    if(!next_string_arg(&arg_state, &key))
        goto end;

    if(!get_zset_by_key(state.keys, key, &zset))
        goto end;

    if(!zset) {
        result = 0;
    } else {
        if(!next_string_arg(&arg_state, &member))
            goto end;
        AvlNode *a_node = zset_find(zset, member);
        if(!a_node) {
            result = 0;
        } else {
            zset_remove(zset, a_node);
            result = 1;
        }
    }

    send_uint(result);
end:
    cmd_restore(&arg_state);
}

// ZCARD key
void zcard_handler(void) {
    CmdArgState arg_state = INIT_CMD_ARG_STATE;
    char *key;
    ZSet *zset = NULL;
    uint32_t result;

    if(!next_string_arg(&arg_state, &key))
        goto end;

    if(!get_zset_by_key(state.keys, key, &zset))
        goto end;

    if(!zset) {
        result = 0;
    } else {
        result = zset->tree->size;
    }

    send_uint(result);
end:
    cmd_restore(&arg_state);
}

// ZSCORE key member
void zscore_handler(void) {
    CmdArgState arg_state = INIT_CMD_ARG_STATE;
    char *key, *member;
    ZSet *zset = NULL;

    if(!next_string_arg(&arg_state, &key))
        goto end;

    if(!get_zset_by_key(state.keys, key, &zset))
        goto end;

    if(!zset) {
        send_nil();
        goto end;
    }

    if(!next_string_arg(&arg_state, &member))
        goto end;

    AvlNode *a_node = zset_find(zset, member);
    if(!a_node)
        send_nil();
    else
        send_double(a_node->key);
end:
    cmd_restore(&arg_state);
}

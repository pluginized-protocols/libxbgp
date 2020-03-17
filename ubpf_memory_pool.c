//
// Created by thomas on 12/03/20.
//

#include "ubpf_memory_pool.h"
#include "list.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

enum {
    MEMPOOL_TYPE_U64,
    MEMPOOL_TYPE_RAW_PTR,
    MEMPOOL_TYPE_PTR,
    MEMPOOL_TYPE_LST
};

static inline void delete_mem_node(void *_mn) {
    list_iterator_t lst_it;
    struct mem_node *mn = _mn;

    if (mn->is_lst) {
        if (mn->clean) {
            list_iterator(mn->value.lst, &lst_it);
            while (iterator_end(&lst_it)) { // free resources allocated inside the pointer
                mn->clean(iterator_get(&lst_it));
            }
        }
        destroy_list(mn->value.lst);
    } else if (mn->length > 8) {
        if (mn->clean) mn->clean(mn->value.ptr);
        free(mn->value.ptr);
    }
}

struct mem_pool *new_mempool() {

    struct mem_pool *mp;
    mp = calloc(1, sizeof(*mp));

    if (!mp) return NULL;

    if (hashmap_new(&mp->mp, sizeof(struct mem_node)) != 0) return NULL;
    return mp;
}

static int init_memnode_list(struct mem_node *node, uint32_t type, uint32_t length) {
    if (!node) return -1;

    node->type = type;
    // if it is a list, the length value correspond to the value type inserted in the list
    node->length = length;
    node->value.lst = init_list(length);

    if (!node->value.lst) return -1;
    return 0;
}

int add_lst_mempool(struct mem_pool *mp, uint32_t type, void (*cleanup)(void *),
                    uint32_t length, void *val) {
    return add_mempool(mp, type, cleanup, length, val, MEMPOOL_TYPE_LST);
}

int add_single_mempool(struct mem_pool *mp, uint32_t type, void (*cleanup)(void *),
                       uint32_t length, void *val) {
    return add_mempool(mp, type, cleanup, length, val, length > 8 ? MEMPOOL_TYPE_PTR : MEMPOOL_TYPE_U64);
}

int add_raw_ptr_mempool(struct mem_pool *mp, uint32_t type, void (*cleanup)(void *), void *val) {
    return add_mempool(mp, type, cleanup, sizeof(uintptr_t), val, MEMPOOL_TYPE_RAW_PTR);
}

inline int add_mempool(struct mem_pool *mp, uint32_t type, void (*cleanup)(void *),
                       uint32_t length, void *val, int type_mem) {

    struct mem_node new_mem, *current_mem_node;
    memset(&new_mem, 0, sizeof(struct mem_node));

    new_mem.type = type;
    new_mem.length = length;
    new_mem.clean = cleanup;
    current_mem_node = hashmap_get(&mp->mp, type);

    switch (type_mem) {
        case MEMPOOL_TYPE_U64:
            new_mem.clean = NULL; // this is not a pointer. But only a single value
            // if mn->clean is not null, re-put to NULL
            memcpy(&new_mem.value.val, val, length);
            break;
        case MEMPOOL_TYPE_PTR:
            new_mem.value.ptr = malloc(length);
            if (!new_mem.value.ptr) return -1;
            memcpy(new_mem.value.ptr, val, length);
            break;
        case MEMPOOL_TYPE_RAW_PTR:
            new_mem.value.ptr = val;
            break;
        case MEMPOOL_TYPE_LST:
            if (current_mem_node == NULL) {
                // multiple value whose list has not yet been initialized
                if (init_memnode_list(&new_mem, type, length) != 0) return -1;
                if (push(new_mem.value.lst, val)) return -1;
            } else if (push(current_mem_node->value.lst, val) == -1) {
                // multiple value whose list has already been initialized
                // if the insertion fails, then this is an error.
                return -1;
            }
            break;
        default:
            return -1;
    }

    if (current_mem_node == NULL) { // if NULL, put the new mem_node in the mem_pool
        if (hashmap_put(&mp->mp, type, new_mem) == -1) goto err;
    } else if (type_mem != MEMPOOL_TYPE_LST) {
        // if not NULL and it is not list based then you try to override.
        // This is considered as an error
        goto err;
    }

    return 0;

    err:
    if (type_mem == MEMPOOL_TYPE_PTR) free(new_mem.value.ptr);
    else if (type_mem == MEMPOOL_TYPE_LST) destroy_list(new_mem.value.lst);
    return -1;
}

void *get_mempool_ptr(struct mem_pool *mp, uint32_t type) {
    struct mem_node *node;
    if (!mp) return NULL;
    node = hashmap_get(&mp->mp, type);
    if (!node) return NULL;

    // if the size don't match with the one of a pointer OR it is a list --> return NULL
    return node->length < sizeof(uintptr_t) || node->is_lst ? NULL : node->value.ptr;
}

uint64_t get_mempool_u64(struct mem_pool *mp, uint32_t type) {
    struct mem_node *node;

    if (!mp) return 0;
    node = hashmap_get(&mp->mp, type);
    if (!node) return 0;

    return node->length <= 8 && !node->is_lst ? node->value.val : 0;
}

void remove_mempool(struct mem_pool *mp, uint32_t type) { // TODO del fun
    struct mem_node *pool;
    pool = hashmap_get(&mp->mp, type);
    if (!pool) return;
    if (pool->length > 8) free(pool->value.ptr);

    delete_mem_node(pool);
    hashmap_delete(&mp->mp, type);
}

void delete_mempool(struct mem_pool *mp) {
    if (!mp) return;
    hashmap_destroy_free(&mp->mp, delete_mem_node);
}

struct mempool_iterator *new_iterator_mempool(struct mem_pool *mp, uint32_t type) {

    struct mempool_iterator *it;
    struct mem_node *node;
    if (!mp) return NULL;

    node = hashmap_get(&mp->mp, type);
    if (!node) return NULL;
    if (!node->is_lst) return NULL;

    it = malloc(sizeof(*it));
    if (!it) return NULL;

    if (list_iterator(node->value.lst, &it->lst_it) == -1) return NULL;

    it->mn = node;

    return it;
}

void *get_mempool_iterator(struct mempool_iterator *it) {
    if (!it) return NULL;

    return iterator_get(&it->lst_it);
}

void *next_mempool_iterator(struct mempool_iterator *it) {
    if (!it) return NULL;

    return iterator_next(&it->lst_it);
}

int end_mempool_iterator(struct mempool_iterator *it) {
    if (!it) return 1;

    return iterator_end(&it->lst_it);
}

int remove_mempool_iterator(struct mempool_iterator *it) {
    if (!it) return 0;

    return iterator_remove(&it->lst_it);
}


void destroy_mempool_iterator(struct mempool_iterator *it) {
    if (!it) return;
    free(it);
}
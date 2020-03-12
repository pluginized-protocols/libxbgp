//
// Created by thomas on 12/03/20.
//

#include "ubpf_memory_pool.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>


int init_mempool(struct mem_pool *mp) {
    if (hashmap_new(&mp->mp, sizeof(struct mem_node)) != 0) return -1;
    return 0;
}

int add_mempool(struct mem_pool *mp, uint32_t type, uint32_t length, void *val) {

    int is_ptr;
    struct mem_node new_mem;
    memset(&new_mem, 0, sizeof(struct mem_node));

    is_ptr = length > 8 ? 1 : 0;

    new_mem.type = type;
    new_mem.length = length;

    if (!is_ptr) {
        memcpy(&new_mem.value.val, val, length);
    } else {
        new_mem.value.ptr = malloc(length);
        if (!new_mem.value.ptr) return -1;
        memcpy(new_mem.value.ptr, val, length);
    }

    if (hashmap_get(&mp->mp, type) != NULL) goto err;
    if (hashmap_put(&mp->mp, type, new_mem) == -1) goto err;

    return 0;

    err:
    if (is_ptr) free(new_mem.value.ptr);
    return -1;
}

void *get_mempool_ptr(struct mem_pool *mp, uint32_t type) {
    struct mem_node *node;
    if (!mp) return NULL;
    node = hashmap_get(&mp->mp, type);
    if (!node) return NULL;

    return node->length <= 8 ? NULL : node->value.ptr;
}

uint64_t get_mempool_u64(struct mem_pool *mp, uint32_t type) {
    struct mem_node *node;

    if (!mp) return 0;
    node = hashmap_get(&mp->mp, type);
    if (!node) return 0;

    return node->length <= 8 ? node->value.val : 0;
}

void remove_mempool(struct mem_pool *mp, uint32_t type) {

    struct mem_node *pool;
    pool = hashmap_get(&mp->mp, type);
    if (!pool) return;
    if (pool->length > 8) free(pool->value.ptr);
    hashmap_delete(&mp->mp, type);
}

void delete_mempool(struct mem_pool *mp) {
    if (!mp) return;
    hashmap_destroy(&mp->mp);
}
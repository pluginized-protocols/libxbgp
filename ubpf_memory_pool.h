//
// Created by thomas on 12/03/20.
//

#ifndef UBPF_TOOLS_UBPF_MEMORY_POOL_H
#define UBPF_TOOLS_UBPF_MEMORY_POOL_H

#include "hashmap.h"

struct mem_node {
    uint32_t type;
    uint32_t length;
    union {
        uint64_t val;
        uint8_t *ptr;
    } value;
};


typedef hashmap_t(struct mem_node) _mem_pool;

struct mem_pool {
    _mem_pool mp;
};

int init_mempool(struct mem_pool *mp);

int add_mempool(struct mem_pool *mp, uint32_t type, uint32_t length, void *val);

void remove_mempool(struct mem_pool *mp, uint32_t type);

uint64_t get_mempool_u64(struct mem_pool *mp, uint32_t type);

void *get_mempool_ptr(struct mem_pool *mp, uint32_t type);

void delete_mempool(struct mem_pool *mp);

#endif //UBPF_TOOLS_UBPF_MEMORY_POOL_H
//
// Created by thomas on 12/03/20.
//

#ifndef UBPF_TOOLS_UBPF_MEMORY_POOL_H
#define UBPF_TOOLS_UBPF_MEMORY_POOL_H

#include "hashmap.h"
#include "list.h"


struct mem_node {
    uint32_t type;
    uint32_t length;
    int val_type;

    void (*clean)(void *);

    union {
        uint64_t val;
        uint8_t *ptr;
        list_t *lst;
    } value;
};


typedef hashmap_t(struct mem_node) _mem_pool;

typedef hashmap_iterator(struct mem_node) _mem_pool_it;

// encapsulation for public header
// (hashmap macros should not be visible externally)
struct mem_pool {
    _mem_pool mp;
    // int list_node; // set to 1 if mem_mode->value is a list
};

struct mem_pool_it {
    _mem_pool_it it;
};
// end encapsulation

struct lst_mempool_iterator {
    struct mem_node *mn;
    struct list_iterator lst_it;
};

struct mempool_iterator {
    struct mem_pool *mp;
    struct hashmap_iterator it;
};

struct mem_pool *new_mempool(void);

int add_lst_mempool(struct mem_pool *mp, uint32_t type, void (*cleanup)(void *), uint32_t length, void *val);

int add_single_mempool(struct mem_pool *mp, uint32_t type, void (*cleanup)(void *), uint32_t length, void *val);

int add_raw_ptr_mempool(struct mem_pool *mp, uint32_t type, void (*cleanup)(void *), void *val);

void remove_mempool(struct mem_pool *mp, uint32_t type);

uint64_t get_mempool_u64(struct mem_pool *mp, uint32_t type);

void *get_mempool_ptr(struct mem_pool *mp, uint32_t type);

void delete_mempool(struct mem_pool *mp);

struct lst_mempool_iterator *new_lst_iterator_mempool(struct mem_pool *mp, uint32_t type);

void *get_lst_mempool_iterator(struct lst_mempool_iterator *it);

void *next_lst_mempool_iterator(struct lst_mempool_iterator *it);

int hasnext_lst_mempool_iterator(struct lst_mempool_iterator *it);

int end_lst_mempool_iterator(struct lst_mempool_iterator *it);

/**
 * Remove the current element in the list.
 * Do not mix up with destroy_mempool which
 * deallocate the iterator and not an element
 * contained inside the memory pool.
 */
int remove_lst_mempool_iterator(struct lst_mempool_iterator *it);

/**
 * Deallocate memory used by the iterator
 * @param it
 */
void destroy_lst_mempool_iterator(struct lst_mempool_iterator *it);

struct mem_pool_it *new_mempool_iterator(struct mem_pool *mp);

void delete_mempool_iterator(struct mem_pool_it *it);

void *next_mempool_iterator(struct mem_pool_it *it);

int hasnext_mempool_iterator(struct mem_pool_it *it);

#endif //UBPF_TOOLS_UBPF_MEMORY_POOL_H
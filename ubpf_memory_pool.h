//
// Created by thomas on 12/03/20.
//

#ifndef UBPF_TOOLS_UBPF_MEMORY_POOL_H
#define UBPF_TOOLS_UBPF_MEMORY_POOL_H

#include "list.h"
#include "uthash.h"

typedef struct element {
    void (*clean)(void *); /* used to clean data passed to the pointer if any */
    struct element *prev; /* needed for a doubly-linked list only */
    struct element *next; /* needed for singly- or doubly-linked lists */
    size_t len;
    int raw;
    uint8_t data[0];
} mp_element_t;

struct mem_node {
    UT_hash_handle hh;
    uint32_t type;
    uint32_t length;
    mp_element_t *value;
};

struct mempool_data {
    int length;
    void *data;
};

// encapsulation for public header
// (hashmap macros should not be visible externally)
struct mem_pool {
    struct mem_node *node;
    // int list_node; // set to 1 if mem_mode->value is a list
};


struct mem_node_it {
    struct mem_node *node;
    mp_element_t *curr_element;
};


// end encapsulation

struct mem_pool_it_ {
    struct mem_pool *pool; /* main memory pool */
    struct mem_node *node; /* current node on which we iterate */
    struct mem_node_it *it; /* current memory node iterator */
};
struct mem_pool_it {
    struct mem_pool_it_ it;
};

struct mempool_iterator {
    struct mem_pool *mp;

};

struct mem_pool *new_mempool(void);

int add_mempool(struct mem_pool *mp, uint32_t type, void (*cleanup)(void *),
                uint32_t length, void *val, int raw);

void remove_mempool(struct mem_pool *mp, uint32_t type);

int get_mempool_data(struct mem_pool *mp, uint32_t type, struct mempool_data *data);

void delete_mempool(struct mem_pool *mp);

struct mem_pool_it *new_mempool_iterator(struct mem_pool *mp);

void delete_mempool_iterator(struct mem_pool_it *it);

void *next_mempool_iterator(struct mem_pool_it *it);

void delete_memnode_iterator(struct mem_node_it *it);

void remove_memnode(struct mem_pool *mp, struct mem_node *node);

void *memnode_next_element(struct mem_node_it *it);

int memnode_hasnext(struct mem_node_it *it);

int mempool_hasnext(struct mem_pool_it *it);

struct mem_node_it *new_memnode_iterator(struct mem_node *node);

#endif //UBPF_TOOLS_UBPF_MEMORY_POOL_H
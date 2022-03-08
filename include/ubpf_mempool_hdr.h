//
// Created by thomas on 12/03/20.
//

#ifndef UBPF_TOOLS_UBPF_MEMPOOL_HDR_H
#define UBPF_TOOLS_UBPF_MEMPOOL_HDR_H

#include <stdint.h>

struct mempool_data {
    int length;
    void *data;
};

typedef struct mem_pool mem_pool;

typedef struct lst_mempool_iterator lst_mempool_iterator;

typedef struct mem_pool_it mempool_iterator;


extern struct mem_pool *new_mempool(void);

extern int add_mempool(struct mem_pool *mp, uint32_t type, void (*cleanup)(void *),
                       uint32_t length, void *val, int raw);

extern void remove_mempool(struct mem_pool *mp, uint32_t type);



extern void delete_mempool(struct mem_pool *mp);

extern uint32_t jhash_mempool(struct mem_pool *mp);

extern mempool_iterator *new_mempool_iterator(struct mem_pool *mp);

extern void delete_mempool_iterator(mempool_iterator *it);

extern void *next_mempool_iterator(mempool_iterator *it);

int mempool_hasnext(struct mem_pool_it *it);

extern int get_mempool_data(struct mem_pool *mp, uint32_t type, struct mempool_data *data);

#endif //UBPF_TOOLS_UBPF_MEMPOOL_HDR_H
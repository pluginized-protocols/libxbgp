//
// Created by thomas on 12/03/20.
//

#ifndef UBPF_TOOLS_UBPF_MEMPOOL_HDR_H
#define UBPF_TOOLS_UBPF_MEMPOOL_HDR_H

#include <stdint.h>

typedef struct mem_pool mem_pool;

typedef struct mempool_iterator mempool_iterator;


extern struct mem_pool *new_mempool(void);

extern int add_lst_mempool(struct mem_pool *mp, uint32_t type, void (*cleanup)(void *), uint32_t length, void *val);

extern int add_single_mempool(struct mem_pool *mp, uint32_t type, void (*cleanup)(void *), uint32_t length, void *val);

extern int add_mempool(struct mem_pool *mp, uint32_t type, void (*cleanup)(void *),
                       uint32_t length, void *val, int is_lst);

extern void remove_mempool(struct mem_pool *mp, uint32_t type);

extern uint64_t get_mempool_u64(struct mem_pool *mp, uint32_t type);

extern void *get_mempool_ptr(struct mem_pool *mp, uint32_t type);

extern void delete_mempool(struct mem_pool *mp);

extern struct mempool_iterator *new_iterator_mempool(struct mem_pool *mp, uint32_t type);

extern void *get_mempool_iterator(struct mempool_iterator *it);

extern void *next_mempool_iterator(struct mempool_iterator *it);

extern int end_mempool_iterator(struct mempool_iterator *it);

extern int remove_mempool_iterator(struct mempool_iterator *it);

extern void destroy_mempool_iterator(struct mempool_iterator *it);

extern int add_raw_ptr_mempool(struct mem_pool *mp, uint32_t type, void (*cleanup)(void *), void *val);

#endif //UBPF_TOOLS_UBPF_MEMPOOL_HDR_H
//
// Created by thomas on 12/03/20.
//

#ifndef UBPF_TOOLS_UBPF_MEMPOOL_HDR_H
#define UBPF_TOOLS_UBPF_MEMPOOL_HDR_H

#include <stdint.h>

typedef struct mem_pool mem_pool;

extern int init_mempool(mem_pool *mp);

extern int add_mempool(mem_pool *mp, uint32_t type, uint32_t length, void *val);

extern void remove_mempool(mem_pool *mp, uint32_t type);

extern uint64_t get_mempool_u64(mem_pool *mp, uint32_t type);

extern void *get_mempool_ptr(mem_pool *mp, uint32_t type);

extern void delete_mempool(mem_pool *mp);


#endif //UBPF_TOOLS_UBPF_MEMPOOL_HDR_H
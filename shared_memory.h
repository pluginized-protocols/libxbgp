//
// Created by thomas on 19/11/18.
//

#ifndef FRR_UBPF_SHARED_MEMORY_H
#define FRR_UBPF_SHARED_MEMORY_H

#include <stdlib.h>
#include <stdint.h>
#include "uthash.h"
#include <sys/ipc.h>
#include <memalloc/michelfralloc.h>

#define MIN_MICHELFRA_MEM_SIZE (4096)
#define MIN_MEM_SIZE_PLUGIN MIN_MICHELFRA_MEM_SIZE

#define ONE_IF_ZERO(x) ((x) == 0 ? 1 : (x))

#define MEM_ALIGN(x) \
  ((((ONE_IF_ZERO(x) - 1) | ((MIN_MEM_SIZE_PLUGIN) - 1)) + 1))

typedef plugin_dynamic_memory_pool_t michelfra_mem_t;

/*
 * BUMP MALLOC
 */

typedef struct bump_mem {
    uint32_t total_mem;
    uint32_t available_size;
    uint8_t *mem_start;
    uint8_t *next_avail;
} bump_t;

void init_bump(bump_t *pool, uint32_t mem_size, uint8_t *mem_area);

void *bump_alloc(bump_t *pool, size_t);

void reset_bump(bump_t *pool);


typedef union mem_context {
    michelfra_mem_t michelfra;
    bump_t bump;
} mem_context_t;


struct memory_manager {
    void *(*malloc)(mem_context_t *, size_t);

    void (*free)(mem_context_t *, void *ptr);

    void *(*realloc)(mem_context_t *, void *, size_t);

    void (*init)(mem_context_t *, void *, uint32_t);

    void (*reset)(mem_context_t *);

#define mem_mgr_initialized(x) ((x)->usable)
    int usable;

    mem_context_t memory_ctx;
};

typedef enum MEM_TYPE {
    MIN_MEM,
    MICHELFRA_MEM,
    BUMP_MEM,
    MAX_MEM,
} mem_type_t;


int init_memory_manager(struct memory_manager *mgr, mem_type_t mem_type);

void destroy_memory_manager(struct memory_manager *mgr);


void mem_init(struct memory_manager *mgr, void *start_mem, size_t tot_mem_size);

void *mem_alloc(struct memory_manager *mgr, size_t size);

void *mem_realloc(struct memory_manager *mgr, void *ptr, size_t size);

void mem_free(struct memory_manager *mgr, void *ptr);

void mem_reset(struct memory_manager *mgr);


typedef struct map_shared {
    UT_hash_handle hh;
    int id;
    uint8_t *data;
} map_shared_t;

//void init_shared_map(map_shared_t *map);

void destroy_shared_map(map_shared_t **map);

void *shared_new(struct memory_manager *mgr, map_shared_t **shared, key_t key, size_t size);

void *shared_get(struct memory_manager *mgr, map_shared_t **shared, key_t key);

void shared_rm(struct memory_manager *mgr, map_shared_t **shared, key_t key);

#endif //FRR_UBPF_SHARED_MEMORY_H

//
// Created by thomas on 19/11/18.
//

#include "shared_memory.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "tools_ubpf_api.h"
#include "tommy.h"

/**
 * BUMP ALLOC
 * Stack like allocation for plugins that do not want to
 * save the memory between two consecutive calls
 */
void init_bump(bump_t *pool, uint32_t mem_size, uint8_t *mem_area) {
    if (!pool) return;

    pool->total_mem = mem_size;
    pool->available_size = mem_size;
    pool->mem_start = mem_area;
    pool->next_avail = mem_area;
}

void *bump_alloc(bump_t *pool, size_t size) {
    if (!pool) return NULL;

    void *ptr;
    size_t aligned_size = (size + 7u) & (-8u);
    if (aligned_size > pool->available_size) return NULL;

    ptr = pool->next_avail;

    pool->next_avail += aligned_size;
    return ptr;
}

void reset_bump(bump_t *pool) {
    if (!pool) return;

    pool->available_size = pool->total_mem;
    pool->next_avail = pool->mem_start;
}


/** MEMORY MANAGEMENT */

static inline void michelfra_init(mem_context_t *pool, void *mem_area, uint32_t mem_size) {
    memset(pool, 0, sizeof(*pool));

    pool->michelfra.memory_start = mem_area;
    pool->michelfra.memory_max_size = mem_size;
    pool->michelfra.memory_current_end = mem_area;
}

static inline void *michelfra_malloc(mem_context_t *pool, size_t size) {
    return michelfralloc(&pool->michelfra, size);
}

static inline void michelfra_free(mem_context_t *pool, void *ptr) {
    return michelfree(&pool->michelfra, ptr);
}

static inline void *michelfra_realloc(mem_context_t *pool, void *ptr, size_t size) {
    return michelfrealloc(&pool->michelfra, ptr, size);
}

static inline void michelfra_reset(mem_context_t *pool) {
    pool->michelfra.memory_current_end = pool->michelfra.memory_start;
    memset(&pool->michelfra.dlmalloc_state, 0, sizeof(pool->michelfra.dlmalloc_state));
}


static void bump_init(mem_context_t *pool, void *mem_area, uint32_t mem_size) {
    memset(pool, 0, sizeof(*pool));

    init_bump(&pool->bump, mem_size, mem_area);
}

static inline void *bump_malloc(mem_context_t *pool, size_t size) {
    return bump_alloc(&pool->bump, size);
}

static inline void bump_free(mem_context_t *pool UNUSED, void *ptr UNUSED) {
    // bump is stack like. Thus, unable to free
    // memory
}

static inline void *bump_realloc(mem_context_t *pool UNUSED, void *ptr UNUSED, size_t size UNUSED) {
    return NULL; // realloc unsupported for bump memory
}

static inline void bump_reset(mem_context_t *pool) {
    reset_bump(&pool->bump);
}

static const struct memory_manager mem_mgrs[] = {
        [MICHELFRA_MEM] = {
                .malloc = michelfra_malloc,
                .free = michelfra_free,
                .realloc = michelfra_realloc,
                .init = michelfra_init,
                .reset = michelfra_reset,
                .usable = 0, // make sure this field is
                // set to zero (will be set to 1 if
                // michelfra is init)
        },
        [BUMP_MEM] = {
                .malloc = bump_malloc,
                .free = bump_free,
                .realloc = bump_realloc,
                .reset = bump_reset,
                .init = bump_init,
                .usable = 0, // same as above
        }
};


int init_memory_manager(struct memory_manager *mgr, mem_type_t mem_type) {

    if (mem_type <= MIN_MEM || mem_type >= MAX_MEM) {
        return -1;
    }

    memcpy(mgr, &mem_mgrs[mem_type], sizeof(*mgr));

    switch (mem_type) {
        case MICHELFRA_MEM:
            memset(&mgr->memory_ctx.michelfra, 0, sizeof(mgr->memory_ctx.michelfra));
            break;
        case BUMP_MEM:
            memset(&mgr->memory_ctx.bump, 0, sizeof(mgr->memory_ctx.bump));
            break;
        default:
            return -1;
    }

    mgr->usable = 1;
    return 0;
}

void destroy_memory_manager(struct memory_manager *mgr UNUSED) {
    // for now, nothing is dynamically allocated inside the
    // memory manager
    return;
}

void mem_init(struct memory_manager *mgr, void *start_mem, size_t tot_mem_size) {
    if (!mem_mgr_initialized(mgr)) return;
    return mgr->init(&mgr->memory_ctx, start_mem, tot_mem_size);
}

void *mem_alloc(struct memory_manager *mgr, size_t size) {
    if (!mem_mgr_initialized(mgr)) return NULL;
    return mgr->malloc(&mgr->memory_ctx, size);
}

void *mem_realloc(struct memory_manager *mgr, void *ptr, size_t size) {
    if (!mem_mgr_initialized(mgr)) return NULL;
    return mgr->realloc(&mgr->memory_ctx, ptr, size);
}

void mem_free(struct memory_manager *mgr, void *ptr) {
    if (!mem_mgr_initialized(mgr)) return;
    mgr->free(&mgr->memory_ctx, ptr);
}

void mem_reset(struct memory_manager *mgr) {
    if (!mem_mgr_initialized(mgr)) return;
    mgr->reset(&mgr->memory_ctx);
}


///* shared memory related functions *///

static inline int search_shared_block(const void *arg, const void *obj) {
    const int *arg_id = arg;
    const map_shared_t *elem = obj;

    return *arg_id != elem->id;
}

void init_shared_hash(tommy_hashdyn *hashdyn) {
    if (!hashdyn) return;
    tommy_hashdyn_init(hashdyn);
}

void *shared_new(struct memory_manager *mgr, tommy_hashdyn *shared, key_t key, size_t size) {
    uint8_t *block;
    map_shared_t *shared_block;

    uint32_t hash_key = tommy_inthash_u32(key);

    shared_block = tommy_hashdyn_search(shared, search_shared_block,
                                        &key, hash_key);

    if (shared_block) return NULL; // key already assigned, this is so sad :/

    block = mgr->malloc(&mgr->memory_ctx, size);

    if (!block) {
        fprintf(stderr, "Unable to allocate memory\n");
        return NULL;
    }

    shared_block = calloc(sizeof(map_shared_t), 1);
    if (!shared_block) {
        mgr->free(&mgr->memory_ctx, block);
        return NULL;
    }

    shared_block->id = key;
    shared_block->data = block;

    tommy_hashdyn_insert(shared, &shared_block->hash_node,
                         shared_block, hash_key);
    return block;
}

void *shared_get(struct memory_manager *mgr UNUSED, tommy_hashdyn *shared, key_t key) {
    map_shared_t *shared_block;

    uint32_t hash_key = tommy_inthash_u32(key);

    shared_block = tommy_hashdyn_search(shared, search_shared_block,
                                        &key, hash_key);

    if (!shared_block) return NULL; // key not assigned in a shared block;

    return shared_block->data;
}

void shared_rm(struct memory_manager *mgr, tommy_hashdyn *shared, key_t key) {
    map_shared_t *shared_block;

    uint32_t hash_key = tommy_inthash_u32(key);

    shared_block = tommy_hashdyn_search(shared, search_shared_block,
                                        &key, hash_key);

    if (!shared_block) return;

    mgr->free(&mgr->memory_ctx, shared_block->data);
    tommy_hashdyn_remove_existing(shared, &shared_block->hash_node);
    free(shared_block);
}


static inline void free_map_shared_t(void *mgr, void* obj) {
    map_shared_t *ms = obj;
    struct memory_manager *manager = mgr;

    manager->free(&manager->memory_ctx, ms->data);
    free(ms);
}

void destroy_shared_map(struct memory_manager *mgr, tommy_hashdyn *shared) {
    if (!shared) return;

    tommy_hashdyn_foreach_arg(shared, free_map_shared_t, mgr);
    tommy_hashdyn_done(shared);
}

//
// Created by thomas on 19/11/18.
//

#ifndef FRR_UBPF_SHARED_MEMORY_H
#define FRR_UBPF_SHARED_MEMORY_H

#include <stdlib.h>
#include <stdint.h>
#include "map.h"
#include <sys/ipc.h>

#define MAGIC 0xCAFEBABEDEADBEEF

#define BLOCK_SIZE 4000 // FIXME: WAY TOO HIGH ! (quick fix for now) 4000 bytes fo a block is not a good idea

typedef map_t(uint8_t *) map_shared_t;

typedef struct header_block {
    uint8_t available : 1; // is this block is available ?
    uint8_t shared : 1; // is this memory zone shared ? the id is stored in an ext struct
    size_t size; // size of this block
    uint64_t magic;
    struct header_block *next; // pointer to the next block in the shared memory zone
} header_block_t;

typedef struct shared_memory {
    uint8_t *heap;
    size_t heap_len;
    header_block_t *start;
    void *last_block; // sbrk limit
    void *end; // end of allocated memory
    map_shared_t shared_blocks;
    short corrupted;
} heap_t;

void *get_start_heap(heap_t *heap);

size_t heap_size(heap_t *heap);

void init_heap(heap_t *mem, void *heap, size_t len);

/**
 * Deallocate internal structures of a heap_t struct.
 * This function does not free the memory pointed
 * by the parameter heap nor the actual memory allocated
 * in the true heap (heap->heap given in the 2nd parameter
 * of init_heap function).
 * @param heap the structure to be internally deallocated
 */
void destroy_heap(heap_t *heap);

int has_enough_space(void *ptr, size_t size);

int is_mem_bound(heap_t *heap, void *ptr);

void flush_heap(heap_t *heap);

void *ubpf_sbrk(heap_t *heap, size_t increment);

void *ubpf_malloc(heap_t *heap, size_t len);

void ubpf_free(heap_t *heap, void *mem);

void *ubpf_calloc(heap_t *heap, size_t nmemb, size_t size);

void *ubpf_shmnew(heap_t *heap, key_t key, size_t size);

void *ubpf_shmget(heap_t *heap, key_t key);

void ubpf_shmrm(heap_t *heap, key_t key);

/* new */


typedef struct memory_pool {
    uint64_t num_of_blocks;
    uint64_t size_of_each_block;
    uint64_t num_free_blocks;
    uint64_t num_initialized;
    uint8_t *mem_start;
    uint8_t *next;
    map_shared_t shared;
} memory_pool_t;



void *my_malloc(memory_pool_t *mem_pool, unsigned int size);
void *my_calloc(memory_pool_t *mem_pool, size_t nmemb, size_t size);
void my_free(memory_pool_t *mem_pool, void *ptr);
void *my_realloc(memory_pool_t *mem_pool, void *ptr, unsigned int size);

void *my_shmnew(memory_pool_t *mp, key_t key, size_t size);
void *my_shmget(memory_pool_t *mp, key_t key);
void my_shmrm(memory_pool_t *mp, key_t key);
void destroy_memory_management(heap_t *mp);

void my_free_in_core(memory_pool_t *mem_pool, void *ptr);

int init_memory_management(memory_pool_t *mem_pool, uint8_t *mem, size_t len);

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifdef DEBUG_MEMORY_PRINTF

#define DBG_MEMORY_PRINTF_FILENAME_MAX 24
#define DBG_MEMORY_PRINTF(fmt, ...)                                                                 \
    debug_printf("%s:%u [%s]: " fmt "\n",                                                    \
        __FILE__ + MAX(DBG_MEMORY_PRINTF_FILENAME_MAX, sizeof(__FILE__)) - DBG_MEMORY_PRINTF_FILENAME_MAX, \
        __LINE__, __FUNCTION__, __VA_ARGS__)

#else

#define DBG_MEMORY_PRINTF(fmt, ...)

#endif // #ifdef DEBUG_PLUGIN_PRINTF


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
void *bump_calloc(bump_t *pool, size_t nmemb, size_t size);
void reset_bump(bump_t *pool);

/*
 * useless free used for compatibility
 * with existing code
 */
void bump_free(bump_t *pool, void *ptr);

#endif //FRR_UBPF_SHARED_MEMORY_H

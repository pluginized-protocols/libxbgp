//
// Created by thomas on 19/11/18.
//

#include "shared_memory.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "map.h"

typedef enum TYPE_MEM {
    SHARED,
    NORMAL
} type_mem_t;

static inline int merge(header_block_t *a, header_block_t *b) {

    if (a->next != b || !a->available || !b->available) return -1;
    if (a > b) return -1;

    a->next = b->next;
    a->size += b->size + sizeof(header_block_t);
    return 0;
}

static inline void split(header_block_t *a, size_t len) {

    size_t tot_len = len + sizeof(header_block_t);
    size_t tot_block;
    header_block_t *next;

    tot_block = a->size;
    next = a->next;

    if (a->size - len > sizeof(header_block_t)) {
        // the splitting is performed if there is at least enough
        // space for one header_block_t + 1 byte of memory

        a->size = len;
        a->next = (void *) ((uint8_t *) a + len + sizeof(header_block_t));
        a->magic = MAGIC;

        a->next->available = 1;
        a->next->size = tot_block - tot_len;
        a->next->next = next;
        a->next->magic = MAGIC;
    }

}

static void clean(heap_t *heap) {

    header_block_t *ptr, *previous;

    ptr = heap->start;
    previous = NULL;

    while (ptr) {
        if (previous && previous->available && ptr->available) {
            merge(previous, ptr);
            ptr = previous->next;
        } else {
            previous = ptr;
            ptr = ptr->next;
        }
    }


}

static inline int is_corrupted(header_block_t *block) {
    if (block->magic != MAGIC) fprintf(stderr, "[ERROR] MEMORY IS CORRUPTED !\n");
    return block->magic != MAGIC;
}

void *get_start_heap(heap_t *heap) {
    return heap ? heap->heap : NULL;
}

size_t heap_size(heap_t *heap) {
    return heap ? heap->heap_len : 0;
}

int is_mem_bound(heap_t *heap, void *ptr) {

    return ptr >= get_start_heap(heap) && (uint8_t *) ptr < (uint8_t *) get_start_heap(heap) + heap_size(heap);

}

int has_enough_space(void *ptr, size_t size) {
    header_block_t *ptr_block;

    ptr_block = (header_block_t *) ((uint8_t *) ptr - sizeof(header_block_t));

    if (ptr_block->magic != MAGIC) return 0; // memory corruption

    return ptr_block->size >= size;
}

void flush_heap(heap_t *heap) {

    if (!heap || !heap->heap) return;

    header_block_t *curr;

    for (curr = heap->start; curr; curr = curr->next)
        if (!curr->shared && !curr->available) {
            ubpf_free(heap, curr + 1);
        }

}

void init_heap(heap_t *mem, void *heap, size_t len) {

    mem->heap = heap;
    mem->heap_len = len;
    mem->start = NULL;
    mem->last_block = &mem->heap[0];
    mem->end = &mem->heap[len - 1];
    mem->corrupted = 0;
    map_init(&mem->shared_blocks);

}

void destroy_heap(heap_t *heap) {
    map_shared_t *curr, *tmp;
    HASH_ITER(hh, heap->shared_blocks, curr, tmp) {
        HASH_DEL(heap->shared_blocks, curr);
        free(curr);
    }
}

void *ubpf_sbrk(heap_t *heap, size_t increment) {

    if (!heap || !heap->heap) return (void *) -1;

    if (heap->last_block + increment > heap->end) {
        fprintf(stderr, "OUT OF SPACE !\n");
        return (void *) -1; // out of space... this is quite embarrassing
    }

    heap->last_block += increment; // allocate increment

    return heap->last_block;
}

/* generic ubpf_malloc handling NORMAL and SHARED blocks  */
static inline void *alloc_mem(heap_t *heap, size_t len, type_mem_t type) {

    if (!heap || !heap->heap) return NULL;
    if (heap->corrupted) return NULL;

    void *top_new_space, *alloc_space;
    header_block_t *ptr, *previous, *new_header, *potential_ptr;
    size_t tot_len;
    uint8_t shared_flag = type == SHARED ? 1 : 0;

    len = (0 == (len & 0x3u)) ? len : (len + 3u) & ~0x03u; // 32bits alignment

    previous = heap->start;
    tot_len = len + sizeof(header_block_t);

    potential_ptr = NULL;
    size_t size_pot_ptr = 0;

    for (ptr = heap->start; ptr; ptr = ptr->next) {
        if (is_corrupted(ptr)) {
            heap->corrupted = 1;
            return NULL;
        }

        if (ptr->available) {
            if (ptr->size == len) { // exact fit (tot len not here because header already setup)
                if (is_corrupted(ptr)) {
                    heap->corrupted = 1;
                    return NULL; // memory is corrupted
                }
                ptr->available = 0;
                ptr->shared = shared_flag;
                return ptr + 1;
            } else if (ptr->size >= tot_len && (size_pot_ptr == 0 || ptr->size < size_pot_ptr)) {
                // here tot_len in the comparison is mandatory because it is needed to include
                // the header of the the available space after splitting a larger free block
                // [header| free space > len] ---> [header|len] + [header| free_space - len - sizeof(header) ]

                // try to find the smallest block among these available
                size_pot_ptr = ptr->size;
                potential_ptr = ptr;
            }
        }
        previous = ptr;
    }

    if (potential_ptr) {
        if (is_corrupted(potential_ptr)) {
            heap->corrupted = 1;
            return NULL;
        }
        split(potential_ptr, len);
        potential_ptr->available = 0;
        potential_ptr->shared = shared_flag;
        return potential_ptr + 1;
    }


    alloc_space = heap->last_block;
    top_new_space = ubpf_sbrk(heap, len + sizeof(header_block_t));
    if (top_new_space == (void *) -1) return NULL;

    new_header = (header_block_t *) alloc_space;

    if (!previous) previous = alloc_space; // no blocks are assigned yet
    if (!heap->start) heap->start = alloc_space;

    previous->next = new_header;

    memset(new_header, 0, sizeof(header_block_t));

    new_header->next = NULL;
    new_header->available = 0;
    new_header->size = len;
    new_header->magic = MAGIC;
    new_header->shared = shared_flag;

    return new_header + 1;
}

void *ubpf_malloc(heap_t *heap, size_t mem) {
    return alloc_mem(heap, mem, NORMAL);
}

void ubpf_free(heap_t *heap, void *_mem) {

    uint8_t *mem = _mem;

    if (!heap || !heap->heap) return;
    if (!mem) return;

    if (!is_mem_bound(heap, mem)) {
        fprintf(stderr, "OUT OF BOUND FREE\n");
        return;
    }

    header_block_t *h = (header_block_t *) (mem - sizeof(header_block_t));

    if (h < heap->start) return;
    if (h->available) return;

    h->available = 1;
    clean(heap);
}

void *ubpf_calloc(heap_t *heap, size_t nmemb, size_t size) {

    if (!heap || !heap->heap) return NULL;

    size_t tot;
    void *mem_ptr;

    tot = nmemb * size;
    mem_ptr = alloc_mem(heap, tot, NORMAL);

    if (mem_ptr) {
        memset(mem_ptr, 0, tot);
        return mem_ptr;
    }

    return NULL;
}

void *ubpf_shmnew(heap_t *heap, key_t key, size_t size) {
    map_shared_t *shared;
    uint8_t *block;

    if (!heap || !heap->heap) return NULL;
    HASH_FIND_INT(heap->shared_blocks, &key, shared);

    if (shared) return NULL; // key already assigned, this is so sad :/
    block = alloc_mem(heap, size, SHARED);

    if (!block) {
        fprintf(stderr, "Try to allocate %zu byte, (%zu left)\n", size, heap->heap_len);
        return NULL;
    }

    shared = calloc(sizeof(map_shared_t), 1);
    if (!shared) {
        ubpf_free(heap, block);
        return NULL;
    }
    shared->id = key;
    shared->data = block;

    HASH_ADD_INT(heap->shared_blocks, id, shared);
    return block;
}

void *ubpf_shmget(heap_t *heap, key_t key) {

    map_shared_t *shared;

    if (!heap || !heap->heap) return NULL;

    HASH_FIND_INT(heap->shared_blocks, &key, shared);

    if (!shared) return NULL; // key not assigned in a shared block;

    return shared->data;
}

void ubpf_shmrm(heap_t *heap, key_t key) {
    map_shared_t *shared;

    if (!heap || !heap->heap) return;
    HASH_FIND_INT(heap->shared_blocks, &key, shared);
    if (!shared) return; // key not assigned in a shared block;

    ubpf_free(heap, shared->data);
    HASH_DEL(heap->shared_blocks, shared);
}


///* new functions *///

#define MAGIC_NUMBER 0xa110ca7ab1e

static inline uint8_t *addr_from_index(memory_pool_t *mp, uint64_t i) {
    return mp->mem_start + (i * mp->size_of_each_block);
}

static inline uint64_t index_from_addr(memory_pool_t *mp, const uint8_t *p) {
    return ((uint64_t) (p - mp->mem_start)) / mp->size_of_each_block;
}

/**
* Search for big enough free space on heap.
* Split the free space slot if it is too big, else space will be wasted.
* Return the pointer to this slot.
* If no adequately large free slot is available, extend the heap and return the pointer.
*/
void *my_malloc(memory_pool_t *mp, unsigned int size) {
    if (!mp) {
        fprintf(stderr, "FATAL ERROR: calling my_free outside plugin scope!\n");
        return NULL;
    }

    if (size > mp->size_of_each_block - 8) {
        fprintf(stderr, "Asking for %u bytes by slots up to %lu!\n (to big alloc request)", size,
                mp->size_of_each_block - 8);
        return NULL;
    }
    if (mp->num_initialized < mp->num_of_blocks) {
        uint64_t *p = (uint64_t *) addr_from_index(mp, mp->num_initialized);
        /* Very important for the mp->next computation */
        *p = mp->num_initialized + 1;
        mp->num_initialized++;
    }

    void *ret = NULL;
    if (mp->num_free_blocks > 0) {
        ret = (void *) mp->next;
        mp->num_free_blocks--;
        if (mp->num_free_blocks > 0) {
            mp->next = addr_from_index(mp, *((uint64_t *) mp->next));
        } else {
            mp->next = NULL;
        }
    } else {
        printf("Out of memory!\n");
    }
    *((uint64_t *) ret) = MAGIC_NUMBER;
    return (uint8_t *) ret + 8;
}

void *my_calloc(memory_pool_t *mem_pool, size_t nmemb, size_t size) {
    void *ptr = my_malloc(mem_pool, nmemb * size);
    if (!ptr) return NULL;
    memset(ptr, 0, nmemb * size);
    return ptr;
}

void my_free_in_core(memory_pool_t *mp, void *_ptr) {

    uint8_t *ptr = _ptr;

    ptr -= 8;
    if (*((uint64_t *) ptr) != MAGIC_NUMBER) {
        printf("MEMORY CORRUPTION: BAD METADATA: 0x%lx, ORIGINAL PTR: %p\n", *((uint64_t *) ptr), ptr + 8);
    }

    if (mp->next != NULL) {
        (*(uint64_t *) ptr) = index_from_addr(mp, mp->next);
        if (!(mp->mem_start <= (uint8_t *) ptr &&
              (uint8_t *) ptr < (mp->mem_start + (mp->num_of_blocks * mp->size_of_each_block)))) {
            printf("MEMORY CORRUPTION: FREEING MEMORY (%p) NOT BELONGING TO THE PLUGIN\n", ptr + 8);
        }
        mp->next = (uint8_t *) ptr;
    } else {
        (*(uint64_t *) ptr) = mp->num_of_blocks;
        if (!(mp->mem_start <= (uint8_t *) ptr &&
              (uint8_t *) ptr < (mp->mem_start + (mp->num_of_blocks * mp->size_of_each_block)))) {
            printf("MEMORY CORRUPTION: FREEING MEMORY (%p) NOT BELONGING TO THE PLUGIN\n", ptr + 8);
        }
        mp->next = (uint8_t *) ptr;
    }
    mp->num_free_blocks++;
}


/**
 * Frees the allocated memory. If first checks if the pointer falls
 * between the allocated heap range. It also checks if the pointer
 * to be deleted is actually allocated. this is done by using the
 * magic number. Due to lack of time i haven't worked on fragmentation.
 */
void my_free(memory_pool_t *mp, void *ptr) {
    if (!mp) {
        fprintf(stderr, "FATAL ERROR: calling my_free outside plugin scope!\n");
        return;
    }
    if (ptr) my_free_in_core(mp, ptr);
}

/**
 * Reallocate the allocated memory to change its size. Three cases are possible.
 * 1) Asking for lower or equal size, or larger size without any block after.
 *    The block is left untouched, we simply increase its size.
 * 2) Asking for larger size, and another block is behind.
 *    We need to request another larger block, then copy the data and finally free it.
 * 3) Asking for larger size, without being able to have free space.
 *    Free the pointer and return NULL.
 * If an invalid pointer is provided, it returns NULL without changing anything.
 */
void *my_realloc(memory_pool_t *mp, void *ptr, unsigned int size) {
    if (!mp) {
        fprintf(stderr, "FATAL ERROR: calling my_free outside plugin scope!\n");
        return NULL;
    }
    // we cannot change the size of the block: if the new size is above the maximum, print an error,
    // otherwise, return the same pointer
    if (size > mp->size_of_each_block - 8) {
        printf("Asking for %u bytes by slots up to %lu!\n", size, mp->size_of_each_block - 8);
        return NULL;
    }
    return ptr;
}


void *my_shmnew(memory_pool_t *mp, key_t key, size_t size) {

    uint8_t *block;
    map_shared_t *shared;

    if (!mp) return NULL;

    HASH_FIND_INT(mp->shared, &key, shared);
    if (shared) return NULL;

    block = my_malloc(mp, size);

    if (!block) {
        fprintf(stderr, "Try to allocate %zu byte, no enough space\n", size);
        return NULL;
    }

    shared = calloc(1, sizeof(map_shared_t));
    if (!shared) {
        fprintf(stderr, "Unable to allocated space for shared context\n");
        my_free(mp, block);
        return NULL;
    }

    shared->id = key;
    shared->data = block;

    HASH_ADD_INT(mp->shared, id, shared);

    return block;
}

void *my_shmget(memory_pool_t *mp, key_t key) {

    map_shared_t *shared;

    if (!mp) return NULL;

    HASH_FIND_INT(mp->shared, &key, shared);
    if (!shared) return NULL; // key not assigned in a shared block;

    return shared->data;
}

void my_shmrm(memory_pool_t *mp, key_t key) {

    map_shared_t *shared;

    if (!mp) return;

    HASH_FIND_INT(mp->shared, &key, shared);
    if (!shared) return; // key not assigned in a shared block;

    my_free(mp, shared->data);

    HASH_DEL(mp->shared, shared);
    free(shared);
}

int init_memory_management(memory_pool_t *mem_pool, uint8_t *mem, size_t len) {

    if (!mem) return -1;

    mem_pool->shared = NULL;
    mem_pool->mem_start = mem;
    mem_pool->size_of_each_block = BLOCK_SIZE; /* TEST */
    mem_pool->num_of_blocks = len / BLOCK_SIZE;
    mem_pool->num_initialized = 0;
    mem_pool->num_free_blocks = mem_pool->num_of_blocks;
    mem_pool->next = mem_pool->mem_start;

    return 0;
}

void destroy_memory_management(heap_t *mp) {
    map_shared_t *curr, *tmp;
    HASH_ITER(hh, mp->shared_blocks, curr, tmp) {
        HASH_DEL(mp->shared_blocks, curr);
        free(curr);
    }
}

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

void *bump_calloc(bump_t *pool, size_t nmemb, size_t size) {
    size_t mem_size;
    mem_size = nmemb * size;

    void *ptr = bump_alloc(pool, mem_size);
    if (!ptr) return NULL;

    memset(ptr, 0, mem_size);
    return ptr;
}

void reset_bump(bump_t *pool) {
    if (!pool) return;

    pool->available_size = pool->total_mem;
    pool->next_avail = pool->mem_start;
}

//
// Created by thomas on 23/09/19.
//

#ifndef FRR_UBPF_HASHMAP_H
#define FRR_UBPF_HASHMAP_H

#include <stdint.h>
#include <stddef.h>

#define HASHMAP_INIT_SIZE 32

#define IN_USE 1u
#define AVAIL 0u

struct key {
    uint64_t val;
    char in_use;
    unsigned int idx_free_lst;
};

struct alloc_keys {
    unsigned int max_size;
    unsigned int size;
    void **alloc_keys;
};

typedef struct hashmap {
    unsigned int n;
    unsigned int m;
    struct key *keys;
    struct alloc_keys alloc;
    void **values;
} hashmap_t;

#define hashmap_t(T) \
struct {\
    hashmap_t base;\
    T tmp;\
    T *ref;\
}

#define hashmap_new(m, size)\
new_hashmap(&((m)->base), size)

#define hashmap_destroy(m)\
free_hashmap(&((m)->base))

#define hashmap_get(m, key)\
((m)->ref = get(&(m)->base, key))

#define hashmap_put(m, key, value)\
( (m)->tmp = (value),\
put(&(m)->base, key, &(m)->tmp, sizeof((m)->tmp)) )

#define hashmap_delete(m, key)\
delete(&(m)->base, key)


int new_hashmap(hashmap_t *hashmap, int size);

void free_hashmap(hashmap_t *hashmap);

uint64_t hash(hashmap_t *hashmap, uint64_t key);

int resize(hashmap_t *hashmap, unsigned int cap);

int put(hashmap_t *hashmap, uint64_t key, void *value, size_t size);

void *get(hashmap_t *hashmap, uint64_t key);

int delete(hashmap_t *hashmap, uint64_t key);

#endif //FRR_UBPF_HASHMAP_H

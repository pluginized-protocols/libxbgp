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
};

typedef struct hashmap {
    unsigned int n;
    unsigned int m;
    struct key *keys;
    void **values;
    size_t size_val;
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

#define hashmap_destroy_free(m, fun) free_hashmap_fun(&((m)->base), fun)

#define hashmap_get(m, key)\
((m)->ref = get(&(m)->base, key))

#define hashmap_put(m, key, value)\
( (m)->tmp = (value),\
put(&(m)->base, key, &(m)->tmp, sizeof((m)->tmp)) )

#define hashmap_delete(m, key)\
delete(&(m)->base, key, NULL)

#define hashmap_delete_fun(m, key, fn)  delete(&(m)->base, key, fn);


int new_hashmap(hashmap_t *hashmap, unsigned int size);

void free_hashmap(hashmap_t *hashmap);

void free_hashmap_fun(hashmap_t *h_map, void (*func)(void *));

uint64_t hash(hashmap_t *hashmap, uint64_t key);

int resize(hashmap_t *hashmap, unsigned int cap);

int put(hashmap_t *hashmap, uint64_t key, void *value, size_t size);

void *get(hashmap_t *hashmap, uint64_t key);

int delete(hashmap_t *hashmap, uint64_t key, void (*cleanup)(void *));

#endif //FRR_UBPF_HASHMAP_H

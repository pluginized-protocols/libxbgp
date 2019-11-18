//
// Created by thomas on 23/09/19.
//

#include "hashmap.h"

#include <stdlib.h>
#include <string.h>

/**
 * Compute the location of the key, value pair in the hashmap
 * @param hashmap hashmap
 * @param key ID of the element to recompute
 * @param value internal pointer of an element already "stored" in the hashmap
 * @return
 */
static int put_move(hashmap_t *hashmap, uint64_t key, void *value, unsigned int idx_free) {
    uint64_t i;

    if (hashmap->n > hashmap->m / 2) resize(hashmap, 2 * hashmap->m);

    for (i = hash(hashmap, key); hashmap->keys[i].in_use == IN_USE; i = (i + 1) % hashmap->m) {
        if (hashmap->keys[i].val == key) {
            hashmap->values[i] = value;
            return 0;
        }
    }

    hashmap->keys[i].val = key;
    hashmap->keys[i].in_use = IN_USE;
    hashmap->keys[i].idx_free_lst = idx_free;

    hashmap->values[i] = value;
    hashmap->n++;
    return 0;
}


int new_hashmap(hashmap_t *hashmap, int size) {

    if (!hashmap) return -1;

    hashmap->keys = calloc(size, sizeof(struct key));
    if (!hashmap->keys) return -1;

    hashmap->values = malloc(size * sizeof(void *));
    if (!hashmap->values) {
        free(hashmap->keys);
        return -1;
    }

    hashmap->alloc.alloc_keys = malloc(size * sizeof(void *));
    hashmap->alloc.size = 0;
    hashmap->alloc.max_size = size;
    if (!hashmap->alloc.alloc_keys) {
        free(hashmap->keys);
        free(hashmap->values);
        return -1;
    }

    hashmap->n = 0;
    hashmap->m = size;

    return 0;
}

void free_hashmap(hashmap_t *hashmap) {

    unsigned int i;

    if (!hashmap) return;

    for (i = 0; i < hashmap->alloc.size; i++) {
        free(hashmap->alloc.alloc_keys[i]);
    }
    free(hashmap->alloc.alloc_keys);
    free(hashmap->keys);
    free(hashmap->values);
}

inline uint64_t hash(hashmap_t *hashmap, uint64_t key) {

    if (!hashmap) return -1;
    return key % hashmap->m;
}

int resize(hashmap_t *hashmap, unsigned int cap) {

    unsigned int i;
    hashmap_t new_hashmap;
    struct key *new_keys;
    void **new_values;

    void **realloc_alloc_keys;

    size_t size = cap * sizeof(uint64_t);
    new_keys = calloc(cap, sizeof(uint64_t));
    if (!new_keys) return -1;

    new_values = malloc(size);
    if (!new_values) {
        free(new_keys);
        return -1;
    }

    realloc_alloc_keys = realloc(hashmap->alloc.alloc_keys, cap);
    if (!realloc_alloc_keys) return -1;

    new_hashmap.m = cap;
    new_hashmap.n = 0;
    for (i = 0; i < hashmap->m; i++) {
        if (hashmap->keys[i].in_use) {
            hashmap->keys[i].in_use = AVAIL;
            put_move(&new_hashmap, hashmap->keys[i].val,
                     hashmap->values[i], hashmap->keys[i].idx_free_lst);
        }
    }

    free(hashmap->keys);
    free(hashmap->values);
    hashmap->m = cap;
    hashmap->values = new_values;
    hashmap->keys = new_keys;

    return 0;
}

int put(hashmap_t *hashmap, uint64_t key, void *value, size_t size) {

    void *hashmap_val = malloc(size);
    if (!hashmap_val) return -1;
    memcpy(hashmap_val, value, size);


    if (hashmap->alloc.max_size == hashmap->alloc.size) {
        void *reall = realloc(hashmap->alloc.alloc_keys, hashmap->alloc.max_size * 2);
        if (!reall) return -1;
        hashmap->alloc.alloc_keys = reall;
        hashmap->alloc.max_size *= 2;
    }

    hashmap->alloc.alloc_keys[hashmap->alloc.size] = hashmap_val;
    hashmap->alloc.size++;

    return put_move(hashmap, key, hashmap_val, hashmap->alloc.size - 1);
}

void *get(hashmap_t *hashmap, uint64_t key) {

    uint64_t i;

    for (i = hash(hashmap, key); hashmap->keys[i].in_use; i = (i + 1) % hashmap->m) {
        if (hashmap->keys[i].val == key) {
            return hashmap->values[i];
        }
    }
    return NULL;
}

int delete(hashmap_t *hashmap, uint64_t key) {
    uint64_t i, j;
    uint64_t redo_key;
    unsigned int redo_idx_free;
    void *redo_value;
    if (!hashmap) return -1;

    i = hash(hashmap, key);
    j = i;

    while (key != hashmap->keys[i].val) {
        i = (i + 1) % hashmap->m;
        if (!hashmap->keys[i].in_use || i == j) return 0;
        // check i == j condition in case if we already iterate on the whole array once
    }

    // free list modif
    // swap
    hashmap->alloc.alloc_keys[hashmap->keys[i].idx_free_lst] =
            hashmap->alloc.alloc_keys[hashmap->alloc.size - 1];
    hashmap->alloc.size--;

    hashmap->keys[i].in_use = AVAIL;
    free(hashmap->values[i]);
    hashmap->values[i] = NULL;


    i = (i + 1) % hashmap->m;
    while (hashmap->keys[i].in_use) {
        redo_key = hashmap->keys[i].val;
        redo_value = hashmap->values[i];
        redo_idx_free = hashmap->keys[i].idx_free_lst;
        hashmap->n--;
        put_move(hashmap, redo_key, redo_value, redo_idx_free);
        i = (i + 1) % hashmap->m;
    }

    hashmap->n--;

    if (hashmap->n > 0 && hashmap->n == hashmap->m / 8) resize(hashmap, hashmap->m / 2);
    return 0;
}
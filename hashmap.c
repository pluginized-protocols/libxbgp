//
// Created by thomas on 23/09/19.
//

#include "hashmap.h"

#include <stdlib.h>
#include <string.h>

int new_hashmap(hashmap_t *hashmap, unsigned int size) {

    if (!hashmap) return -1;

    hashmap->keys = calloc(size, sizeof(struct key));
    if (!hashmap->keys) return -1;

    hashmap->values = calloc(size, sizeof(void *));
    if (!hashmap->values) {
        free(hashmap->keys);
        return -1;
    }

    hashmap->n = 0;
    hashmap->m = size;

    return 0;
}

void free_hashmap(hashmap_t *hashmap) {

    unsigned int i;
    if (!hashmap) return;

    for (i = 0; i < hashmap->m; i++) {
        if (hashmap->values[i] != NULL) {
            free(hashmap->values[i]);
        }
    }

    free(hashmap->keys);
    free(hashmap->values);
}

inline uint64_t hash(hashmap_t *hashmap, uint64_t key) {

    if (!hashmap) return -1;
    return key % hashmap->m;
}

static inline int _ptr_put(hashmap_t *hashmap, uint64_t key, void *value, size_t size, int is_alloc) {

    unsigned int i;
    void *new_val;

    if (hashmap->n >= hashmap->m / 2) resize(hashmap, hashmap->m * 2);

    for (i = hash(hashmap, key); hashmap->keys[i].in_use == IN_USE; i = (i + 1) % hashmap->m) {
        if (hashmap->keys[i].val == key) {
            if (is_alloc) {
                hashmap->values[i] = value;
            } else {
                // assuming "size" is the same for the whole hashmap.
                // macro functions must be used to manipulate the hashmap
                memcpy(hashmap->values[i], value, size);
            }
            return 0;
        }
    }

    if (!is_alloc) {
        new_val = malloc(size);
        if (!new_val) return -1;
        memcpy(new_val, value, size);
    } else {
        new_val = value;
    }

    hashmap->values[i] = new_val;
    hashmap->n++;

    hashmap->keys[i].in_use = IN_USE;
    hashmap->keys[i].val = key;

    return 0;
}

int put(hashmap_t *hashmap, uint64_t key, void *value, size_t size) {
    return _ptr_put(hashmap, key, value, size, 0);
}


void *get(hashmap_t *hashmap, uint64_t key) {

    unsigned int i;

    for (i = hash(hashmap, key); hashmap->keys[i].in_use == IN_USE; i = (i + 1) % hashmap->m) {
        if (hashmap->keys[i].val == key) return hashmap->values[i];
    }
    return NULL;
}


int resize(hashmap_t *hashmap, unsigned int cap) {

    unsigned int i, ret_val;
    hashmap_t new_hm;

    if (new_hashmap(&new_hm, cap) != 0) return -1;

    for (i = 0; i < hashmap->m; i++) {
        ret_val = _ptr_put(&new_hm, hashmap->keys[i].val, hashmap->values[i], hashmap->size_val, 1);
        if (ret_val != 0) return -1; // should never happen since memory is already allocated
    }

    hashmap->keys = new_hm.keys;
    hashmap->values = new_hm.values;
    hashmap->m = new_hm.m;

    return 0;
}

int delete(hashmap_t *hashmap, uint64_t key) {

    unsigned int i, j, k, first, ret_val;

    uint64_t old_key;
    void *old_val;
    first = 1;

    j = hash(hashmap, key);

    for (i = j; hashmap->keys[i].in_use == IN_USE && ((i != j) || first); i = (i + 1) % hashmap->m) {
        if (first) first = 0;
        if (hashmap->keys[i].val == key) {
            hashmap->keys[i].in_use = AVAIL;
            free(hashmap->values[i]);
            hashmap->values[i] = NULL;

            for (k = (i + 1) % hashmap->m; hashmap->keys[k].in_use == IN_USE; k = (k + 1) % hashmap->m) {

                old_key = hashmap->keys[k].val;
                old_val = hashmap->values[k];

                hashmap->keys[k].in_use = AVAIL;
                hashmap->values[k] = NULL;
                hashmap->n--;

                ret_val = _ptr_put(hashmap, old_key, old_val, hashmap->size_val, 1);
                if (ret_val != 0) return -1; // wtf ? should not happen
            }
            return 0;
        }
    }

    return -1;
}
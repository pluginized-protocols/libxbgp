//
// Created by thomas on 23/09/19.
//

#include "hashmap.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int new_hashmap(hashmap_t *hashmap, unsigned int size) {

    if (!hashmap) return -1;

    hashmap->keys = calloc(size, sizeof(struct key));
    if (!hashmap->keys) return -1;

    // hashmap->values is an array of pointers.
    // The real value is stored outside the array
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

void free_hashmap_fun(hashmap_t *h_map, void (*func)(void *)) {

    unsigned int i;
    if (!h_map) return;

    for (i = 0; i < h_map->m; i++) {
        if (h_map->values[i] != NULL) {
            if (func) {
                func(h_map->values[i]);
            }
            free(h_map->values[i]);
        }
    }

    free(h_map->keys);
    free(h_map->values);

}

inline uint64_t hash(hashmap_t *hashmap, uint64_t key) {

    if (!hashmap) return -1;
    return key % hashmap->m;
}

static inline int _ptr_put(hashmap_t *hashmap, uint64_t key, void *value, size_t size, int is_alloc) {

    unsigned int i;
    void *new_val;

    if (!value) {
        return -1;
    }

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
        if (hashmap->keys[i].in_use) {
            ret_val = _ptr_put(&new_hm, hashmap->keys[i].val, hashmap->values[i], hashmap->size_val, 1);
            if (ret_val != 0) return -1; // should never happen since memory is already allocated
        }
    }

    hashmap->keys = new_hm.keys;
    hashmap->values = new_hm.values;
    hashmap->m = new_hm.m;

    return 0;
}

int delete(hashmap_t *hashmap, uint64_t key, void (*cleanup)(void *)) {

    unsigned int i, j, k, first, ret_val;

    uint64_t old_key;
    void *old_val;
    first = 1;

    j = hash(hashmap, key);

    for (i = j; hashmap->keys[i].in_use == IN_USE && ((i != j) || first); i = (i + 1) % hashmap->m) {
        if (first) first = 0;
        if (hashmap->keys[i].val == key) {
            hashmap->keys[i].in_use = AVAIL;
            if (cleanup != NULL) {
                cleanup(hashmap->values[i]);
            }
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

// from included
static inline unsigned int find_next_in_use(struct hashmap *h, unsigned int from, int *err) {
    unsigned int i;
    if (!h) {
        goto err;
    }

    for (i = from; i < h->m; i++) {
        if (h->keys[i].in_use == IN_USE) {
            *err = 0;
            return i;
        }
    }

    err:
    *err = 1;
    return from;
}

int new_hashmap_iterator(struct hashmap_iterator *it, struct hashmap *hashmap) {
    unsigned int i;
    int err;

    if (!hashmap || !it) return -1;

    i = find_next_in_use(hashmap, 0, &err);
    if (err) return -1;

    it->finished = 0;
    it->next_element = i;
    it->hm = hashmap;
    return 0;
}

void *next_hashmap_iterator(struct hashmap_iterator *it) {

    int err;
    void *ret;
    unsigned int i;

    if (it->finished) return NULL;
    ret = it->hm->values[it->next_element];

    i = find_next_in_use(it->hm, it->next_element + 1, &err);
    if (err) {
        it->finished = 1;
    } else {
        it->next_element = i;
    }

    return ret;
}

int hasnext_hashmap_iterator(struct hashmap_iterator *it) {
    if (!it) return 0;
    if (it->finished) return 0;

    return 1;
}
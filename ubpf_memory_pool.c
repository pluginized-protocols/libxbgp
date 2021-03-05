//
// Created by thomas on 12/03/20.
//

#include "ubpf_memory_pool.h"
#include "list.h"
#include "utlist.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

enum {
    MEMPOOL_TYPE_U64,
    MEMPOOL_TYPE_RAW_PTR,
    MEMPOOL_TYPE_PTR,
    MEMPOOL_TYPE_LST
};

static inline void delete_mem_node(struct mem_node *mn) {
    void *clean_ptr;
    mp_element_t *curr, *tmp;

    DL_FOREACH_SAFE(mn->value, curr, tmp) {
        DL_DELETE(mn->value, curr);
        if (curr->clean) {
            clean_ptr = curr->raw == 1 ? *(void **) curr->data : curr->data;
            curr->clean(clean_ptr);
        }
        free(curr);
    }
}

struct mem_pool *new_mempool() {

    struct mem_pool *mp;
    mp = calloc(1, sizeof(*mp));
    if (!mp) return NULL;
    /*mp->node = calloc(1, sizeof(struct mem_node));
    if (!mp->node) {
        free(mp);
        return NULL;
    }*/
    return mp;
}

int add_mempool(struct mem_pool *mp, uint32_t type, void (*cleanup)(void *),
                uint32_t length, void *val, int raw) {
    struct mem_node new_mem, *current_mem_node;
    mp_element_t *element;
    memset(&new_mem, 0, sizeof(struct mem_node));

    new_mem.type = type;
    new_mem.length = length;
    HASH_FIND_INT(mp->node, &type, current_mem_node);

    element = calloc(1, sizeof(*element) + length);
    if (!element) return -1;
    element->len = length;
    element->clean = cleanup;
    if (raw) {
        if (length != sizeof(uintptr_t)) return -1;
        element->raw = 1;
        memcpy(element->data, &val, sizeof(uintptr_t));
    } else {
        element->raw = 0;
        memcpy(element->data, val, length);
    }

    if (current_mem_node == NULL) { // if NULL, put the new mem_node in the mem_pool
        struct mem_node *cpy_mem = calloc(1, sizeof(new_mem));
        if (!cpy_mem) return -1;
        memcpy(cpy_mem, &new_mem, sizeof(new_mem));
        HASH_ADD_INT(mp->node, type, cpy_mem);
        current_mem_node = cpy_mem;
    }

    DL_APPEND(current_mem_node->value, element);
    return 0;
}

int get_mempool_data(struct mem_pool *mp, uint32_t type, struct mempool_data *data) {

    struct mem_node *node;
    if (!mp) return -1;

    HASH_FIND_INT(mp->node, &type, node);
    if (!node) return -1;

    data->length = node->length;
    data->data = node->value->raw == 1 ? *(void **) node->value->data : node->value->data;

    return 0;
}

void remove_memnode(struct mem_pool *mp, struct mem_node *node) {
    if (!node) return;
    delete_mem_node(node);
    HASH_DELETE(hh, mp->node, node);
    free(node);
}

void remove_mempool(struct mem_pool *mp, uint32_t type) {
    struct mem_node *pool;
    HASH_FIND_INT(mp->node, &type, pool);
    if (!pool) return;
    remove_memnode(mp, pool);
}

void delete_mempool(struct mem_pool *mp) {
    struct mem_node *curr, *temp;
    HASH_ITER(hh, mp->node, curr, temp) {
        remove_memnode(mp, curr);
    }
}

struct mem_node_it *new_memnode_iterator(struct mem_node *node) {
    struct mem_node_it *it;
    if (node == NULL) return NULL;
    it = malloc(sizeof(*it));
    if (!it) return NULL;
    it->node = node;
    it->curr_element = node->value;
    return it;
}

void *memnode_next_element(struct mem_node_it *it) {
    mp_element_t *elem;
    if (!it || !it->curr_element) return NULL;
    elem = it->curr_element;
    it->curr_element = it->curr_element->next;
    return elem->data;
}

int memnode_hasnext(struct mem_node_it *it) {
    if (!it) return 0;
    if (!it->curr_element) return 0;
    return 1;
}

void delete_memnode_iterator(struct mem_node_it *it) {
    free(it);
}


struct mem_pool_it *new_mempool_iterator(struct mem_pool *mp) {
    struct mem_node *node;
    struct mem_pool_it *it;
    if (!mp) return NULL;

    it = malloc(sizeof(*it));
    if (!it) return NULL;

    node = mp->node;

    it->it.node = node;
    it->it.pool = mp;
    it->it.it = new_memnode_iterator(node);
    if (!it->it.it) return NULL;

    return it;
}

void delete_mempool_iterator(struct mem_pool_it *it) {
    delete_memnode_iterator(it->it.it);
    free(it);
}

void *next_mempool_iterator(struct mem_pool_it *it) {

    struct mem_node *node;

    if (!memnode_hasnext(it->it.it)) {
        node = it->it.node->hh.next;
        if (!node) return NULL;
        it->it.node = node;
        delete_memnode_iterator(it->it.it);
        it->it.it = new_memnode_iterator(node);
    }
    return memnode_next_element(it->it.it);
}

int mempool_hasnext(struct mem_pool_it *it) {
    if (!memnode_hasnext(it->it.it)) {
        return it->it.node->hh.next != NULL;
    }
    return 1;
}

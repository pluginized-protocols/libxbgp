//
// Created by thomas on 14/04/22.
//

#include <stddef.h>

#include "fake_api.h"

static char available_mem[4096];

void *fake_alloc(size_t size) {
    void *ptr;
    size_t aligned_size = (size + 7u) & (-8u);
    if (aligned_size > sizeof(available_mem)) return NULL;

    ptr = available_mem + 64;

    return ptr;
}
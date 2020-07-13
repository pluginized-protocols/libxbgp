//
// Created by thomas on 14/08/19.
//

#include "ubpf_context.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

context_t *new_context() {

    context_t *ctx = calloc(1, sizeof(context_t));
    if (!ctx) return NULL;

    return ctx;
}

int free_context(context_t *ctx) {
    free(ctx);
    return 0;
}
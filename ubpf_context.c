//
// Created by thomas on 14/08/19.
//

#include "ubpf_context.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

static map_allowed_ctx_t current_context;
map_allowed_ctx_t *map_ctx = NULL;

#define MAX_INIT_CONTEXT 32

static inline void init_ctx_map() {
    if (!map_ctx) {
        hashmap_new(&current_context, MAX_INIT_CONTEXT);
        map_ctx = &current_context;
    }
}

void destroy_context() {
    if (!map_ctx) return;

    hashmap_destroy(map_ctx);
    map_ctx = NULL;
}


context_t *new_context(plugin_t *p) {

    if (!p) return NULL;
    init_ctx_map();

    context_t *ctx = calloc(1, sizeof(context_t));
    if (!ctx) return NULL;

    ctx->p = p;

    return ctx;
}

int register_context(context_t *ctx) {
    int return_val;
    init_ctx_map();

    return_val = hashmap_put(map_ctx, (uint64_t) ctx, 1) == 0;
    return return_val;
}

int unregister_context(context_t *ctx) {

    hashmap_delete(map_ctx, (uint64_t) ctx);

    return 0;
}
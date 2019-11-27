//
// Created by thomas on 14/08/19.
//

#include "ubpf_context.h"
#include <string.h>
#include <stdlib.h>

static map_allowed_ctx_t current_context;
map_allowed_ctx_t *map_ctx = NULL;

#define STRING_PTR_ARRAY 17

static inline void init_ctx_map() {
    if (!map_ctx) {
        map_init(&current_context);
        map_ctx = &current_context;
    }
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

    init_ctx_map();

    char key[STRING_PTR_ARRAY];

    memset(key, 0, sizeof(char) * STRING_PTR_ARRAY);

    if (ptr_to_string(key, ctx, STRING_PTR_ARRAY) != 0) {
        return -1;
    }

    return map_set(map_ctx, key, 1) == 0;
}

int unregister_context(context_t *ctx) {

    char key[STRING_PTR_ARRAY];
    memset(key, 0, sizeof(char) * STRING_PTR_ARRAY);
    if (ptr_to_string(key, ctx, STRING_PTR_ARRAY) != 0) {
        return -1;
    }

    map_remove(map_ctx, key);
    return 0;
}

int context_ok(context_t *ctx) {

    char key[STRING_PTR_ARRAY];
    memset(key, 0, STRING_PTR_ARRAY * sizeof(char));

    ptr_to_string(key, ctx, STRING_PTR_ARRAY * sizeof(char));

    init_ctx_map();

    if (!ctx) return 0;
    if (!map_get(map_ctx, key)) return 0;

    return ctx->args == NULL ? 0 : 1; // check if args pointer is not NULL
}

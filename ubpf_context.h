//
// Created by thomas on 14/08/19.
//

#ifndef FRR_UBPF_UBPF_CONTEXT_H
#define FRR_UBPF_UBPF_CONTEXT_H


#include "bpf_plugin.h"
#include "hashmap.h"

typedef struct bytecode_context context_t;
typedef hashmap_t(short) map_allowed_ctx_t;

/**
 * This structure is passed to every plugins
 * as one of their arguments. The structure
 * is accessible through it. However, every pointers
 * contained in this structure is not accessible by the
 * plugin and every attempt to dereference (during run-time)
 * any of these will result in a crash of the plugin.
 * (i.e. the VM stops its execution)
 */
struct bytecode_context {
    // contains internal information needed to run every plugins
    // You should add here every needed thing to correctly run
    // a given plugin
    plugin_t *p;
    void *args;    // pointer to the argument of the plugin used to
#define LENGTH_CONTEXT_ERROR 50
    char error[LENGTH_CONTEXT_ERROR]; // string with small indication of the error;
    int error_status;
};


context_t *new_context(plugin_t *p);

int register_context(context_t *ctx);

int unregister_context(context_t *ctx);

int context_ok(context_t *ctx);

void destroy_context(void);


#endif //FRR_UBPF_UBPF_CONTEXT_H

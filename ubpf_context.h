//
// Created by thomas on 14/08/19.
//

#ifndef FRR_UBPF_UBPF_CONTEXT_H
#define FRR_UBPF_UBPF_CONTEXT_H


#include "bpf_plugin.h"
#include "context_hdr.h"


typedef hashmap_t(short) map_allowed_ctx_t;

context_t *new_context(plugin_t *p);

int register_context(context_t *ctx);

int unregister_context(context_t *ctx);

int context_ok(context_t *ctx);

void destroy_context(void);


#endif //FRR_UBPF_UBPF_CONTEXT_H

//
// Created by thomas on 14/08/19.
//

#ifndef FRR_UBPF_UBPF_CONTEXT_H
#define FRR_UBPF_UBPF_CONTEXT_H


#include "bpf_plugin.h"
#include "context_hdr.h"

context_t *new_context(void);

int free_context(context_t *ctx);

args_t *get_args_from_context(context_t *ctx);


#endif //FRR_UBPF_UBPF_CONTEXT_H

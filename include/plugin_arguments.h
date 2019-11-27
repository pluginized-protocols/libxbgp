//
// Created by thomas on 19/11/18.
//

#ifndef FRR_UBPF_PLUGIN_ARGUMENTS_H
#define FRR_UBPF_PLUGIN_ARGUMENTS_H

#include "../hashmap.h"

#define kind_ptr 0
#define kind_primitive 1

typedef struct {
    void *arg;
    size_t len;
    short kind;
    unsigned int type; // custom type defined by the protocol insertion point
} bpf_args_t;

typedef struct {
    bpf_args_t *args;
    int nargs;
    int plugin_type;
} bpf_full_args_t;

typedef hashmap_t(bpf_full_args_t *) map_args_bpf_t;

#endif //FRR_UBPF_PLUGIN_ARGUMENTS_H

//
// Created by thomas on 19/11/18.
//

#ifndef FRR_UBPF_PLUGIN_ARGUMENTS_H
#define FRR_UBPF_PLUGIN_ARGUMENTS_H

#include <stddef.h>
#include <stdint.h>

#define kind_null 0
#define kind_ptr 1
#define kind_primitive 2
#define kind_hidden 3

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
    uintptr_t return_value;
} bpf_full_args_t;

#endif //FRR_UBPF_PLUGIN_ARGUMENTS_H

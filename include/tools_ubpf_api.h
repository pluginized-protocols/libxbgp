//
// Created by thomas on 19/08/19.
//

#ifndef FRR_UBPF_TOOLS_UBPF_API_H
#define FRR_UBPF_TOOLS_UBPF_API_H

#include "include/plugin_arguments.h"
#include "ubpf_context.h"


struct prefix {
    uint8_t family;
    uint16_t prefixlen;
    uint8_t u[20];
};

enum RESERVED_RETURN_VAL {
    BPF_CONTINUE = 0,

};


#define UNUSED(arg) ((void) arg)

#define safe_args(args, position, type_arg) \
(valid_args(args) && (args)->nargs > position && (args)->args[position].type == type_arg)

#define get_arg(args, position, cast) \
((cast) ((args)->args[position].arg))

#define api_args context_t *vm_ctx, bpf_full_args_t *args, int pos_arg

#define auto_get(type, cast) \
safe_args(args, pos_arg, type) ? get_arg(args, pos_arg, cast) : NULL


#endif //FRR_UBPF_TOOLS_UBPF_API_H

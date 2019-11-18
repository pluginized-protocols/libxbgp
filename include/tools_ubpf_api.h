//
// Created by thomas on 19/08/19.
//

#ifndef FRR_UBPF_TOOLS_UBPF_API_H
#define FRR_UBPF_TOOLS_UBPF_API_H

#include "ubpf_tools/include/plugin_arguments.h"
#include "ubpf_tools/ubpf_context.h"



#define UNUSED(arg) ((void) arg)

#define safe_args(args, position, type_arg) \
(valid_args(args) && (args)->nargs > position && (args)->args[position].type == type_arg)

#define get_arg(args, position, cast) \
((cast) ((args)->args[position].arg))

#define api_args context_t *vm_ctx, bpf_full_args_t *args, int pos_arg

#define auto_get(type, cast) \
safe_args(args, pos_arg, type) ? get_arg(args, pos_arg, cast) : NULL


#endif //FRR_UBPF_TOOLS_UBPF_API_H

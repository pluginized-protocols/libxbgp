//
// Created by thomas on 19/08/19.
//

#ifndef FRR_UBPF_TOOLS_UBPF_API_H
#define FRR_UBPF_TOOLS_UBPF_API_H

#include "plugin_arguments.h"
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

/**
 * On PRE and POST mode, these are the only value
 * accepted by the manager.
 * On REPLACE mode, the return value is not checked
 * by the manager. If the function has to return
 * a specific value --> TODO
 */
/*enum RESERVED_RETURN_VAL {
    BPF_UNDEF = 0,
    BPF_CONTINUE, // continue the execution of the mode (ONLY in PRE or POST mode)
    BPF_FAILURE, // the uBPF code has badly terminated. On PRE and POST mode, continue the execution of other modes
    BPF_SUCCESS, // the uBPF code has successfully terminated. On PRE and POST, tells to the manager to return (other mode are skipped)
    BPF_MAX_RESERVED_RETURN_VAL
};*/

#ifndef UNUSED
#define UNUSED __attribute__((unused))
#endif

#define get_arg_from_type(ctx, type_arg) ({ \
    int _i; \
    void *ret; \
    args_t *fargs; \
    ret = NULL; \
    fargs = get_args_from_context(ctx); \
    for (_i = 0; _i < fargs->nargs; _i++) { \
        if (fargs->args[_i].type == (type_arg)) { \
            ret = fargs->args[_i].arg; \
            break; \
        } \
    } \
    ret; \
})


#endif //FRR_UBPF_TOOLS_UBPF_API_H

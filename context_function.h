//
// Created by thomas on 11/01/22.
//

#ifndef UBPF_TOOLS_CONTEXT_FUNCTION_H
#define UBPF_TOOLS_CONTEXT_FUNCTION_H

#include <ffi.h>
#include <stdint.h>
#include <stdio.h>
#include "ubpf_context.h"
#include "tools_ubpf_api.h"

#define ARGS args

#define api_name_closure(name) closure_##name

#define def_fun_api(name, ret_val_type, ...) \
void api_name_closure(name)(ffi_cif *cif UNUSED, void *ret, void **ARGS, void *usr_data) { \
    ((void) ARGS);                                         \
    ret_val_type ret_val;          \
    context_t *ctx = usr_data;\
    ret_val = name(ctx,##__VA_ARGS__);          \
    *(ret_val_type *) ret = ret_val; \
}

#define def_fun_api_void(name, ...) \
void api_name_closure(name)(ffi_cif *cif UNUSED, void *ret UNUSED, void **ARGS, void *usr_data) { \
    ((void) ARGS);  /* make compiler silent */                               \
    context_t *ctx = usr_data;\
    name(ctx,##__VA_ARGS__);   \
}

typedef struct ubpf_closure closure_t;

typedef void (api_function)(ffi_cif *, void *ret, void **args, void *ctx);

struct ubpf_closure {
    ffi_cif cif;
    ffi_closure *closure;

    void *fn;

    /* VM context */
    context_t *context_vm;

    int args_nb;
    ffi_type *arg_type[0];
};

int ffi_closure_support(void);

struct ubpf_closure *make_closure(api_function *fn, int args_nb,
                                  ffi_type **args_type, ffi_type *return_type,
                                  void *exec_context);

void free_closure(struct ubpf_closure *closure);


#endif //UBPF_TOOLS_CONTEXT_FUNCTION_H

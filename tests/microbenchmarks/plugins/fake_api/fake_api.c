//
// Created by thomas on 14/04/22.
//

#include <stddef.h>

#include "fake_api.h"

#include "xbgp_compliant_api/xbgp_api_function_helper.h"
#include "xbgp_compliant_api/xbgp_common.h"
#include "context_function.h"

#define NOINLINE __attribute__ ((noinline))

static char available_mem[4096];

static int my_mem = 0;

void * NOINLINE fake_alloc(context_t *ctx UNUSED, size_t size) {
    void *ptr;
    size_t aligned_size = (size + 7u) & (-8u);
    if (aligned_size > sizeof(available_mem)) return NULL;

    ptr = available_mem;
    // do sthg to force compile to call this function
    ((size_t *)ptr)[0] = size;

    return ptr;
}

int * NOINLINE get_memory(context_t *ctx UNUSED) {
    int *ptr_to_data = fake_alloc(NULL, sizeof(my_mem));

    *ptr_to_data = my_mem + *((int *) ptr_to_data);

    return ptr_to_data;
}

int NOINLINE set_memory(context_t *ctx UNUSED, int value) {
    int *random_val = fake_alloc(NULL, sizeof(value));
    my_mem = value + *random_val;
    return 0;
}

static def_fun_api(get_memory, int *);

static def_fun_api(set_memory, int, *(int *) ARGS[0]);

static def_fun_api(fake_alloc, void *, *(size_t *) ARGS[0]);

proto_ext_fun_t fake_funcs[] = {
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_ulong
                },
                .return_type = &ffi_type_pointer,
                .name = "fake_alloc",
                .args_nb = 1,
                .fn = fake_alloc,
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(fake_alloc)
        },
        {
                .args_type = NULL,
                .return_type = &ffi_type_pointer,
                .name = "get_memory",
                .args_nb = 0,
                .fn = get_memory,
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(get_memory)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_sint
                },
                .args_nb = 1,
                .return_type = &ffi_type_sint,
                .name = "set_memory",
                .fn = set_memory,
                .attributes = HELPER_ATTR_NONE,
                .closure_fn = api_name_closure(set_memory)
        },
        proto_ext_func_null
};
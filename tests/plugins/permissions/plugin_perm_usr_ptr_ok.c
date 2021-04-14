//
// Created by thomas on 17/03/21.
//
#include "include/bytecode_public.h"
#include "example_funcs.h"

uint64_t macro_void_test(args_t *args UNUSED) {
    perm_none();
    perm_usr_ptr();

    return 0;
}
//
// Created by thomas on 17/03/21.
//
#include "include/bytecode_public.h"
#include "example_funcs.h"

uint64_t macro_void_test(args_t *args UNUSED) {
    perm_none();
    perm_usr_ptr();
    perm_read();
    perm_write();

    perm_usr_ptr_read();
    perm_usr_ptr_write();
    perm_read_write();
    perm_all();

    return 0;
}
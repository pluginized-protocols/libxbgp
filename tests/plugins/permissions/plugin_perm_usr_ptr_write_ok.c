//
// Created by thomas on 17/03/21.
//

#include "include/bytecode_public.h"
#include "example_funcs.h"

uint64_t macro_void_test() {
    perm_usr_ptr();
    perm_write();
    perm_usr_ptr_write();
    return 0;
}

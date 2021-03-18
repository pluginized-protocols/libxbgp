//
// Created by thomas on 17/03/21.
//

#include "include/bytecode_public.h"
#include "example_funcs.h"

uint64_t macro_void_test() {
    perm_read();
    perm_write();
    perm_read_write();
    return 0;
}

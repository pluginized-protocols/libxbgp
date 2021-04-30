//
// Created by thomas on 29/04/21.
//

#include "include/bytecode_public.h"

uint64_t macro_void_test() {

    int **malloc_val = get_arg(42);
    int read_val;

    if (!malloc_val) {
        return EXIT_FAILURE;
    }

    read_val = **malloc_val;
    log_msg(L_DEBUG "SUPER LOG is %d", LOG_INT(read_val));

    **malloc_val = 2021;
    return 42;
}

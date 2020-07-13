//
// Created by thomas on 8/05/20.
//

#include "../../include/bytecode_public.h"

// test_replace_first_no_fallback

void set_return_value(int a);

uint64_t replace_part_1() {

    int *a = get_arg(0);
    int *b = get_arg(1);
    int *must_next = get_arg(2);

    if (!a || !b || !must_next) {
        ebpf_print("Failed to retrieve args (p1)\n");
        return EXIT_FAILURE;
    }

    if (*must_next) {
        next();
    }

    set_return_value(*a + *b);
    return EXIT_SUCCESS;
}

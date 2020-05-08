//
// Created by thomas on 8/05/20.
//

#include "../../include/public_bpf.h"

// test_replace_first_no_fallback

void set_return_value(int a);

uint64_t replace_part_1(bpf_full_args_t *args) {

    int *a = bpf_get_args(0, args);
    int *b = bpf_get_args(1, args);
    int *must_next = bpf_get_args(2, args);

    if (!a || !b || !must_next) {
        return EXIT_FAILURE;
    }

    if (*must_next) {
        next();
    }

    set_return_value(*a + *b);
    return EXIT_SUCCESS;
}

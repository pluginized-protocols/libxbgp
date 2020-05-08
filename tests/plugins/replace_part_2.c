//
// Created by thomas on 8/05/20.
//

//
// Created by thomas on 8/05/20.
//

#include "../../include/public_bpf.h"

// test_replace_first_no_fallback

void set_return_value(int a);

uint64_t replace_part_2(bpf_full_args_t *args) {

    int *a = bpf_get_args(0, args);
    int *b = bpf_get_args(1, args);

    int *must_fallback = bpf_get_args(3, args);

    int comp;

    if (!a || !b || !must_fallback) {
        return EXIT_FAILURE;
    }

    if (*must_fallback) {
        next(); // next should execute the fallback code
        // return EXIT_FAILURE could tells to fallback too
    }

    comp = *a + *b;

    if (comp == 42) {
        set_return_value(222);
    } else {
        set_return_value(1);
    }

    return EXIT_SUCCESS;
}

//
// Created by thomas on 8/05/20.
//

//
// Created by thomas on 8/05/20.
//

#include "../../include/bytecode_public.h"

// test_replace_first_no_fallback

void set_return_value(int a);

uint64_t replace_part_2() {

    int *a = get_arg(0);
    int *b = get_arg(1);

    int *must_fallback = get_arg(3);

    int comp;

    if (!a || !b || !must_fallback) {
        ebpf_print("Failed to retrieve args (p2)\n");
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

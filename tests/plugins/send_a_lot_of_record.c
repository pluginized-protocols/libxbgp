//
// Created by twirtgen on 8/01/20.
//

#include "../../include/public_bpf.h"

uint64_t big_test(bpf_full_args_t *args) {

    int i;
    int value = 1;

    for (i = 0; i < 42; i++) {
        if (!send_to_monitor(&value, sizeof(int), 1)) return EXIT_FAILURE;
        value++;
    }
    return EXIT_SUCCESS;
}
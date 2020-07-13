//
// Created by twirtgen on 8/01/20.
//

#include "../../include/bytecode_public.h"

uint64_t big_test() {

    int i;
    int value = 1;

    for (i = 0; i < 42; i++) {
        if (!send_to_monitor(&value, sizeof(int), 1)) return EXIT_FAILURE;
        value++;
    }
    return EXIT_SUCCESS;
}

//
// Created by twirtgen on 8/01/20.
//

#include "../../include/bytecode_public.h"

uint64_t big_test() {

    int i;
    int value = 1;

    struct vargs vargs;

    for (i = 0; i < 42; i++) {

        vargs = (struct vargs) {
                .nb_args = 1,
                .args = (struct vtype[]) {
                        {.val = {.sint = i}, .type = VT_SINT}
                }
        };

        if (!super_log(L_INFO "I send the value %d", &vargs)) return EXIT_FAILURE;
        value++;
    }
    return EXIT_SUCCESS;
}

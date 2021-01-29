//
// Created by twirtgen on 7/01/20.
//

#include "../../include/bytecode_public.h"

uint64_t send_monitoring_data() {

    int data = 42;
    int ret_val;

    struct vargs vargs = {
            .nb_args = 1,
            .args = (struct vtype[]) {
                    {.val = {.sint = data}, .type = VT_SINT}
            }
    };

    ret_val = super_log(L_INFO "I send the value %d", &vargs) ? EXIT_SUCCESS : EXIT_FAILURE;

    return ret_val;
}

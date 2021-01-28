//
// Created by twirtgen on 8/01/20.
//

#include "../../include/bytecode_public.h"

uint64_t ebpf_main() {

    struct vargs vargs;

    const char coucou[] = "Je suis une data"; // length 16
    const char coucou2[] = "En voici un autre";
    int value = 3844;
    int value2 = 2142;

    vargs = (struct vargs) {
            .nb_args = 1,
            .args = (struct vtype[]) {
                    {.val = {.pvalue = coucou}, .type = VT_POINTER}
            }
    };
    if (!super_log(L_INFO "Msg sent: %s", &vargs)) return EXIT_FAILURE;

    vargs = (struct vargs) {
            .nb_args = 1,
            .args = (struct vtype[]) {
                    {.val = {.pvalue = coucou2}, .type = VT_POINTER}
            }
    };
    if (!super_log(L_INFO "Msg sent: %s", &vargs)) return EXIT_FAILURE;

    vargs = (struct vargs) {
            .nb_args = 1,
            .args = (struct vtype[]) {
                    {.val = {.sint = value}, .type = VT_SINT}
            }
    };
    if (!super_log(L_INFO "Int sent: %d", &vargs)) return EXIT_FAILURE;

    vargs = (struct vargs) {
            .nb_args = 1,
            .args = (struct vtype[]) {
                    {.val = {.sint = value2}, .type = VT_SINT}
            }
    };
    if (!super_log(L_INFO "Int sent: %d", &vargs)) return EXIT_FAILURE;


    return EXIT_SUCCESS;
}

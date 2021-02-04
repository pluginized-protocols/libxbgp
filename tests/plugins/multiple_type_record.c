//
// Created by twirtgen on 8/01/20.
//

#include "../../include/bytecode_public.h"

uint64_t ebpf_main() {

    const char coucou[] = "Je suis une data"; // length 16
    const char coucou2[] = "En voici un autre";
    int value = 3844;
    int value2 = 2142;


    if (!log_msg(L_INFO "Msg sent: %s", LOG_PTR(coucou))) return EXIT_FAILURE;

    if (!log_msg(L_INFO "Msg sent: %s", LOG_PTR(coucou2))) return EXIT_FAILURE;

    if (!log_msg(L_INFO "Int sent: %d", LOG_INT(value))) return EXIT_FAILURE;

    if (!log_msg(L_INFO "Int sent: %d", LOG_INT(value2))) return EXIT_FAILURE;

    // test with a lot of argument (more than 5)
    if (!log_msg(L_INFO "Big Test %s %s %d %d %p", LOG_PTR(coucou), LOG_PTR(coucou2),
                 LOG_INT(value), LOG_INT(value2), LOG_PTR(coucou))) {
        return EXIT_FAILURE;
    }


    return EXIT_SUCCESS;
}

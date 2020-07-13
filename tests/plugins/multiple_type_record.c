//
// Created by twirtgen on 8/01/20.
//

#include "../../include/bytecode_public.h"

uint64_t ebpf_main() {

    const char coucou[] = "Je suis une data"; // length 16
    const char coucou2[] = "En voici un autre";
    int value = 3844;
    int value2 = 2142;

    if (!send_to_monitor(coucou, sizeof(coucou), 2)) return EXIT_FAILURE;
    if (!send_to_monitor(&value, sizeof(value), 1)) return EXIT_FAILURE;
    if (!send_to_monitor(coucou2, sizeof(coucou2), 2)) return EXIT_FAILURE;
    if (!send_to_monitor(&value2, sizeof(value), 1)) return EXIT_FAILURE;


    return EXIT_SUCCESS;
}

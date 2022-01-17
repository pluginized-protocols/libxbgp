//
// Created by twirtgen on 8/01/20.
//

#include <xbgp_compliant_api/xbgp_plugin_api.h>

uint64_t big_test() {

    int i;
    int value = 1;

    for (i = 0; i < 42; i++) {
        if (!log_msg(L_INFO "I send the value %d", LOG_INT(i))) return EXIT_FAILURE;
        value++;
    }
    return EXIT_SUCCESS;
}

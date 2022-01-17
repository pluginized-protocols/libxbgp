//
// Created by thomas on 29/04/21.
//

#include <xbgp_compliant_api/xbgp_plugin_api.h>

uint64_t macro_void_test() {

    int **malloc_val = get_arg(42);

    if (!malloc_val) {
        return EXIT_FAILURE;
    }

    int a = 42 + 3;
    log_msg(L_DEBUG "The logger logs %d\n", LOG_INT(a));

    return 42;
}
//
// Created by thomas on 13/04/22.
//

#include "dumb_functions.h"
#include  "../../../xbgp_deps/xbgp_compliant_api/xbgp_plugin_api.h"
#include "../defs_type.h"

uint64_t loop_10(exec_info_t *info) {
    int i;
    uint64_t my_mod;

    my_mod = info->replace_return_value;
    for (i = 0; i < 10; i++) {
        my_mod = (my_mod + i) % info->insertion_point_id;
    }
    return my_mod;
}
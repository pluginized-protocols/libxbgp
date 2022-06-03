//
// Created by thomas on 13/04/22.
//

#include "dumb_functions.h"
#include  "../../../xbgp_deps/xbgp_compliant_api/xbgp_plugin_api.h"
#include "../defs_type.h"

uint64_t direct_return(exec_info_t *info) {
    return EXIT_BPF_SUCCESS;
}
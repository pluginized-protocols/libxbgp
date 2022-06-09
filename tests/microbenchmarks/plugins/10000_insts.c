//
// Created by thomas on 13/04/22.
//

#include "dumb_functions.h"
#include  "../../../xbgp_deps/xbgp_compliant_api/xbgp_plugin_api.h"
#include "../defs_type.h"

uint64_t loop_10000(exec_info_t *info UNUSED) {
    unsigned int i;
    unsigned int nimp;
    unsigned int bizarre;

    nimp = 56;

    bizarre = nimp + 1;
    for (i = 1; i <= 10000; i++) {
        nimp += (nimp - bizarre + (42u * i));
        bizarre += i * nimp - 2u + bizarre + nimp * bizarre;
    }


    return nimp;
}
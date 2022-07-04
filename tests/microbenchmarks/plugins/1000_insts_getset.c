//
// Created by thomas on 13/04/22.
//

#include "dumb_functions.h"
#include  "../../../xbgp_deps/xbgp_compliant_api/xbgp_plugin_api.h"
#include "../defs_type.h"

#ifdef PLUGIN_MODE
#include "./fake_api/fake_api_plugin.h"
#else
#include "fake_api/fake_api.h"
#endif

uint64_t loop_1000_getset(exec_info_t *info UNUSED) {
    unsigned int i;
    unsigned int nimp;
    unsigned int bizarre;

    nimp = 0;
    bizarre = nimp + 1;
    for (i = 1; i <= 1000; i++) {
#ifdef PLUGIN_MODE
        nimp = *get_memory();
#else
        nimp = *get_memory(NULL);
#endif
        nimp += (nimp - bizarre + (42u * i));
        bizarre += i * nimp - 2u + bizarre + nimp * bizarre;
#ifdef PLUGIN_MODE
        set_memory((int) nimp);
#else
        set_memory(NULL, (int) nimp);
#endif
    }

    return nimp;
}
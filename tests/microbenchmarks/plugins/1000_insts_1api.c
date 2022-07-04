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

uint64_t loop_1000_1api(exec_info_t *info UNUSED) {
    unsigned int i;
    uint64_t *my_mod_2;
    //uint64_t my_mod = 0;
    unsigned int nimp;
    unsigned int bizarre;

#ifdef PLUGIN_MODE
    my_mod_2 = fake_alloc(sizeof(*my_mod_2) * 5);
#else
    my_mod_2 = fake_alloc(NULL, sizeof(*my_mod_2) * 5);
#endif
    if (!my_mod_2) {
        ebpf_print("[Warning] Unable to allocate memory");
        return -1;
    }

    nimp = 0;
    bizarre = nimp + 1;
    for (i = 1; i <= 1000; i++) {
        nimp += (nimp - bizarre + (42u * i));
        bizarre += i * nimp - 2u + bizarre + nimp * bizarre;
    }

    return nimp;
}
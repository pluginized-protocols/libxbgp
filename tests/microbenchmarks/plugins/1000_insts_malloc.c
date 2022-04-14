//
// Created by thomas on 13/04/22.
//

#include "dumb_functions.h"
#include  "../../../xbgp_deps/xbgp_compliant_api/xbgp_plugin_api.h"
#include "../defs_type.h"

#ifndef PLUGIN_MODE
extern void *fake_alloc(size_t size);
#endif

uint64_t loop_1000_malloc(exec_info_t *info) {
    int i;
    uint64_t *my_mod_2;
    uint64_t my_mod;

#ifdef PLUGIN_MODE
    my_mod_2 = ctx_malloc(sizeof(my_mod_2));
#else
    my_mod_2 = fake_alloc(sizeof(my_mod_2));
#endif
    if (!my_mod_2) {
        ebpf_print("[Warning] Unable to allocate memory");
        return -1;
    }

    *my_mod_2 = info->replace_return_value;
    for (i = 0; i < 1000; i++) {
        *my_mod_2 = (*my_mod_2 + i) % info->insertion_point_id;
    }
    my_mod = *my_mod_2;
    return my_mod;
}
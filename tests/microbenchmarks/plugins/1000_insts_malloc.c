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

uint64_t loop_1000_malloc(exec_info_t *info) {
    unsigned int i;
    uint64_t *my_mod_2;
    uint64_t my_mod = 0;

#ifdef PLUGIN_MODE
    my_mod_2 = fake_alloc(sizeof(*my_mod_2) * 5);
#else
    my_mod_2 = fake_alloc(NULL, sizeof(*my_mod_2) * 5);
#endif
    if (!my_mod_2) {
        ebpf_print("[Warning] Unable to allocate memory");
        return -1;
    }
#ifdef PLUGIN_MODE
    my_mod_2[0] = *get_memory();
#else
    my_mod_2[0] = *get_memory(NULL);
#endif
    for (i = 1; i <= 1000; i++) {
        my_mod_2[i % 5] = (my_mod_2[(i-1) % 5]) % info->insertion_point_id;
    }

    for (i = 0; i < 5; i++) {
        my_mod += my_mod_2[i];
    }

#ifdef PLUGIN_MODE
    set_memory((int) my_mod);
#else
    set_memory(NULL, (int) my_mod);
#endif

    return my_mod;
}
//
// Created by twirtgen on 3/12/19.
//

#include <xbgp_compliant_api/xbgp_plugin_api.h>

uint64_t main_replace_simple() {

    int *replace = ctx_shmget(1);
    *replace += 10;

    return *replace;
}

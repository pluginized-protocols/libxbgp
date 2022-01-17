//
// Created by twirtgen on 5/12/19.
//

#include <xbgp_compliant_api/xbgp_plugin_api.h>

uint64_t main_macro_weird() {

    int *a = get_arg(32);
    char *b = get_arg(33);
    uint32_t *c = get_arg(34);
    short *d = get_arg(35);

    if (!a || !b || !c || !d) return 0;

    return (uint64_t) *a + *b + *c + *d;
}

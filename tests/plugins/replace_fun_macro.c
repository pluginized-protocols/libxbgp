//
// Created by twirtgen on 5/12/19.
//

#include "../../include/public_bpf.h"

uint64_t main_macro_weird(bpf_full_args_t *args) {

    int *a = bpf_get_args(0, args);
    char *b = bpf_get_args(1, args);
    uint32_t *c = bpf_get_args(2, args);
    short *d = bpf_get_args(3, args);

    if (!a || !b || !c || !d) return 0;

    return *a + *b + *c + *d;
}
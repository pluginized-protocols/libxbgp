//
// Created by twirtgen on 3/12/19.
//

#include "../../include/public_bpf.h"

uint64_t main_pre_zero(bpf_full_args_t *args) {

    int *arg = bpf_get_args(0, args);

    int *init = ctx_shmnew(1, sizeof(int));
    *init = *arg;

    return *init;
}

//
// Created by twirtgen on 3/12/19.
//

#include "../../include/public_bpf.h"

uint64_t main_replace_simple(bpf_full_args_t *args) {

    int *replace = ctx_shmget(1);
    *replace += 10;

    return *replace;
}
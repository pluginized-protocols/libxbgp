//
// Created by twirtgen on 3/12/19.
//

#include "../../include/public_bpf.h"

uint64_t main_post_simple(bpf_full_args_t *args) {

    int return_val;

    int *init = ctx_shmget(1);
    *init += 10;

    return_val = *init;

    ctx_shmrm(1);

    return return_val;
}
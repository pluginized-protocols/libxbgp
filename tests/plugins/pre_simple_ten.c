//
// Created by twirtgen on 3/12/19.
//

#include "../../include/public_bpf.h"

uint64_t main_pre_ten(bpf_full_args_t *args) {

    int *mdr = ctx_shmget(1);
    *mdr += 10;

    return *mdr;
}

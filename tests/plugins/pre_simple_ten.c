//
// Created by twirtgen on 3/12/19.
//

#include "../../include/bytecode_public.h"

uint64_t main_pre_ten() {

    int *mdr = ctx_shmget(1);
    *mdr += 10;

    return *mdr;
}

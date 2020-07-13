//
// Created by twirtgen on 3/12/19.
//

#include "../../include/bytecode_public.h"

uint64_t main_pre_zero() {

    int *arg = get_arg(42);

    int *init = ctx_shmnew(1, sizeof(int));
    *init = *arg;

    return *init;
}

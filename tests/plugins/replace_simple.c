//
// Created by twirtgen on 3/12/19.
//

#include "../../include/bytecode_public.h"

uint64_t main_replace_simple() {

    int *replace = ctx_shmget(1);
    *replace += 10;

    return *replace;
}

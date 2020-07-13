//
// Created by twirtgen on 6/12/19.
//
#include "../../include/bytecode_public.h"

void post_function_call(void);

uint64_t macro_void_test_post() {

    // changes made on REPLACE function should be reflected here;
    int *a = get_arg(0);

    if (*a == 2150) post_function_call();

    return BPF_SUCCESS;
}

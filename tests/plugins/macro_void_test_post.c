//
// Created by twirtgen on 6/12/19.
//
#include "../../include/public_bpf.h"

void post_function_call(void);

uint64_t macro_void_test_post(bpf_full_args_t *args) {

    // changes made on REPLACE function should be reflected here;
    int *a = bpf_get_args(0, args);

    if (*a == 2150) post_function_call();

    return BPF_SUCCESS;
}

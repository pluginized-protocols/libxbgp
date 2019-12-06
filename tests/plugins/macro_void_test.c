//
// Created by twirtgen on 6/12/19.
//

#include "../../include/public_bpf.h"

int set_int_example(bpf_full_args_t *args, int pos_args, int new_int_val);

uint64_t macro_void_test(bpf_full_args_t *args) {

    // multiple copies of the same argument
    int *a = bpf_get_args(0, args);
    int *b = bpf_get_args(0, args);
    // changes made on one variable won't be reflected to the other one

    *a += 10; // changes are local, because args are copied into VM memory

    // but if we use the setter, change will be spread outside the VM
    return set_int_example(args, 0, *b + 8) == 0 ? BPF_SUCCESS : BPF_FAILURE;
}
//
// Created by twirtgen on 6/12/19.
//


#include "../../include/bytecode_public.h"

int set_int_example(int pos_args, int new_int_val);

uint64_t macro_void_test() {

    // multiple copies of the same argument
    int *a = get_arg(0);
    int *b = get_arg(0);
    // changes made on one variable won't be reflected to the other one

    if (!a || !b) {
        ebpf_print("Unable to get arguments\n");
    }

    *a += 10; // changes are local, because args are copied into VM memory

    // but if we use the setter, change will be spread outside the VM
    return set_int_example(0, *b + 8) == 0 ? BPF_SUCCESS : BPF_FAILURE;
}

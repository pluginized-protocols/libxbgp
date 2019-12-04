//
// Created by thomas on 29/11/19.
//

#include "../../include/public_bpf.h"

int add_two(int a);

uint64_t plugin_main(bpf_full_args_t *args) {

    int return_val = 0;
    int *arg = bpf_get_args(0, args);

    if (arg) {
        return_val = add_two(*arg);
    } else {
        ebpf_print("Argument is NULL\n");
    }

    return return_val;
}

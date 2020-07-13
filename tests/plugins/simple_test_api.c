//
// Created by thomas on 29/11/19.
//

#include "../../include/bytecode_public.h"

int add_two(int a);

uint64_t plugin_main() {

    int return_val = 0;
    int *arg = get_arg(42);

    if (arg) {
        return_val = add_two(*arg);
    } else {
        ebpf_print("Argument is NULL\n");
    }

    return return_val;
}

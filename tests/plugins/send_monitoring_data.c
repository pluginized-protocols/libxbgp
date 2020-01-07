//
// Created by twirtgen on 7/01/20.
//

#include "../../include/public_bpf.h"

#define TYPE_INT 1

uint64_t send_monitoring_data(bpf_full_args_t *args) {

    int data = 42;
    int ret_val;

    ret_val = send_to_monitor(&data, sizeof(int), TYPE_INT) ? EXIT_SUCCESS : EXIT_FAILURE;
    return ret_val;
}
//
// Created by cyril on 14/02/19.
//


#include <ubpf_tools/include/public_bpf.h>

uint64_t send_packet(bpf_full_args_t *data) {
    return send_to_monitor(data, 0,0);
}
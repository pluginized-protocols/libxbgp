//
// Created by cyril on 04/02/19.
//

#include <ubpf_tools/include/public_bpf.h>

uint64_t rcv_packet(bpf_full_args_t *data) {
    return send_to_monitor(data, 0,0);
}
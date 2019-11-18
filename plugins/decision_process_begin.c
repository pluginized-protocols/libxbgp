//
// Created by thomas on 10/12/18.
//

#include "ubpf_tools/include/public_bpf.h"
#include <ubpf_tools/include/monitoring_struct.h>
#include <bgpd/bgp_ubpf_light_struct.h>

int start_decision_process(bpf_full_args_t *args){

    monit_decision_process_t *decision_msg;
    bgp_ebpf_t *bgp;
    clock_t begin;

    decision_msg = ctx_shmnew(1, sizeof(monit_decision_process_t));
    if(!decision_msg) {
        set_error("shared memory error", 20);
        return EXIT_FAILURE;
    }

    bgp = bpf_get_args(0, args);
    if(!bgp) return EXIT_FAILURE;

    begin = clock();

    decision_msg->begin = begin;
    decision_msg->router_id = bgp->router_id;

    ctx_free(bgp);
    return EXIT_SUCCESS;

}
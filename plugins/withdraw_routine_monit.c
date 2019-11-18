//
// Created by thomas on 2/12/18.
//

#include "ubpf_tools/include/public_bpf.h"
#include <ubpf_tools/include/monitoring_struct.h>
#include <bgpd/bgp_ubpf_light_struct.h>

#define cleanup \
ctx_free(peer);\
ctx_free(p);

int monit_withdraw_routine(bpf_full_args_t *args) {

    monit_prefix_withdraw_t data = {};
    int ret;
    peer_ebpf_t *peer;
    struct prefix *p;

    peer = bpf_get_args(0, args);
    p = bpf_get_args(1, args);

    if(!peer || !p) {
        cleanup
        return EXIT_FAILURE;
    }

    data.local_id = peer->local_id;
    data.remote_id = peer->remote_id;
    data.peer_as = peer->as;
    data.p = *p;


    ret = send_to_monitor(&data, sizeof(monit_prefix_update_t), BGP_PREFIX_WITHDRAW) ? EXIT_SUCCESS : EXIT_FAILURE;
    if(ret == EXIT_FAILURE){
        set_error("send_to_monitor failed", 23);
    }
    cleanup
    return ret;
}
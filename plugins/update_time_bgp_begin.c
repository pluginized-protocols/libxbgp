//
// Created by thomas on 25/11/18.
//

#include "ubpf_tools/include/public_bpf.h"
#include <ubpf_tools/include/monitoring_struct.h>
#include <bgpd/bgp_ubpf_light_struct.h>
#define cleanup \
ctx_free(peer);

int bgp_update_time(bpf_full_args_t *args) {

    monit_update_msg_t *msg;
    peer_ebpf_t *peer;
    clock_t tick = clock();

    msg = ctx_shmnew(1, sizeof(monit_update_msg_t));
    if (!msg) {
        set_error("shmnew failed", 14);
        return EXIT_FAILURE;
    }

    memset(msg, 0, sizeof(monit_update_msg_t));

    peer = bpf_get_args(0, args);
    if(!peer) {
        cleanup
        return EXIT_FAILURE;
    }

    memcpy(&msg->begin, &tick, sizeof(clock_t));

    msg->remote_id = peer->remote_id;
    msg->local_id = peer->local_id;
    msg->peer_as = peer->as;

    get_time(&msg->time);

    cleanup
    return EXIT_SUCCESS;
}
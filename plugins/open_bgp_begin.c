//
// Created by thomas on 19/11/18.
//

#include "ubpf_tools/include/public_bpf.h"
#include <ubpf_tools/include/monitoring_struct.h>
#include <bgpd/bgp_ubpf_light_struct.h>

#include "bgpd/bgpd.h"

#define cleanup ctx_free(peer);

int init_bgp_open_monitoring(bpf_full_args_t *args) {

    monit_open_received_msg_t *open_msg;
    peer_ebpf_t *peer;
    clock_t begin;

    open_msg = ctx_shmnew(1, sizeof(monit_open_received_msg_t));
    if (!open_msg) {
        set_error("shmnew failed", 14);
        return EXIT_FAILURE;
    }

    peer = bpf_get_args(0, args);

    if (!peer) return EXIT_FAILURE;

    memset(open_msg, 0, sizeof(monit_open_received_msg_t));

    open_msg->remote_id = peer->remote_id;
    open_msg->local_id = peer->local_id;
    open_msg->peer_as = peer->as;

    memcpy(&open_msg->remote_id, &peer->remote_id, sizeof(struct in_addr));
    memcpy(&open_msg->local_id, &peer->local_id, sizeof(struct in_addr));
    memcpy(&open_msg->peer_as, &peer->as, sizeof(as_t));

    get_time(&open_msg->time);

    begin = clock();
    memcpy(&open_msg->begin, &begin, sizeof(time_t));

    cleanup
    return EXIT_SUCCESS;
}
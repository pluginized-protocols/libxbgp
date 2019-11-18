//
// Created by thomas on 29/12/18.
//

#include "ubpf_tools/include/public_bpf.h"
#include <ubpf_tools/include/monitoring_struct.h>
#include <bgpd/bgp_ubpf_light_struct.h>


#define cleanup \
ctx_free(prefix);\
ctx_free(peer);\
ctx_free(reason);\
ctx_free(len_reason);


int invalid_update(bpf_full_args_t *args) {
    int ret_exit;
    struct prefix *prefix;
    peer_ebpf_t *peer;
    char *reason;
    int *len_reason;
    monit_invalid_update_inbound_t data;

    memset(&data, 0, sizeof(monit_invalid_update_inbound_t));
    prefix = bpf_get_args(1, args);
    peer = bpf_get_args(2, args);
    reason = bpf_get_args(3, args);
    len_reason = bpf_get_args(4, args);
    if (!peer || !prefix || !reason || !len_reason) {
        cleanup
        return EXIT_FAILURE;
    }

    data.remote_id = peer->remote_id;
    data.local_id = peer->local_id;
    data.peer_as = peer->as;
    data.p = *prefix;

    ebpf_memcpy(&data.reason, reason, sizeof(char) * (*len_reason));
    data.reason_len = sizeof(char) * (*len_reason);

    ret_exit = send_to_monitor(&data, sizeof(monit_invalid_update_inbound_t),
                            BGP_INVALID_UPDATE_INBOUND);


    if(!ret_exit) set_error("send_to_monitor failed", 23);

    cleanup
    return ret_exit == 1 ? EXIT_SUCCESS : EXIT_FAILURE;
}

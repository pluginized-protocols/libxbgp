//
// Created by thomas on 19/11/18.
//

#include "ubpf_tools/include/public_bpf.h"
#include <ubpf_tools/include/monitoring_struct.h>
#include <bgpd/bgp_ubpf_light_struct.h>

#define cleanup \
ctx_free(peer);\
ctx_free(ret_val_host);

int init_bgp_open_end_monitoring(bpf_full_args_t *args) {

    monit_open_received_msg_t *open_msg;
    peer_ebpf_t *peer;
    clock_t end;
    int ret;
    int *ret_val_host;

    open_msg = ctx_shmget(1);
    if (!open_msg) {
        set_error("shmget failed", 14);
        return EXIT_FAILURE;
    }

    peer = bpf_get_args(0, args);
    ret_val_host = bpf_get_args(1, args);
    if (!peer || !ret_val_host){
        cleanup
        return EXIT_FAILURE;
    }
    end = clock();

    open_msg->remote_id = peer->remote_id;

    //memcpy(&open_msg.remote_id, args->peer + offsetof(struct peer, remote_id), sizeof(struct in_addr));
    memcpy(&open_msg->end_process, &end, sizeof(time_t));
    memcpy(&open_msg->status, ret_val_host, sizeof(int));

    ret = send_to_monitor(open_msg, sizeof(monit_open_received_msg_t), BGP_OPEN_MSG);

    ctx_shmrm(1);

    if (!ret) {
        set_error("send_to_monitor failed", 23);
    }

    cleanup
    return ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
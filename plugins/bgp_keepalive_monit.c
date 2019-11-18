//
// Created by thomas on 10/11/18.
//

// #include "defaults.h"
#include "ubpf_tools/include/public_bpf.h"
#include <ubpf_tools/include/monitoring_struct.h>
#include <bgpd/bgp_ubpf_light_struct.h>


#define cleanup \
ctx_free(peer);\
ctx_free(last);\
ctx_free(elapsed);

int bgp_keepalive_monitoring(bpf_full_args_t *args) {

    monit_bgp_keepalive_t monitoring_item;
    peer_ebpf_t *peer;
    int at_exit;
    struct timeval *last, *elapsed;

    peer = bpf_get_args(0, args);
    elapsed = bpf_get_args(1, args);
    last = bpf_get_args(2, args);

    if(!peer || !elapsed || !last) {
        cleanup
        return EXIT_FAILURE;
    }

    monitoring_item.remote_id = peer->remote_id;
    monitoring_item.local_id = peer->local_id;
    monitoring_item.peer_as = peer->as;
    monitoring_item.keepalive_interval = 0x0; // args->peer.keepalive; // TODO not included in light struct


    if (get_time(&monitoring_item.time) < 0) {
        set_error("Can't retrieve time", 20);
        cleanup
        return EXIT_FAILURE;
    }


    memcpy(&monitoring_item.last, last, sizeof(struct timeval));
    memcpy(&monitoring_item.elapsed, elapsed, sizeof(struct timeval));

    at_exit = send_to_monitor(&monitoring_item, sizeof(monit_bgp_keepalive_t), BGP_KEEPALIVE) ? EXIT_SUCCESS
                                                                                              : EXIT_FAILURE;

    if(at_exit == EXIT_FAILURE){
        set_error("send_to_monitor failed", 23);
    }
    cleanup
    return at_exit;
}
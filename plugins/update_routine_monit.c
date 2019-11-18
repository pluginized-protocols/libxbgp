//
// Created by thomas on 2/12/18.
//

#include "ubpf_tools/include/public_bpf.h"
#include <ubpf_tools/include/monitoring_struct.h>
#include <bgpd/bgp_ubpf_api_plugins.h>

#define cleanup \
ctx_free(as_path);\
ctx_free(buf);\
ctx_free(peer);\
ctx_free(attr);\
ctx_free(p);

int monit_update_routine(bpf_full_args_t *args) {

    int err;
    size_t total_len;
    peer_ebpf_t *peer;
    struct attr *attr;
    struct prefix *p;
    monit_prefix_update_t data = {};
    uint64_t adj_in_count, adj_rib_out_count, loc_rib_count;

    uint8_t *buf, *as_path;

    as_path = NULL;
    buf = NULL;

    peer = bpf_get_args(0, args);
    attr = bpf_get_args(3, args);
    p = bpf_get_args(1, args);

    if(!peer || !attr || !p) {
        cleanup
        return EXIT_FAILURE;
    }

    data.remote_id = peer->remote_id;
    data.local_id = peer->local_id;
    data.peer_as = peer->as;
    data.p = *p;

    count_adj_rib_in_peer(&peer->pcount, &adj_in_count);
    count_adj_rib_out_peer(&peer->scount, &adj_rib_out_count);
    loc_rib_count =  count_loc_rib_from_peer_args(args, 0);

    data.loc_rib = loc_rib_count;
    data.adj_rib_in = adj_in_count;
    data.adj_rib_out = adj_rib_out_count;

    as_path = (uint8_t *) as_path_store_from_attr(args, 3, &total_len);

    if (!as_path) {
        set_error("as_path_store failed", 21);
        cleanup
        return EXIT_FAILURE;
    }

    data.as_path_size = (uint16_t) total_len;

    buf = ctx_malloc(sizeof(monit_prefix_update_t) + data.as_path_size);
    if (!buf) {
        cleanup
        return EXIT_FAILURE;
    }

    *(monit_prefix_update_t *) buf = data;
    ebpf_memcpy(&buf[sizeof(monit_prefix_update_t)], as_path, data.as_path_size);

    err = send_to_monitor(buf, sizeof(monit_prefix_update_t) + data.as_path_size, BGP_PREFIX_UPDATE);

    if (!err) {
        set_error("send_monitor failed", 20);
    }
    cleanup
    return err ? EXIT_SUCCESS : EXIT_FAILURE;
}

//
// Created by thomas on 27/02/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <bgpd/bgp_ubpf_api_plugins.h>
#include <bgpd/bgp_attr.h>
#include <bgpd/bgp_route.h>

#define cleanup \
ctx_free(peer_new);\
ctx_free(peer_old);\
ctx_free(exist);\
ctx_free(new);


unsigned int ebpf_neighbor_addr_cmp(bpf_full_args_t *args) {

    int ret;

    peer_ebpf_t *peer_new;
    peer_ebpf_t *peer_old;

    struct bgp_path_info *exist, *new;

    exist = get_bgp_path_info_from_args(args, 1);
    new = get_bgp_path_info_from_args(args, 2);


    peer_new = peer_from_prefix(args, 2); // ) return BGP_SPEC_ERROR;
    peer_old = peer_from_prefix(args, 1);


    if (!peer_new || !peer_old || !exist || !new) {
        cleanup
        return BGP_SPEC_ERROR;
    }


    if (CHECK_FLAG(exist->flags, BGP_PATH_STALE)) {
        return BGP_SPEC_COMP_2;
    }

    if (CHECK_FLAG(new->flags, BGP_PATH_STALE)) {
        return BGP_SPEC_COMP_1;
    }

    /* locally configured routes to advertise do not have su_remote */
    if (peer_new->su_remote == NULL)
        return BGP_SPEC_COMP_1;
    if (peer_old->su_remote == NULL)
        return BGP_SPEC_COMP_2;

    ret = sockunion_cmp(peer_new->su_remote, peer_old->su_remote);

    if (ret == 1) {
        cleanup
        return BGP_SPEC_COMP_1;
    }

    if (ret == -1) {
        cleanup
        return BGP_SPEC_COMP_2;
    }

    cleanup
    return BGP_SPEC_COMP_2; // end of bgp_decision process
}
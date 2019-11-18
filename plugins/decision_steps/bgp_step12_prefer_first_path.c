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
ctx_free(pair->new);\
ctx_free(pair->old);\
ctx_free(pair);\
ctx_free(bgp);

unsigned int ebpf_bgp_prefer_first_path(bpf_full_args_t *args) {
    bgp_peer_sort_t new_sort;
    bgp_peer_sort_t exist_sort;

    peer_ebpf_t *peer_new;
    peer_ebpf_t *peer_old;
    struct bgp_path_info_pair *pair;
    bgp_ebpf_t *bgp;

    peer_new = peer_from_prefix(args, 2);
    peer_old = peer_from_prefix(args, 1);

    pair = get_cmp_prefixes(args, 2, 1);
    bgp = get_bgp_instance(args, 3);

    if (!peer_new || !peer_old || !pair || !bgp) {
        cleanup
        return BGP_SPEC_ERROR;
    }

    new_sort = ebpf_peer_sort(peer_new); //peer_new->sort;
    exist_sort = ebpf_peer_sort(peer_old);

    if (!bpf_bgp_flag_check(bgp, BGP_FLAG_COMPARE_ROUTER_ID)
        && new_sort == BGP_PEER_EBGP && exist_sort == BGP_PEER_EBGP) {
        if (CHECK_FLAG(pair->new->flags, BGP_PATH_SELECTED)) {
            cleanup
            return BGP_SPEC_COMP_2;
        }

        if (CHECK_FLAG(pair->old->flags, BGP_PATH_SELECTED)) {
            cleanup
            return BGP_SPEC_COMP_1;
        }
    }
    cleanup
    return BGP_DECISION_ROUTE_ID;
}
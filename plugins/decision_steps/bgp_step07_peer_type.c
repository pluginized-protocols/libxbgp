//
// Created by thomas on 27/02/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <bgpd/bgp_ubpf_api_plugins.h>
#include <bgpd/bgp_attr.h>
#include <bgpd/bgpd.h>

#define cleanup \
ctx_free(peer_new);\
ctx_free(peer_old);

unsigned int ebpf_bgp_peer_type(bpf_full_args_t *args) {

    bgp_peer_sort_t new_sort, exist_sort;
    peer_ebpf_t *peer_new;
    peer_ebpf_t *peer_old;

    peer_new = peer_from_prefix(args, 2);
    peer_old =  peer_from_prefix(args, 1);

    if(!peer_new || !peer_old){
        cleanup
        return BGP_SPEC_ERROR;
    }


    new_sort = ebpf_peer_sort(peer_new); //peer_new->sort;
    exist_sort = ebpf_peer_sort(peer_old);

    if (new_sort == BGP_PEER_EBGP
        && (exist_sort == BGP_PEER_IBGP || exist_sort == BGP_PEER_CONFED)) {
        cleanup
        return BGP_SPEC_COMP_2;
    }

    if (exist_sort == BGP_PEER_EBGP
        && (new_sort == BGP_PEER_IBGP || new_sort == BGP_PEER_CONFED)) {
        cleanup
        return BGP_SPEC_COMP_1;
    }

    cleanup
    return BGP_DECISION_CONFED_CHECK;
}
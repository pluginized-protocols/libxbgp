//
// Created by thomas on 27/02/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <bgpd/bgp_ubpf_api_plugins.h>
#include <bgpd/bgp_attr.h>

#define cleanup \
ctx_free(bgp);\
ctx_free(peer_new);\
ctx_free(peer_old);


unsigned int ebpf_confed_check(bpf_full_args_t *args) {

    bgp_peer_sort_t new_sort, exist_sort;

    peer_ebpf_t *peer_new;
    peer_ebpf_t *peer_old;
    bgp_ebpf_t *bgp;

    peer_old = peer_from_prefix(args, 1);
    peer_new = peer_from_prefix(args, 2);
    bgp = get_bgp_instance(args, 3);

    if (!bgp || !peer_new || !peer_old) {
        cleanup
        ebpf_print("Error Memory\n");
        return BGP_SPEC_ERROR;
    }


    new_sort = ebpf_peer_sort(peer_new); //peer_new->sort;
    exist_sort = ebpf_peer_sort(peer_old);

    if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)) {
        if (new_sort == BGP_PEER_CONFED
            && exist_sort == BGP_PEER_IBGP) {
            cleanup
            return BGP_SPEC_COMP_2;
        }

        if (exist_sort == BGP_PEER_CONFED
            && new_sort == BGP_PEER_IBGP) {
            cleanup
            return BGP_SPEC_COMP_1;
        }
    }

    cleanup
    return BGP_DECISION_IGP_ALL;
}

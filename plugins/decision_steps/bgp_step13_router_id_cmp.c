//
// Created by thomas on 27/02/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <bgpd/bgp_ubpf_api_plugins.h>
#include <bgpd/bgp_attr.h>

#define cleanup \
ctx_free(newattr);\
ctx_free(existattr);\
ctx_free(peer_new);\
ctx_free(peer_old);


unsigned int ebpf_router_id_cmp(bpf_full_args_t *args) {

    struct attr *existattr, *newattr;
    struct in_addr new_id, exist_id;
    peer_ebpf_t *peer_new;
    peer_ebpf_t *peer_old;


    newattr = get_attr_from_prefix(args, 2);
    existattr = get_attr_from_prefix(args, 1);

    peer_new = peer_from_prefix(args, 2);
    peer_old = peer_from_prefix(args, 1);

    if (!newattr || !existattr || !peer_new || !peer_old) {
        cleanup
        return BGP_SPEC_ERROR;
    }

    if (newattr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
        new_id.s_addr = newattr->originator_id.s_addr;
    else
        new_id.s_addr = peer_new->remote_id.s_addr;
    if (existattr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
        exist_id.s_addr = existattr->originator_id.s_addr;
    else
        exist_id.s_addr = peer_old->remote_id.s_addr;

    if (ntohl(new_id.s_addr) < ntohl(exist_id.s_addr)) {
        cleanup
        return BGP_SPEC_COMP_2;
    }

    if (ntohl(new_id.s_addr) > ntohl(exist_id.s_addr)) {
        cleanup
        return BGP_SPEC_COMP_1;
    }

    cleanup
    return BGP_DECISION_CLUSTER_ID_CMP;
}
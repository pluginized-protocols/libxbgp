//
// Created by thomas on 23/04/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <bgpd/bgp_ubpf_api_plugins.h>
#include "bgpd/bgp_community.h"

#define DEBUG 0

#define cleanup \
ctx_free(attr); \
ctx_free(c->val);\
ctx_free(c); \
ctx_free(p); \
ctx_free(peer);

uint64_t filter_input_test_must_pass(bpf_full_args_t *args) {

#if DEBUG
    int i;
    uint16_t high;
    uint16_t low;
    uint32_t val;
#endif
    struct attr *attr;
    struct community *c;
    struct prefix *p;
    peer_ebpf_t *peer;

    attr = bpf_get_args(2, args);
    p = bpf_get_args(1, args);
    peer = bpf_get_args(0, args);
    c = get_community_from_args(args, 2);

    if (!c || !p || !attr || !peer) {
        cleanup
        return BGP_CONTINUE;
    }

#if DEBUG
    ebpf_print("\033[1m\033[35mYou need to sleep on it 1\033[0m\n");

    ebpf_print("Prefix received from AS %d (%d)\n", peer->as, ebpf_ntohl(p->u.prefix4.s_addr));

    for(i = 0; i < c->size; i++) {

        val = ebpf_ntohl(c->val[i]);

        high = (val & 0xFFFF0000) >> 16;
        low = (val & 0x0000FFFF);

        ebpf_print("Community received is %hu:%hu\n", high, low);

    }
#endif

    //ebpf_print("New incoming route %d\n", p->u.prefix4.s_addr);

    if (add_community_val_to_attr(args, 2, ((6532u) << 16u) | (0x0000FFFFu & 58u)) != 0) {
        ebpf_print("Add value failed");
    }

    cleanup
    return BGP_CONTINUE;

}
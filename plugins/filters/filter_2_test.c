//
// Created by thomas on 23/04/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <bgpd/bgp_ubpf_api_plugins.h>
#include "bgpd/bgp_community.h"

#define DEBUG 0

#define cleanup \
ctx_free(c->val);\
ctx_free(c);\
ctx_free(attr);

uint64_t filter_input_test_must_pass(bpf_full_args_t *args) {

#if DEBUG
    int i;
    uint32_t val;
    uint16_t high, low;
#endif
    struct community *c;
    struct attr *attr;

    c = get_community_from_args(args, 2);
    attr = get_attr_from_args(args, 2);

    if (!c || !attr) {
        cleanup
        return BGP_CONTINUE;
    }

#if DEBUG
    ebpf_print("\033[1m\033[35mYou need to sleep on it 2\033[0m\n");

    for(i = 0; i < c->size; i++) {

        val = ebpf_ntohl(c->val[i]);

        high = (val & 0xFFFF0000) >> 16;
        low = (val & 0x0000FFFF);

        ebpf_print("Community received is %hu:%hu\n", high, low);

    }
#endif

    if (del_community_val_form_args_attr(args, 2, ((6532u) << 16u) | (0x0000FFFFu & 58u)) != 0) {
        ebpf_print("Deleting failed");
    }

    cleanup
    return BGP_CONTINUE;

}
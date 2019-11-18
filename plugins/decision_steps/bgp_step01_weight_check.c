//
// Created by thomas on 27/02/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <bgpd/bgp_ubpf_api_plugins.h>
#include <bgpd/bgp_attr.h>

#define cleanup \
ctx_free(attr_new); \
ctx_free(attr_old);


uint64_t ebpf_bgp_weight_check(bpf_full_args_t *args) {
    uint32_t new_weight;
    uint32_t exist_weight;

    struct attr *attr_new;
    struct attr *attr_old;


    attr_new = get_attr_from_prefix(args, 2);
    attr_old = get_attr_from_prefix(args, 1);

    if (!attr_new || !attr_old) {
        cleanup
        return BGP_SPEC_ERROR;
    }

    new_weight = attr_new->weight;
    exist_weight = attr_old->weight;


    if (new_weight > exist_weight) {
        cleanup
        return BGP_SPEC_COMP_2;
    }

    if (new_weight < exist_weight) {
        cleanup
        return BGP_SPEC_COMP_1;
    }

    cleanup
    return BGP_DECISION_LOCAL_PREF;
}
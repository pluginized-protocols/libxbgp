//
// Created by thomas on 27/02/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <bgpd/bgp_ubpf_api_plugins.h>
#include <bgpd/bgp_attr.h>

#define cleanup \
ctx_free(newattr);\
ctx_free(existattr);\
ctx_free(bgp);

static inline uint32_t bgp_med_value(struct attr *attr, bgp_ebpf_t *bgp) { // TODO CHECK HERE ATTR
    if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))
        return attr->med;
    else {
        if (bpf_bgp_flag_check(bgp, BGP_FLAG_MED_MISSING_AS_WORST))
            return BGP_MED_MAX;
        else
            return 0;
    }
}

unsigned int ebpf_med_check(bpf_full_args_t *args) {

    int internal_as_route, confed_as_route;
    struct attr *newattr, *existattr;
    uint32_t new_med, exist_med;
    bgp_ebpf_t *bgp;


    newattr = get_attr_from_prefix(args, 2);
    existattr = get_attr_from_prefix(args, 1);
    bgp = get_bgp_instance(args, 3);

    if (!newattr || !existattr || !bgp) {
        cleanup
        return BGP_SPEC_ERROR;
    }


    internal_as_route = (bpf_aspath_count_hops(newattr->aspath) == 0
                         && bpf_aspath_count_hops(existattr->aspath) == 0);
    confed_as_route = (bpf_aspath_count_confeds(newattr->aspath) > 0
                       && bpf_aspath_count_confeds(existattr->aspath) > 0
                       && bpf_aspath_count_hops(newattr->aspath) == 0
                       && bpf_aspath_count_hops(existattr->aspath) == 0);

    if (bpf_bgp_flag_check(bgp, BGP_FLAG_ALWAYS_COMPARE_MED)
        || (bpf_bgp_flag_check(bgp, BGP_FLAG_MED_CONFED) && confed_as_route)
        || bpf_aspath_cmp_left(newattr->aspath, existattr->aspath)
        || bpf_aspath_cmp_left_confed(newattr->aspath, existattr->aspath)
        || internal_as_route) {
        new_med = bgp_med_value(newattr, bgp);
        exist_med = bgp_med_value(existattr, bgp);

        if (new_med < exist_med) {
            cleanup
            return BGP_SPEC_COMP_2;
        }

        if (new_med > exist_med) {
            cleanup
            return BGP_SPEC_COMP_1;
        }
    }

    cleanup
    return BGP_DECISION_PEER_TYPE;
}

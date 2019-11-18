//
// Created by thomas on 27/02/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <bgpd/bgp_ubpf_api_plugins.h>
#include <bgpd/bgp_attr.h>

#define cleanup \
ctx_free(attrnew); \
ctx_free(attrold); \
ctx_free(bgp);

uint64_t ebpf_bgp_as_path_length(bpf_full_args_t *args) {

    struct attr *attrnew;
    struct attr *attrold;
    bgp_ebpf_t *bgp;

    attrnew = attrold = NULL;
    bgp = NULL;

    if(!(attrnew = get_attr_from_prefix(args, 2))){
        cleanup
        return BGP_SPEC_ERROR;
    }

    if(!(attrold = get_attr_from_prefix(args, 1))){
        cleanup
        return BGP_SPEC_ERROR;
    }

    bgp = bpf_get_args(3, args);

    if(!bgp) {
        cleanup
        return BGP_SPEC_ERROR;
    }



    if (!bpf_bgp_flag_check(bgp, BGP_FLAG_ASPATH_IGNORE)) {
        unsigned int exist_hops = bpf_aspath_count_hops(attrold->aspath);
        unsigned int exist_confeds = bpf_aspath_count_confeds(attrold->aspath);

        if (bpf_bgp_flag_check(bgp, BGP_FLAG_ASPATH_CONFED)) {
            unsigned int aspath_hops;

            aspath_hops = bpf_aspath_count_hops(attrnew->aspath);
            aspath_hops += bpf_aspath_count_confeds(attrnew->aspath);

            if (aspath_hops < (exist_hops + exist_confeds)) {
                cleanup
                return BGP_SPEC_COMP_2;
            }

            if (aspath_hops > (exist_hops + exist_confeds)) {
                cleanup
                return BGP_SPEC_COMP_1;
            }
        } else {
            unsigned int newhops = bpf_aspath_count_hops(attrnew->aspath);

            if (newhops < exist_hops) {
                cleanup
                return BGP_SPEC_COMP_2;
            }

            if (newhops > exist_hops) {
                cleanup
                return BGP_SPEC_COMP_1;
            }
        }
    }
    cleanup
    return BGP_DECISION_ORIGIN_CHECK;
}

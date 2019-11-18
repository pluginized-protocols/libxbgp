//
// Created by thomas on 27/02/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <bgpd/bgp_ubpf_api_plugins.h>
#include <bgpd/bgp_route.h>

#define cleanup \
ctx_free(pair->new);\
ctx_free(pair->old);\
ctx_free(pair);

uint64_t ebpf_bgp_local_route(bpf_full_args_t *args) {

    struct bgp_path_info_pair *pair;

    if (!(pair = get_cmp_prefixes(args, 2, 1))) {
        cleanup
        return BGP_SPEC_ERROR;
    }


    if (!(pair->new->sub_type == BGP_ROUTE_NORMAL ||
          pair->new->sub_type == BGP_ROUTE_IMPORTED)) {
        cleanup
        return BGP_SPEC_COMP_2;
    }

    if (!(pair->old->sub_type == BGP_ROUTE_NORMAL ||
          pair->old->sub_type == BGP_ROUTE_IMPORTED)) {
        cleanup
        return BGP_SPEC_COMP_1;
    }


    cleanup
    return BGP_DECISION_ASPATH;
}

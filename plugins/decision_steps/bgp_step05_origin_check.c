//
// Created by thomas on 27/02/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <bgpd/bgp_ubpf_api_plugins.h>
#include <bgpd/bgp_attr.h>

#define cleanup \
ctx_free(attrnew);\
ctx_free(attrold);

uint64_t ebpf_origin_check(bpf_full_args_t *args) {

    struct attr *attrnew;
    struct attr *attrold;

    if (!(attrnew = get_attr_from_prefix(args, 2))) return BGP_SPEC_ERROR;
    if (!(attrold = get_attr_from_prefix(args, 1))) return BGP_SPEC_ERROR;

    if (attrnew->origin < attrold->origin) {
        cleanup
        return BGP_SPEC_COMP_2;
    }

    if (attrnew->origin > attrold->origin) {
        cleanup
        return BGP_SPEC_COMP_1;
    }

    cleanup
    return BGP_DECISION_MED_CHECK;
}
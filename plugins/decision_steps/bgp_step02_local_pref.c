//
// Created by thomas on 27/02/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <bgpd/bgp_ubpf_api_plugins.h>
#include <bgpd/bgp_attr.h>

#define cleanup \
ctx_free(my_bgp); \
ctx_free(new_attr); \
ctx_free(old_attr);

uint64_t ebpf_bgp_local_pref(bpf_full_args_t *args) {

    uint32_t new_pref, exist_pref;
    bgp_ebpf_t *my_bgp;
    struct attr *new_attr;
    struct attr *old_attr;

    new_attr = old_attr = NULL;


    if (!(my_bgp = bpf_get_args(3, args))) {
        cleanup
        ebpf_print("Get bgp struct error\n");
        return BGP_SPEC_ERROR;
    }

    if (!(new_attr = get_attr_from_prefix(args, 2))) { // new
        cleanup
        ebpf_print("Get new attr struct error\n");
        return BGP_SPEC_ERROR;
    }
    if (!(old_attr = get_attr_from_prefix(args, 1))) {
        cleanup
        ebpf_print("Get exist attr struct error\n");
        return BGP_SPEC_ERROR;
    }

    new_pref = exist_pref = my_bgp->default_local_pref;

    if (new_attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
        new_pref = new_attr->local_pref;
    if (old_attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
        exist_pref = new_attr->local_pref;

    if (new_pref > exist_pref) {
        cleanup
        return BGP_SPEC_COMP_2;
    }

    if (new_pref < exist_pref) {
        cleanup
        return BGP_SPEC_COMP_1;
    }

    cleanup
    return BGP_DECISION_LOCAL_ROUTE;
}
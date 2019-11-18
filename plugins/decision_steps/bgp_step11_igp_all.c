//
// Created by thomas on 27/02/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <bgpd/bgp_ubpf_api_plugins.h>
#include <bgpd/bgp_attr.h>
#include <bgpd/bgp_route.h>


#define cleanup \
ctx_free(bgp);\
ctx_free(p_old);\
ctx_free(p_new);\
ctx_free(peer_old);\
ctx_free(peer_new);\
ctx_free(attr_new);\
ctx_free(attr_old);\
ctx_free(extra_new);\
ctx_free(extra_old);\
ctx_free(ptr_mpath);\
ctx_free(cluster_new);\
ctx_free(cluster_old);

static inline int bgp_is_valid_label(mpls_label_t *label) {
    uint8_t *t = (uint8_t *) label;
    if (!t)
        return 0;
    return (t[2] & 0x02);
}

static inline int bgp_cluster_list_length(struct attr *attr, struct cluster_list *cl) {
    return (attr)->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST) ? cl->length : 0;
}

uint64_t ebpf_bgp_igp_m(bpf_full_args_t *args) {

    unsigned int ret = 0;
    uint32_t newm, existm;

    // WARNING A LOT OF MEMORY IS NEEDED

    struct bgp_path_info *p_new;
    struct bgp_path_info *p_old;
    struct bgp_path_info_extra *extra_new;
    struct bgp_path_info_extra *extra_old;
    peer_ebpf_t *peer_old;
    peer_ebpf_t *peer_new;
    struct bgp_maxpaths_cfg *ptr_mpath;
    struct attr *attr_new;
    struct attr *attr_old;
    struct cluster_list *cluster_new;
    struct cluster_list *cluster_old;
    bgp_ebpf_t *bgp;


    peer_new = peer_from_prefix(args, 2);
    peer_old = peer_from_prefix(args, 1);

    p_new = get_bgp_path_info_from_args(args, 2);
    p_old = get_bgp_path_info_from_args(args, 1);

    extra_new = extra_from_prefix(args, 2);
    extra_old = extra_from_prefix(args, 1);
    ptr_mpath = get_maxpath_cfg(args, 4);


    attr_new = get_attr_from_prefix(args, 2);
    attr_old = get_attr_from_prefix(args, 1);

    cluster_new = get_cluster_from_attr_path_info(args, 2);
    cluster_old = get_cluster_from_attr_path_info(args, 1);

    bgp = get_bgp_instance(args, 3);

    if (!p_new || !p_old || !attr_new || !attr_old || !bgp || !peer_new || !peer_old) {
        cleanup
        return BGP_SPEC_ERROR;
    }

    /* 8. IGP metric check. */
    newm = existm = 0;

    if (extra_new)
        newm = extra_new->igpmetric;
    if (extra_old)
        existm = extra_old->igpmetric;

    if (newm < existm) {
        ret = 1;
    } else if (newm > existm) {
        ret = 0;
    } else {
        /* 9. Same IGP metric. Compare the cluster list length as
	   representative of IGP hops metric. Rewrite the metric value
	   pair (newm, existm) with the cluster list length. Prefer the
	   path with smaller cluster list length.                       */
        if (ebpf_peer_sort(peer_new) == BGP_PEER_IBGP
            && ebpf_peer_sort(peer_old) == BGP_PEER_IBGP
            && (ptr_mpath == NULL
                || CHECK_FLAG(
                        ptr_mpath->ibgp_flags,
                        BGP_FLAG_IBGP_MULTIPATH_SAME_CLUSTERLEN))) {
            newm = (uint32_t) bgp_cluster_list_length(attr_new, cluster_new);
            existm = (uint32_t) bgp_cluster_list_length(attr_old, cluster_old);

            if (newm < existm) {
                ret = 1;
            }

            if (newm > existm) {
                ret = 0;
            }
        }
    }

    /* 11. Maximum path check. */
    if (newm == existm) {
        /* If one path has a label but the other does not, do not treat
        * them as equals for multipath
        */
        if ((extra_new && bgp_is_valid_label(&extra_new->label[0]))
            != (extra_old
                && bgp_is_valid_label(&extra_old->label[0]))) {
            // inconsistency
        } else if (bpf_bgp_flag_check(bgp,
                                      BGP_FLAG_ASPATH_MULTIPATH_RELAX)) {

            /*
            * For the two paths, all comparison steps till IGP
            * metric
            * have succeeded - including AS_PATH hop count. Since
            * 'bgp
            * bestpath as-path multipath-relax' knob is on, we
            * don't need
            * an exact match of AS_PATH. Thus, mark the paths are
            * equal.
            * That will trigger both these paths to get into the
            * multipath
            * array.
            */
            set_path_eq(args, 5, 1);
            //*args->paths_eq = 1;

        } else if (peer_new->sort == BGP_PEER_IBGP) {
            if (bpf_aspath_cmp(attr_new->aspath, attr_old->aspath)) {
                set_path_eq(args, 5, 1);
                //*args->paths_eq = 1;

            }
        } else if (peer_new->as == peer_old->as) {
            set_path_eq(args, 5, 1);
            //*args->paths_eq = 1;
        }
    } else {
        /*
        * TODO: If unequal cost ibgp multipath is enabled we can
        * mark the paths as equal here instead of returning
        */

        cleanup
        return ret == 1 ? BGP_SPEC_COMP_2 : BGP_SPEC_COMP_1; /// WHY RETURNING HERE ??
    }
    cleanup
    return BGP_DECISION_PREFER_FIRST_PATH;
}
//
// Created by thomas on 27/02/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <bgpd/bgp_ubpf_api_plugins.h>
#include <bgpd/bgp_attr.h>
#include <bgpd/bgp_route.h>

#define cleanup \
ctx_free(attr_new);\
ctx_free(attr_old);\
ctx_free(cl_new);\
ctx_free(cl_old);

static inline int bgp_cluster_list_length(struct attr *attr, struct cluster_list *cl) {
    return (attr)->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST) ? cl->length : 0;
}

unsigned int ebpf_cluster_id_cmp(bpf_full_args_t *args) {

    int new_cluster;
    int exist_cluster;

    struct attr *attr_new;
    struct attr *attr_old;

    struct cluster_list *cl_new;
    struct cluster_list *cl_old;

    cl_new = ctx_malloc(sizeof(struct cluster_list));
    cl_old = ctx_malloc(sizeof(struct cluster_list));

    attr_new = get_attr_from_prefix(args, 2);
    attr_old = get_attr_from_prefix(args, 1);

    if (!attr_new || attr_old) {
        cleanup
        return BGP_SPEC_ERROR;
    }

    cl_new = get_cluster_from_attr_path_info(args, 2);
    cl_old = get_cluster_from_attr_path_info(args, 1);

    new_cluster = bgp_cluster_list_length(attr_new, cl_new);
    exist_cluster = bgp_cluster_list_length(attr_old, cl_old);

    if (new_cluster < exist_cluster) {
        cleanup
        return BGP_SPEC_COMP_2;
    }

    if (new_cluster > exist_cluster) {
        cleanup
        return BGP_SPEC_COMP_1;
    }

    cleanup
    return BGP_DECISION_NEIGHBOR_ADDR_CMP;
}
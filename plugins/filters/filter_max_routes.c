//
// Created by thomas on 19/05/19.
//


#include <ubpf_tools/include/public_bpf.h>
#include <bgpd/bgp_ubpf_api_plugins.h>
#include <lib/filter.h>
#include "bgpd/bgp_community.h"

#define cleanup \
ctx_free(p);\
ctx_free(store_p);\
ctx_free(afi);\
ctx_free(safi);

#define MAX_ALLOWED_SUBPREFIXES 4


uint64_t rib_max_lookup(bpf_full_args_t *args) {

    struct prefix *p, *store_p;
    int nb = -1;

    p = bpf_get_args(1, args);
    afi_t *afi = bpf_get_args(3, args);
    safi_t *safi = bpf_get_args(4, args);

    store_p = ctx_malloc(sizeof(struct prefix));

    if(!p || !afi || !safi || !store_p)  {
        cleanup
        return BGP_CONTINUE;
    }

    if (rib_lookup(*afi, *safi, p, store_p) == -1) goto cont;

    if (store_p->prefixlen == p->prefixlen) goto cont;


    if ( (nb = bgp_table_range_nb_ebpf(*afi, *safi, store_p, 128, MAX_ALLOWED_SUBPREFIXES + 1)) >=
        MAX_ALLOWED_SUBPREFIXES) {
        ebpf_print("%d prefixes to reach route --> deny\n", nb);
        cleanup
        return FILTER_DENY;
    }

    cont:
    cleanup
    return BGP_CONTINUE;

}
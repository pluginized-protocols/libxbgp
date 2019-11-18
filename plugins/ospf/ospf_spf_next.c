//
// Created by cyril on 29/04/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <ospfd/ospf_ubpf_api_plugins.h>
#include <ospfd/ospf_spf.h>
#include <ospfd/ospf_lsa.h>
#include <ospfd/ospfd.h>

struct my_link {
    struct in_addr link_id;
    struct in_addr link_data;
    uint8_t type;
    uint8_t tos;
    uint16_t metric;
    uint32_t color;
};

#define RED 1
#define GREEN 2


#define IS_MAXAGE(x) (OSPF_LSA_MAXAGE < plugin_get_age(x) ? 1 : 0)

#define cleanup \
ctx_free(v);\
ctx_free(lsah);\
ctx_free(area);

#define __cleanup \
ctx_free(v);\
ctx_free(ospf);\
ctx_free(area);\
ctx_free(candidate);


uint64_t new(bpf_full_args_t *data) {
    struct ospf_lsa *w_lsa = NULL;
    uint8_t *p;
    uint8_t *lim;
    struct router_lsa_link *l = NULL;
    struct in_addr *r;
    int type = 0, lsa_pos = -1, lsa_pos_next = 0;

    int vertex_args = 0;
    int ospf_args = 1;
    int area_args = 2;

    struct vertex *v = bpf_get_args(0, data);
    struct ospf *ospf = bpf_get_args(1, data);
    struct ospf_area *area = bpf_get_args(2, data);
    struct vertex_pqueue_head *candidate = bpf_get_args(3, data);

    struct lsa_header *v_lsa =  get_lsa_header_from_vertex(data, 0, 1);


    if (!v || !ospf || !area || !candidate || !v_lsa) {
        __cleanup
        return EXIT_FAILURE;
    }


    /* If this is a router-LSA, and bit V of the router-LSA (see Section
       A.4.2:RFC2328) is set, set Area A's TransitCapability to true.  */
    if (v->type == OSPF_VERTEX_ROUTER) {
        if (IS_ROUTER_LSA_VIRTUAL((struct router_lsa *) v_lsa))
            area->transit = OSPF_TRANSIT_TRUE;
    }

    p = ((uint8_t *) v_lsa) + OSPF_LSA_HEADER_SIZE + 4;
    lim = ((uint8_t *) v_lsa) + ebpf_ntohs(v_lsa->length);

    struct ospf_lsa *test_lsa;
    int type_13 = 13;
    void *args[] = {data, &ospf_args, &area_args, &type_13, &v->id, &v->id};
    test_lsa = plugin_ospf_lsa_lookup(args);

    while (p < lim) {
        struct vertex *w;
        uint8_t *my_lim;
        unsigned int distance;

        /* In case of V is Router-LSA. */
        if (v_lsa->type == OSPF_ROUTER_LSA) {
            l = (struct router_lsa_link *) p;

            int ignored = 0;
            if (test_lsa != NULL) { // There is a type 13 corresponding LSA

                ebpf_print("SPF type 13\n");

                struct lsa_header *test_lsah = test_lsa->data;

                uint8_t *my_p = ((uint8_t *) test_lsah) + OSPF_LSA_HEADER_SIZE + 4;
                my_lim = ((uint8_t *) test_lsa) + ebpf_ntohs(test_lsah->length);
                while (my_p < my_lim) {
                    struct my_link *my_link = (struct my_link *) my_p;
                    if (l->link_id.s_addr == my_link->link_id.s_addr) {
                        if (ebpf_ntohl(my_link->color) == RED) { // If the link is red, we ignore it
                            ignored = 1;
                            break;
                        }
                    }
                    my_p += sizeof(struct my_link);
                }
            }

            lsa_pos = lsa_pos_next; /* LSA link position */
            lsa_pos_next++;
            p += (OSPF_ROUTER_LSA_LINK_SIZE
                  + (l->m[0].tos_count * OSPF_ROUTER_LSA_TOS_SIZE));

            if (ignored) continue;

            /* (a) If this is a link to a stub network, examine the
               next
               link in V's LSA.  Links to stub networks will be
               considered in the second stage of the shortest path
               calculation. */
            type = l->m[0].type;
            if (type == LSA_LINK_TYPE_STUB)
                continue;

            /* (b) Otherwise, W is a transit vertex (router or
               transit
               network).  Look up the vertex W's LSA (router-LSA or
               network-LSA) in Area A's link state database. */
            switch (type) {
                case LSA_LINK_TYPE_POINTOPOINT:
                case LSA_LINK_TYPE_VIRTUALLINK: {

                    int ospf_router_lsa = OSPF_ROUTER_LSA;
                    void *my_args[] = {data, &ospf_args, &area_args, &ospf_router_lsa, &l->link_id, &l->link_id};

                    w_lsa = plugin_ospf_lsa_lookup(my_args);
                    break;
                }
                case LSA_LINK_TYPE_TRANSIT:
                    w_lsa = plugin_ospf_lsa_lookup_by_id(data,
                            area_args, OSPF_NETWORK_LSA, l->link_id);
                    break;
                default:
                    ebpf_print("Invalid LSA link type %d\n", type);
                    continue;
            }
        } else {
            /* In case of V is Network-LSA. */
            r = (struct in_addr *) p;
            p += sizeof(struct in_addr);

            /* Lookup the vertex W's LSA. */
            w_lsa = plugin_ospf_lsa_lookup_by_id(data, area_args, OSPF_ROUTER_LSA, *r);
        }

        /* (b cont.) If the LSA does not exist, or its LS age is equal
           to MaxAge, or it does not have a link back to vertex V,
           examine the next link in V's LSA.[23] */
        if (w_lsa == NULL) {
            continue;
        }

        if (IS_MAXAGE(w_lsa)) {
            continue;
        }


        if (plugin_ospf_lsa_has_link(w_lsa->data, v->lsa) < 0) {
            continue;
        }

        /* (c) If vertex W is already on the shortest-path tree, examine
           the next link in the LSA. */
        if (w_lsa->stat == plugin_lsa_in_spf_tree()) {
            continue;
        }

        /* (d) Calculate the link state cost D of the resulting path
           from the root to vertex W.  D is equal to the sum of the link
           state cost of the (already calculated) shortest path to
           vertex V and the advertised cost of the link between vertices
           V and W.  If D is: */

        /* calculate link cost D. */
        if (v_lsa->type == OSPF_ROUTER_LSA)
            distance = v->distance + ebpf_ntohs(l->m[0].metric);
        else /* v is not a Router-LSA */
            distance = v->distance;

        /* Is there already vertex W in candidate list? */
        if (w_lsa->stat == plugin_lsa_not_explored()) {
            /* prepare vertex W. */
            w = plugin_ospf_vertex_new(w_lsa, NULL);


            void *my_args[] = {data, &area_args, &vertex_args,
                               w, l, &distance, &lsa_pos};

            /* Calculate nexthop to W. */
            if (plugin_ospf_nexthop_calculation(my_args))
                plugin_vertex_pqueue_add(candidate, w);
        } else if (w_lsa->stat != plugin_lsa_in_spf_tree()) {
            w = w_lsa->stat;
            void *my_args[] = {data, &area_args, &vertex_args,
                               w, l, &distance, &lsa_pos};
            /* if D is greater than. */
            if (w->distance < distance) {
                continue;
            }
                /* equal to. */
            else if (w->distance == distance) {
                /* Found an equal-cost path to W.
                 * Calculate nexthop of to W from V. */

                plugin_ospf_nexthop_calculation(my_args);
            }
                /* less than. */
            else {
                /* Found a lower-cost path to W.
                 * nexthop_calculation is conditional, if it
                 * finds
                 * valid nexthop it will call spf_add_parents,
                 * which
                 * will flush the old parents
                 */
                plugin_vertex_pqueue_del(candidate, w);
                plugin_ospf_nexthop_calculation(my_args);
                plugin_vertex_pqueue_add(candidate, w);
            }
        } /* end W is already on the candidate list */
    }     /* end loop over the links in V's LSA */

    __cleanup
    return EXIT_SUCCESS;
}
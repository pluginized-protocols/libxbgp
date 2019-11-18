//
// Created by cyril on 03/04/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <ospfd/ospf_ubpf_api_plugins.h>
#include <ospfd/ospfd.h>
#include <ospfd/ospf_lsa.h>
#include <ospfd/ospf_interface.h>

#define cleanup(i) \
ctx_free(area);\
ctx_free(ospf);\
{for(int __I__ = 0; __I__ < i; i++) ctx_free(oi_list[i].ifp);}\
ctx_free(oi_list);\
ctx_free(s);

#define OSPF_MY_LSA_TYPE 13
#define RED 1
#define GREEN 2

/* Plugin to create and originate a new LSA of a new type (13) carrying supplementary information for each link (a color) */
uint64_t originate_my_lsa(bpf_full_args_t *data) {

    struct ospf_area *area;
    struct ospf_interface *oi_list;
    struct ospf *ospf;

    struct stream *s;
    struct lsa_header *lsah;
    struct ospf_lsa *new;

    int ifs_nb = 0;

    ospf = bpf_get_args(0, data);
    area = bpf_get_args(1, data);
    oi_list = get_ospf_interface_list_from_area(data, 1, &ifs_nb);
    /* Create a stream for LSA. */
    s = ctx_malloc(sizeof(struct stream) + OSPF_MAX_LSA_SIZE);

    if (!area || !ospf || !oi_list || !s) {
        cleanup(ifs_nb)
        return EXIT_FAILURE;
    }

    area->ospf = ospf;

    s->getp = s->endp = 0;
    s->next = NULL;
    s->size = OSPF_MAX_LSA_SIZE;
    /* Set LSA common header fields. */

    lsah = (struct lsa_header *) s->data;

    lsah->ls_age = 0;
    lsah->options = (uint8_t) 0;
    lsah->type = OSPF_MY_LSA_TYPE;
    lsah->id = ospf->router_id;
    lsah->adv_router = ospf->router_id;
    lsah->ls_seqnum = ebpf_ntohs(0x10);

    s->endp += OSPF_LSA_HEADER_SIZE;

    /* Lsa body */
    unsigned long putp;
    uint16_t cnt = 0;
    /* Set flags. */
    s->data[s->endp++] = 0;
    /* Set Zero fields. */
    s->data[s->endp++] = 0;
    /* Keep pointer to # links. */
    putp = s->endp;
    /* Forward word */
    s->data[s->endp++] = (uint8_t) (0u >> 8u);
    s->data[s->endp++] = (uint8_t) 0;    /* Set all link information. */

    /* My links lsa set */
    int links = 0;

    for (int i = 0; i < ifs_nb; i++) {
        struct ospf_interface *oi = &oi_list[i];
        struct interface *ifp = oi->ifp;
        /* Check interface is up, OSPF is enable. */
        if (ifp != NULL) {
            if (oi->state != 1) {
                oi->lsa_pos_beg = links;
                /* Describe each link. */
                switch (oi->type) {
                    case OSPF_IFTYPE_BROADCAST:
                        /* We only take care of Broadcast but this could be extended
                         * The following condition is used to choose the color of the links. This could be changed based on the network operator will
                         */
                        if (ifp->speed > 500) {
                            links += plugin_lsa_link_broadcast_set(&s, oi, GREEN);
                        } else {
                            links += plugin_lsa_link_broadcast_set(&s, oi, RED);
                        }
                        break;
                }
                oi->lsa_pos_end = links;
            }
        }
        set_ospf_interface_area(data, 1, oi, i);
    }

    /* Set # of links here. */
    s->data[putp] = (uint8_t) (cnt >> 8u);
    s->data[putp + 1] = (uint8_t) cnt;

    /* Now, create OSPF LSA instance. */
    new = plugin_ospf_lsa_new_and_data(data, 1, s);

    if (new == NULL) {
        cleanup(ifs_nb)
        return 0;
    }
    new = plugin_ospf_lsa_install(area->ospf, NULL, new);
    int ret = plugin_ospf_flood_through_area(data, 1, NULL, new);

    cleanup(ifs_nb)
    return ret == 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

//
// Created by cyril on 16/02/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <ospfd/ospf_ubpf_api_plugins.h>


#define cleanup \
ctx_free(lsa);\
ctx_free(lsah);

typedef struct lsa_flood_m {
    struct ospf_lsa lsa;
    struct lsa_header hdr;
} lsa_flood_t;

/* Monitors the flooding procedure of LSAs */
uint64_t lsa_flood(bpf_full_args_t *data) {
    struct ospf_lsa *lsa;
    struct lsa_header *lsah;
    lsa_flood_t mf;

    lsa = bpf_get_args(2, data);
    lsah = get_lsa_header_from_lsa(data, 2, 0);

    if(!lsa || !lsah) {
        return EXIT_FAILURE;
    }

    mf.lsa = *lsa;
    mf.hdr = *lsah;

    // I could do something with the lsa here.
    return send_to_monitor(&mf, sizeof(lsa_flood_t), 00);
}
//
// Created by cyril on 04/01/19.
//

#include <ubpf_tools/include/public_bpf.h>

typedef struct spf_mon {
    clock_t begin;
    clock_t end;
    struct in_addr area_id;
    uint32_t spf_count;
} spf_mon_t;

/* Bytecode to store the current time in the heap with an ID (useful for measuring execution time) */
uint64_t spf_count(bpf_full_args_t *data) {

    spf_mon_t *t1 = ctx_shmnew(3, sizeof(spf_mon_t));

    if(!t1) return EXIT_FAILURE;
    memset(t1, 0x0, sizeof(spf_mon_t));

    t1->begin = clock();

    return EXIT_SUCCESS;
}
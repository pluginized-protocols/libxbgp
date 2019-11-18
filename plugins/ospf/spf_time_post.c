//
// Created by cyril on 28/03/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <ospfd/ospfd.h>

typedef struct spf_mon {
    clock_t begin;
    clock_t end;
    struct in_addr area_id;
    uint32_t spf_count;
} spf_mon_t;

/* Gets a previous time in the heap and computes the execution time */
uint64_t spf_count(bpf_full_args_t *data) {

    int ret;
    spf_mon_t *mon;
    struct ospf_area *area;
    clock_t clk = clock();

    area = bpf_get_args(1, data);
    if(!area) return EXIT_FAILURE;

    mon = ctx_shmget(3);
    if(!mon) return EXIT_FAILURE;


    mon->end = clk;
    mon->area_id = area->area_id;
    mon->spf_count = area->spf_calculation;

    ret = send_to_monitor(mon, sizeof(spf_mon_t), 0);

    ctx_shmrm(3);
    ctx_free(area);
    return ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
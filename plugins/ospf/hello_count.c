//
// Created by cyril on 30/11/18.
//

#include <ubpf_tools/include/public_bpf.h>
#include <ospfd/ospf_ubpf_api_plugins.h>

#define cleanup \
ctx_free(oi);\
ctx_free(ifp);\
ctx_free(ifp_name);

typedef struct hello_stats {
    uint32_t hello_count;
    uint32_t ifp_speed;
    char name[20];
} hello_stats_t;

/*
 * Plugin that monitors the number of OSPF hello packets sent (+ itf speed & name)
 */
uint64_t hello_count(bpf_full_args_t *data) {

    struct ospf_interface *oi;
    struct interface *ifp;
    char *ifp_name;
    hello_stats_t s;

    oi = bpf_get_args(0, data);
    ifp = bpf_get_args(1, data);

    ifp_name = plugin_get_ifp_name(data, 1);

    if(!oi || !ifp || !ifp_name) {
        cleanup;
        return EXIT_FAILURE;
    }

    s.hello_count = oi->hello_out;
    s.ifp_speed = ifp->speed;
    memcpy(&s.name, ifp->name, 20);

    cleanup
    return send_to_monitor(&s, sizeof(hello_stats_t), 0) == 1 ? EXIT_SUCCESS : EXIT_FAILURE;
}
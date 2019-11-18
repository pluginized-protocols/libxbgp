//
// Created by cyril on 20/02/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <ospfd/ospf_ubpf_api_plugins.h>

#define cleanup \
ctx_free(oi_read);\
ctx_free(new_state);\
ctx_free(name);\

typedef struct ism_ch {
    int new_state;
    int  old_state;
    uint8_t if_name[40];
} ism_change_state_t;

/* Plugin used to monitor the change of ISM state */
uint64_t ism_change_state(bpf_full_args_t *data) {

    ism_change_state_t s;
    struct ospf_interface *oi_read = bpf_get_args(0, data);
    int  *new_state = bpf_get_args(1, data);
    char *name = bpf_get_args(2, data);


    if(oi_read == NULL || !new_state) {
        cleanup
        return EXIT_FAILURE;
    }

    s.new_state = *new_state;
    s.old_state = oi_read->state;
    memcpy(s.if_name, name, 40);

    cleanup
    return send_to_monitor(&s, sizeof(ism_change_state_t), 0);
}
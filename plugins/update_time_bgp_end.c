//
// Created by thomas on 25/11/18.
//

#include "ubpf_tools/include/public_bpf.h"
#include <ubpf_tools/include/monitoring_struct.h>

#define cleanup \
ctx_free(host_status);

int update_time__bgp_end(bpf_full_args_t *args) {

    monit_update_msg_t *msg;
    int ret;
    int *host_status;
    clock_t tick = clock();

    msg = ctx_shmget(1);
    if (!msg) {
        set_error("shmget failed", 14);
        return EXIT_FAILURE;
    }

    host_status = bpf_get_args(1, args);

    
    msg->end_processing = tick;
    msg->status = host_status != NULL ? *host_status : 0;


    ret = send_to_monitor(msg, sizeof(monit_update_msg_t), BGP_UPDATE_TIME_MSG);
    ctx_shmrm(1);

    if(!ret) {
        set_error("send_to_monitor failed", 23);
    }
    cleanup
    return ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
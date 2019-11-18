//
// Created by thomas on 10/12/18.
//

#include "ubpf_tools/include/public_bpf.h"
#include <ubpf_tools/include/monitoring_struct.h>

int end_decision_process(bpf_full_args_t *args) {

    monit_decision_process_t *decision_msg;
    clock_t end;
    int ret;

    decision_msg = ctx_shmget(1);
    if (!decision_msg) {
        set_error("shmget error", 13);
        return EXIT_FAILURE;
    }

    end = clock();

    memcpy(&decision_msg->end, &end, sizeof(time_t));

    ret = send_to_monitor(decision_msg, sizeof(monit_decision_process_t), BGP_DECISION_PROCESS);

    ctx_shmrm(1); // this shared memory won't be used anymore.

    if (!ret) {
        set_error("send_to_monitor failed", 23);
    }

    return ret ? EXIT_SUCCESS : EXIT_FAILURE;

}
//
// Created by thomas.
//

#include <xbgp_compliant_api/xbgp_plugin_api.h>

#define NEXT_SCHEDULE 10

int set_value(int a);

uint64_t job_test(args_t *args UNUSED) {
    int *has_executed;
    time_t next_schedule = NEXT_SCHEDULE;

    has_executed = ctx_shmget(12);

    if (has_executed == NULL) {
        log_msg(L_WARN "Creating shmem");
        has_executed = ctx_shmnew(12, sizeof(*has_executed));

        if (has_executed == NULL) {
            log_msg(L_WARN "Unable to get sh mem");
            return -1;
        }
        log_msg(L_WARN "shmem created");
        *has_executed = 0;
    }

    if (!*has_executed) {
        log_msg(L_WARN "Reschedule plugin");

        if (reschedule_plugin(&next_schedule) != 0) {
            log_msg(L_WARN "Unable to reschedule plugin !");
        }
        *has_executed = 1;
    } else {
        log_msg(L_WARN "Call set_value");
        set_value(56);
        ctx_shmrm(12);
    }

    return 0;
}
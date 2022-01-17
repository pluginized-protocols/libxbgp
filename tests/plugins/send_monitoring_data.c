//
// Created by twirtgen on 7/01/20.
//

#include <xbgp_compliant_api/xbgp_plugin_api.h>

uint64_t send_monitoring_data() {

    int data = 42;
    int ret_val;

    ret_val = log_msg(L_INFO "I send the value %d", LOG_INT(data)) ? EXIT_SUCCESS : EXIT_FAILURE;

    return ret_val;
}

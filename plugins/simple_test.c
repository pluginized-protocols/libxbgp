//
// Created by thomas on 26/10/18.
//

#include "ubpf_tools/include/public_bpf.h"
#include <ubpf_tools/include/monitoring_struct.h>

int my_super_complicated_function(int *bgp_port){

    bgp_test_t d;

    d.curr_timer = 9999;

    send_to_monitor(&d, sizeof(bgp_test_t), BGP_TEST);

    *bgp_port = 14785;
    return *bgp_port;
}
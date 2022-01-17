//
// Created by thomas on 1/07/21.
//

#include <xbgp_compliant_api/xbgp_plugin_api.h>


int set_value(int a);

uint64_t job_test(args_t *args UNUSED) {
    set_value(131);
    return 0;
}
//
// Created by thomas on 6/07/21.
//

#include <xbgp_compliant_api/xbgp_plugin_api.h>


int set_value2(int a);

uint64_t job_test(args_t *args UNUSED) {
    set_value2(111);
    return 0;
}
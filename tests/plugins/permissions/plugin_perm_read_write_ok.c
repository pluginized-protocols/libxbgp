//
// Created by thomas on 17/03/21.
//

#include <xbgp_compliant_api/xbgp_plugin_api.h>
#include "example_funcs.h"

uint64_t macro_void_test() {
    perm_read();
    perm_write();
    perm_read_write();
    return 0;
}

//
// Created by thomas on 16/02/22.
//

#include <xbgp_compliant_api/xbgp_plugin_api.h>

extern void set_replace_var(int var);

uint64_t main_macro_post(exec_info_t *info) {

    set_replace_var(info->replace_return_value + 1);

    return BPF_SUCCESS;
}
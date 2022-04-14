//
// Created by thomas on 13/04/22.
//

#ifndef LIBXBGP_VM_DUMB_FUNCTIONS_H
#define LIBXBGP_VM_DUMB_FUNCTIONS_H

#include <stdint.h>
#include <xbgp_compliant_api/xbgp_common_vm_defs.h>

typedef uint64_t (run_fn)(exec_info_t *);

enum dumb_fn_id {
    dumb_fn_id_min = 0,
    dumb_fn_no_insts,
    dumb_fn_loop_10,
    dumb_fn_loop_100,
    dumb_fn_loop_1000,
    dumb_fn_loop_10000,
    dumb_fn_loop_100000,
    dumb_fn_loop_1000000,
    dumb_fn_loop_1000_1api,
    dumb_fn_loop_1000_2api,
    dumb_fn_loop_1000_3api,
    dumb_fn_id_max
};


uint64_t direct_return(exec_info_t *info);
uint64_t loop_10(exec_info_t *info);
uint64_t loop_100(exec_info_t *info);
uint64_t loop_1000(exec_info_t *info);
uint64_t loop_10000(exec_info_t *info);
uint64_t loop_100000(exec_info_t *info);
uint64_t loop_1000000(exec_info_t *info);
uint64_t loop_1000_1api(exec_info_t *info);
uint64_t loop_1000_2api(exec_info_t *info);
uint64_t loop_1000_3api(exec_info_t *info);

#endif //LIBXBGP_VM_DUMB_FUNCTIONS_H

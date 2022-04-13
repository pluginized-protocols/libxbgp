//
// Created by thomas on 13/04/22.
//

#ifndef LIBXBGP_VM_DUMB_FUNCTION_EXEC_H
#define LIBXBGP_VM_DUMB_FUNCTION_EXEC_H

#include "plugins/dumb_functions.h"
#include "utils.h"

int run_native_function(enum dumb_fn_id id, struct timespec *tp);

int run_plugin_function(enum dumb_fn_id id, struct timespec *tp);

int run_functions(struct run_config *config);


#endif //LIBXBGP_VM_DUMB_FUNCTION_EXEC_H

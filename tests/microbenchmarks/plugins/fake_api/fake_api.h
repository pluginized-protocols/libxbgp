//
// Created by thomas on 14/04/22.
//

#ifndef LIBXBGP_VM_FAKE_API_H
#define LIBXBGP_VM_FAKE_API_H

#include <stddef.h>
#include "xbgp_compliant_api/xbgp_common.h"
#include "xbgp_compliant_api/xbgp_api_function_helper.h"

extern proto_ext_fun_t fake_funcs[];

void *fake_alloc(context_t *ctx, size_t size);

int *get_memory(context_t *ctx);

int set_memory(context_t *ctx, int value);




#endif //LIBXBGP_VM_FAKE_API_H

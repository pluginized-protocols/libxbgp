//
// Created by thomas on 12/04/22.
//

#ifndef LIBXBGP_VM_DEFS_TYPE_H
#define LIBXBGP_VM_DEFS_TYPE_H

#include "../../xbgp_deps/xbgp_compliant_api/xbgp_defs.h"


#define FAKE_VM_CALL 1

enum arg_type {
    TYPE_NULL =  ARG_MAX_OPAQUE,
    TYPE_INT,
};


enum FAKE_RETURN_TYPE {
    EXIT_BPF_SUCCESS,
    EXIT_BPF_ERROR,
};

#endif //LIBXBGP_VM_DEFS_TYPE_H

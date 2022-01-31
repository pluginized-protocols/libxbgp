//
// Created by thomas on 19/11/18.
//

#ifndef FRR_UBPF_PLUGIN_ARGUMENTS_H
#define FRR_UBPF_PLUGIN_ARGUMENTS_H

#include <stddef.h>
#include <stdint.h>
#include <xbgp_compliant_api/xbgp_common_vm_defs.h>

#define kind_null 0
#define kind_ptr 1
#define kind_primitive 2
#define kind_hidden 3

#define entry_arg_null {.arg = NULL, .len = 0, .kind = 0, .type = 0}
#define entry_is_null(entry) (((entry)->arg == NULL) && ((entry)->len == 0) && ((entry)->kind == 0) && ((entry)->type == 0))

#define build_args(entries) \
({ int i__;                               \
args_t args__;                            \
i__ = 0;                                  \
while(!entry_is_null(&(entries)[i__])) {  \
    i__++;                                \
}                                         \
args__.args = (entries);                  \
args__.nargs = i__;                     \
args__;})

struct entry_arg {
    void *arg;
    size_t len;
    short kind;
    int type; // custom type defined by the protocol insertion point
};


#endif //FRR_UBPF_PLUGIN_ARGUMENTS_H

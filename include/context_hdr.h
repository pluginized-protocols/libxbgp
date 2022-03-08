//
// Created by thomas on 20/02/20.
//

#ifndef UBPF_TOOLS_CONTEXT_HDR_H
#define UBPF_TOOLS_CONTEXT_HDR_H


#include "plugin_arguments.h"
#include "ebpf_mod_struct.h"

#include <xbgp_compliant_api/xbgp_common.h>
#include <xbgp_compliant_api/xbgp_api_function_helper.h>
#include <xbgp_compliant_api/xbgp_common_vm_defs.h>

typedef struct plugin plugin_t;


/**
 * This structure is passed to every pluglets
 * as one of their arguments. The structure
 * is accessible through it. However, every pointers
 * contained in this structure is not accessible by the
 * plugin and every attempt to dereference (during run-time)
 * any of these will result in a crash of the plugin.
 * (i.e. the VM stops its execution)
 */
struct bytecode_context {
    // contains internal information needed to run every plugins
    // You should add here every needed thing to correctly run
    // a given plugin
    unsigned int plugin_id; // on which plugin this pluglet is being run
    int type; // PRE REPLACE or POST pluglet
    int seq; // which sequence of pluglet is being run
    plugin_t *p; // backpointer to the plugin
    void *args;    // pointer to the arguments of the plugin
    unsigned int size_args;
    uint64_t *return_val;
    int error_status;
};

struct context {
    uint64_t *return_val;
    int return_value_set;
    int fallback;
    args_t *args; // arguments passed to the VM (but hidden and accessible through API only)
    exec_info_t *info; // argument accessible directly on the VM
    plugin_t *p;
    struct insertion_point_entry *pop; // point of presence of this VM
    struct vm_container *vm;

    insertion_point_info_t *insertion_point_info;
    proto_ext_fun_t *ext_api;
};

#endif //UBPF_TOOLS_CONTEXT_HDR_H

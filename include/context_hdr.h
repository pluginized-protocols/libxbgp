//
// Created by thomas on 20/02/20.
//

#ifndef UBPF_TOOLS_CONTEXT_HDR_H
#define UBPF_TOOLS_CONTEXT_HDR_H


typedef struct bytecode_context context_t;
typedef struct plugin plugin_t;


/**
 * This structure is passed to every plugins
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
    int type; // PRE REPLACE or POST
    plugin_t *p;
    void *args;    // pointer to the arguments of the plugin
#define LENGTH_CONTEXT_ERROR 50
    char error[LENGTH_CONTEXT_ERROR]; // string with small indication of the error;
    int error_status;
};

#endif //UBPF_TOOLS_CONTEXT_HDR_H

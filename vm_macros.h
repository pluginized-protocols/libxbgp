//
// Created by thomas on 26/02/19.
//

#ifndef FRR_UBPF_VM_MACROS_H
#define FRR_UBPF_VM_MACROS_H

//#include "plugins_manager.h"
//#include "ubpf_tools/include/c_lambda.h"

#define RETVAL_VM(ret_val, plug_id, plug_args) \
    {\
        run_plugin_post(plugins_manager, plug_id, plug_args, sizeof(plug_args), NULL);\
        return ret_val;\
    }\

#define DEFFUN_VM(func_name, ret_type, args, plug_id, plug_args, ...) \
    ret_type func_name args { \
        uint64_t __ret_val__;\
        run_plugin_pre(plugins_manager, plug_id, plug_args, sizeof(plug_args), NULL);\
        if(!run_plugin_replace(plugins_manager, plug_id, plug_args, sizeof(plug_args), &__ret_val__)) { \
            {__VA_ARGS__} \
        } else { \
            RETVAL_VM(__ret_val__, plug_id, plug_args);\
        } \
    } \

#endif //FRR_UBPF_VM_MACROS_H
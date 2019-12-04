//
// Created by thomas on 17/03/19.
//

#ifndef FRR_UBPF_PUBLIC_H
#define FRR_UBPF_PUBLIC_H


#include <stdlib.h>
#include <stdint.h>
#include "plugin_arguments.h"
#include "ebpf_mod_struct.h"


extern void set_write_fd(int fd);

extern int
init_plugin_manager(proto_ext_fun_t *api_proto, const char *process_vty_dir, size_t len, plugin_info_t *plugins_array,
                    const char *monitoring_address, const char *monitoring_port, int require_monit);

extern int load_plugin_from_json(const char *file_path, char *sysconfdir, size_t len_arg_sysconfdir);

extern int run_plugin_pre(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

extern int run_plugin_post(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

extern int run_plugin_replace(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

extern bpf_full_args_t *new_argument(bpf_args_t *args, int plugin_id, int nargs, bpf_full_args_t *fargs);

extern int unset_args(bpf_full_args_t *args);

extern bpf_full_args_t *new_argument(bpf_args_t *args, int plugin_id, int nargs, bpf_full_args_t *fargs);

extern int add_pluglet(const char *path_code, size_t add_mem_len, size_t shared_mem, int id_plugin, int type_plugglet,
                       uint32_t seq, uint8_t jit);

extern int rm_plugin(int id_plugin, const char **err);

extern void ubpf_terminate(void);

#define RETVAL_VM(ret_val, plug_id, plug_args, plug_size, ...) \
{\
    run_plugin_post(plug_id, plug_args, plug_size, NULL);\
    {__VA_ARGS__}\
    unset_args(plug_args);\
    return ret_val;\
}

#define POST_NO_RET(plug_id, plug_args, plug_size, ...) \
{\
    run_plugin_post(plug_id, plug_args, plug_size, NULL);\
    {__VA_ARGS__}\
    unset_args(plug_args);\
}

#define VM_CALL_COND(plug_id, plug_args, plug_size, ...)\
{\
    uint64_t __ret_val__;\
    run_plugin_pre(plug_id, plug_args, plug_size, NULL);\
    \
    if(!run_plugin_pre_append(plug_id, plug_args, plug_size, &__ret_val__)){\
        if(!run_plugin_replace(plug_id, plug_args, plug_size, &__ret_val__)) {\
            {__VA_ARGS__}\
        } else {\
            RETVAL_VM(__ret_val__, plug_id, plug_args, plug_size);\
        }\
    }\
    RETVAL_VM(__ret_val__, plug_id, plug_args, plug_size);\
}

#define VM_CALL(plug_id, plug_args, plug_size, ...)\
{\
    uint64_t __ret_val__;\
    run_plugin_pre(plug_id, plug_args, plug_size, NULL);\
    if(!run_plugin_replace(plug_id, plug_args, plug_size, &__ret_val__)) { \
        {__VA_ARGS__} \
    } else { \
        RETVAL_VM(__ret_val__, plug_id, plug_args, plug_size);\
    } \
}

#define VM_CALL_NO_RET(plug_id, plug_args, plug_size, ...)\
{\
    uint64_t __ret_val__;\
    run_plugin_pre(plug_id, plug_args, plug_size, NULL);\
    if(!run_plugin_replace(plug_id, plug_args, plug_size, &__ret_val__)) { \
        {__VA_ARGS__} \
    } else { \
        POST_NO_RET(plug_id, plug_args, plug_size);\
    } \
}

#define DEFFUN_VM(func_name, ret_type, args, plug_id, plug_args, plug_size, ...) \
ret_type func_name args { \
    VM_CALL(plug_id, plug_args, plug_size, __VA_ARGS__)\
}


#endif //FRR_UBPF_PUBLIC_H

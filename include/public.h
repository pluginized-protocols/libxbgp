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

extern int rm_plugin(int id_plugin, const char **err);

extern int run_volatile_plugin(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

extern int send_pluglet(const char *path, const char *plugin_name, short jit, int hook, unsigned int action,
                        uint16_t extra_mem, uint16_t shared_mem, uint32_t seq, int msqid);

int send_rm_pluglet(int msqid, const char *plugin_name, uint32_t seq, int anchor);


#define RETURN_VM_VOID(ret_val, ...) \
{\
    run_plugin_post(___PLUGIN_ID, _____fargs, sizeof(__fargs), NULL);\
    {##__VA_ARGS__}\
    unset_args(_____fargs);\
}

#define RETURN_VM_VAL(ret_val, ...) \
{\
    RETURN_VM_VOID(ret_val, __VA_ARGS__)\
    return ret_val;\
}

#define MACRO_VAL(ret_val, ...)

#define MACRO_VOID(ret_val, ...) \
RETURN_VM_VOID(ret_val, ##__VA_ARGS__)

#define VM_CALL_GEN(plug_id, plug_args, nargs, macro_def, ...)\
{\
    uint64_t __ret_val__;\
    unsigned int ___PLUGIN_ID = plug_id;\
    bpf_full_args_t __fargs, *_____fargs;\
    _____fargs = new_argument(plug_args, ___PLUGIN_ID, nargs, &__fargs);\
    run_plugin_pre(___PLUGIN_ID, _____fargs, sizeof(_____fargs), NULL);\
    if(!run_plugin_replace(___PLUGIN_ID, _____fargs, sizeof(_____fargs), &__ret_val__)) { \
        {__VA_ARGS__} \
        MACRO_ ## macro_def (__ret_val__)\
    } else {\
        RETURN_VM_ ## macro_def (__ret_val__);\
    }\
}

#define VM_CALL(plug_id, plug_args, nargs, ...) \
VM_CALL_GEN(plug_id, plug_args, nargs, VAL, __VA_ARGS__)

#define VM_CALL_VOID(plug_id, plug_args, nargs, ...) \
VM_CALL_GEN(plug_id, plug_args, nargs, VOID, __VA_ARGS__)

#define VM_CALL_CHECK_GEN(plug_id, plug_args, nargs, macro_def, ...) \
{\
    uint64_t __ret_val__;\
    unsigned int ___PLUGIN_ID = plug_id;\
    bpf_full_args_t __fargs, *_____fargs;\
    _____fargs = new_argument(plug_args, ___PLUGIN_ID, nargs, &__fargs);\
    switch(run_plugin_pre(___PLUGIN_ID, plug_args, sizeof(_____fargs), NULL)) {\
        case BPF_SUCCESS:\
            RETURN_VM_ ## macro_def (__ret_val__);\
        default:\
            break;\
    }\
    if(!run_plugin_replace(___PLUGIN_ID, plug_args, sizeof(_____fargs), &__ret_val__)) { \
        {__VA_ARGS__} \
    } else {\
        RETURN_VM_ ## macro_def (__ret_val__);\
    }\
}

#define VM_CALL_CHECK_VOID(plug_id, plug_args, nargs, ...)\
VM_CALL_CHECK_GEN(plug_id, plug_args, nargs, VOID, __VA_ARGS__)

#define VM_CALL_CHECK(plug_id, plug_args, nargs, ...)\
VM_CALL_CHECK_GEN(plug_id, plug_args, nargs, VAL, __VA_ARGS__)


#endif //FRR_UBPF_PUBLIC_H

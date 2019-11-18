//
// Created by thomas on 17/03/19.
//

#ifndef FRR_UBPF_PUBLIC_H
#define FRR_UBPF_PUBLIC_H


#include <stdlib.h>
#include <stdint.h>
#include "plugin_arguments.h"
#include "decision_process_manager.h"
#include "plugins_id.h"
#include "ebpf_mod_struct.h"


extern void set_write_fd(int fd);

extern int init_plugin_manager(proto_ext_fun_t *api_proto);

int main_monitor2(const char *address, const char *port, int fd_read);

extern void start_ubpf_plugin_listener(proto_ext_fun_t *api_proto);

extern void remove_xsi();

extern int load_from_json(const char *file_path);

extern int load_monit_info(const char *file_path, char *addr, size_t len_addr, char *port, size_t len_port);

extern int run_plugin_pre(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

extern int run_plugin_post(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

extern int run_plugin_replace(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

extern int run_plugin_pre_append(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

extern int run_plugin_post_append(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

extern bpf_full_args_t *new_argument(bpf_args_t *args, int plugin_id, int nargs, bpf_full_args_t *fargs);

extern int unset_args(bpf_full_args_t *args);

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

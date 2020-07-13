//
// Created by thomas on 17/03/19.
//

#ifndef FRR_UBPF_PUBLIC_H
#define FRR_UBPF_PUBLIC_H


#include <stdlib.h>
#include <stdint.h>
#include <json-c/json_object.h>
#include <insertion_point.h>
#include "plugin_arguments.h"
#include "ebpf_mod_struct.h"
#include "context_hdr.h"
#include "ubpf_mempool_hdr.h"

extern int
init_plugin_manager(proto_ext_fun_t *api_proto, const char *var_state_dir, size_t len,
                    insertion_point_info_t *insertion_points_array, const char *monitoring_address,
                    const char *monitoring_port, int require_monit);


extern int run_pre_functions(insertion_point_t *p, args_t *args, uint64_t *ret);

extern int run_post_functions(insertion_point_t *p, args_t *args, uint64_t *ret);

extern int run_replace_function(insertion_point_t *p, args_t *args, uint64_t *ret);

extern insertion_point_t *insertion_point(int id);

extern void ubpf_terminate(void);


/* manipulating memory of plugins in helper functions */
extern void *ctx_malloc(context_t *vm_ctx, size_t size);

extern int load_extension_code(const char *path, const char *extension_code_dir, proto_ext_fun_t *api_proto,
                               insertion_point_info_t *points_info);

#define INSERTION_POINT __plugin_point__
#define VM_RETURN_VALUE ___ret_call___
#define FULL_ARGS __fargs__

#define CALL_REPLACE_ONLY(insertion_id, args, arg_vm_check, on_err, ...)            \
{                                                                                   \
    uint64_t VM_RETURN_VALUE = 0;                                                   \
    int ___ubpf_status___ = 0;                                                      \
    int ___ubpf_the_err___ = 0;                                                     \
    insertion_point_t *point = insertion_point(insertion_id);                       \
    if(!point) ___ubpf_the_err___ = 1;                                              \
    if(!___ubpf_the_err___) {                                                       \
        args_t FULL_ARGS = build_args(args);                                            \
        ___ubpf_status___ = run_replace_function(point, &FULL_ARGS, &VM_RETURN_VALUE);  \
        if(___ubpf_status___ != 0) {___ubpf_the_err___ = 1;}                                \
        else if (!arg_vm_check(VM_RETURN_VALUE)) {___ubpf_the_err___ = 1;}              \
    }                                                                               \
    if (___ubpf_the_err___) {                                                       \
        {on_err}                                                                    \
    } else {                                                                        \
       {__VA_ARGS__}                                                                \
    }                                                                               \
}

#define RETURN(return_val) {\
    run_post_functions(INSERTION_POINT, &FULL_ARGS, NULL);\
    return return_val;\
}

#define CALL_ALL(insertion_id, args, args_vm_check, default_ret_val, on_err, ...){\
  uint64_t VM_RETURN_VALUE = 0; \
  args_t FULL_ARGS;\
  int ___ubpf_the_err___ = 0; \
  int ___ubpf_status___ = 0; \
  FULL_ARGS = build_args(args);\
  insertion_point_t *INSERTION_POINT = insertion_point(insertion_id);\
  if (!INSERTION_POINT) {___ubpf_the_err___ = 1;}\
  if (!___ubpf_the_err___) { \
     run_pre_functions(INSERTION_POINT, &FULL_ARGS, NULL);\
     ___ubpf_status___ = run_replace_function(INSERTION_POINT, &FULL_ARGS, &VM_RETURN_VALUE);\
     if (___ubpf_status___ != 0) {___ubpf_the_err___ = 1;}\
     else if (!args_vm_check(VM_RETURN_VALUE)) {___ubpf_the_err___ = 1;}\
  } \
  if (___ubpf_the_err___) {\
    {on_err} \
  } else {\
     {__VA_ARGS__} \
  }\
  if (!___ubpf_the_err___) { \
      RETURN(default_ret_val);\
  }\
  return default_ret_val;\
}

#define CALL_ALL_VOID(insertion_id, args, args_vm_check, on_err, ...) \
    CALL_ALL(insertion_id, args, args_vm_check, , on_err, __VA_ARGS__)

#endif //FRR_UBPF_PUBLIC_H

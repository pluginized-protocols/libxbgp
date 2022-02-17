//
// Created by thomas on 17/03/19.
//

#ifndef FRR_UBPF_PUBLIC_H
#define FRR_UBPF_PUBLIC_H


#include <stdlib.h>
#include <stdint.h>
#include <json-c/json_object.h>
#include "plugin_arguments.h"
#include "ebpf_mod_struct.h"
#include "context_hdr.h"
#include "ubpf_mempool_hdr.h"

#include <xbgp_compliant_api/xbgp_common.h>
#include <xbgp_compliant_api/xbgp_api_function_helper.h>


typedef struct insertion_point insertion_point_t;
typedef struct log_config log_config_t;

extern int
init_plugin_manager(proto_ext_fun_t *api_proto, const char *var_state_dir,
                    insertion_point_info_t *insertion_points_array, int dbg, log_config_t *logs);


extern int run_pre_functions(insertion_point_t *p, args_t *args, uint64_t *ret);

extern int run_post_functions(insertion_point_t *p, args_t *args, uint64_t *ret, uint64_t return_code);

extern int run_replace_function(insertion_point_t *p, args_t *args, uint64_t *ret);

extern insertion_point_t *insertion_point(int id);

extern void ubpf_terminate(void);

extern int extra_info_from_json(const char *path, const char *key);


/* manipulating memory of plugins in helper functions */
extern void *ctx_malloc(context_t *vm_ctx, size_t size);

#define ctx_calloc(vm_ctx, nmemb, size) ({ \
  void *ptr__;                               \
  ptr__ = ctx_malloc((vm_ctx), (nmemb) * (size));      \
  if (ptr__) {                               \
      memset(ptr__, 0, (nmemb) * (size));    \
  }                                          \
  ptr__;                                     \
})

extern void *new_runtime_data(plugin_t *p, const char *key, size_t key_len, void *data, size_t data_len);

extern void *new_runtime_data_int_key(plugin_t *p, unsigned int key, void *data, size_t data_len);

extern void *get_runtime_data(plugin_t *p, const char *key);

extern void *get_runtime_data_int_key(plugin_t *p, unsigned int key);

extern void del_runtime_data(plugin_t *p, const char *key);

extern void del_runtime_data_int_key(plugin_t *p, unsigned int key);

extern int load_extension_code(const char *path, const char *extension_code_dir, proto_ext_fun_t *api_proto,
                               insertion_point_info_t *points_info);

extern args_t *get_args_from_context(context_t *ctx);

#define INSERTION_POINT __plugin_point__
#define VM_RETURN_VALUE ___ret_call___
#define FULL_ARGS __fargs__
#define MAP_RET_TO_VM __map_ret_to_vm__

#define CALL_REPLACE_ONLY(insertion_id, args, arg_vm_check, on_err, ...)            \
do {                                                                                   \
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
} while(0)

#define RETURN_ARG(return_val) do { \
    uint64_t _tmp_ = return_val; \
    run_post_functions(INSERTION_POINT, &FULL_ARGS, NULL, MAP_RET_TO_VM(_tmp_));\
    return return_val;\
} while(0)

#define RETURN_VOID() do { \
    run_post_functions(INSERTION_POINT, &FULL_ARGS, NULL, 0); \
    return;                                                   \
} while(0)

#define RETURN__(_1, N, NAME, ...) NAME

#define RETURN(...) RETURN__(1, ##__VA_ARGS__, RETURN_ARG, RETURN_VOID)(__VA_ARGS__);


#define CALL_PRE(insertion_id, args) \
do {                                                \
   args_t FULL_ARGS = build_args(args);                    \
   insertion_point_t *INSERTION_POINT = insertion_point(insertion_id); \
   if (!INSERTION_POINT) break;                     \
   run_pre_functions(INSERTION_POINT, &FULL_ARGS, NULL);\
} while(0)

#define CALL_ALL(insertion_id, args, args_vm_check, default_ret_val, map_ret_to_vm, on_err, ...) do {\
  uint64_t VM_RETURN_VALUE = 0; \
  args_t FULL_ARGS;                                                                                  \
  uint64_t (*MAP_RET_TO_VM)(uint64_t) = map_ret_to_vm; \
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
} while(0)

#define CALL_ALL_VOID(insertion_id, args, args_vm_check, on_err, ...) \
    CALL_ALL(insertion_id, args, args_vm_check, , on_err, __VA_ARGS__)

#endif //FRR_UBPF_PUBLIC_H

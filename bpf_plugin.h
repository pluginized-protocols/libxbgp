//
// Created by thomas on 7/02/19.
//

#ifndef FRR_UBPF_BPF_PLUGIN_H
#define FRR_UBPF_BPF_PLUGIN_H

#include <stdint.h>
#include "list.h"
#include "include/public.h"
#include <ubpf_manager.h>

#define MAX_HEAP_PLUGIN 1048576 // 1MB
#define MAX_SIZE_ARGS_PLUGIN 512 // 512B must be checked before memcpy args

typedef enum BPF_PLUGIN_TYPE {
    BPF_PRE = 1,
    BPF_POST,
    BPF_REPLACE,
    BPF_PRE_APPEND,
    BPF_POST_APPEND,
} bpf_plugin_type_placeholder_t;

static const struct {
    bpf_plugin_type_placeholder_t val;
    const char *str;
} conversion_placeholder[] = {
        {BPF_PRE,         "bpf_pre"},
        {BPF_POST,        "bpf_post"},
        {BPF_REPLACE,     "bpf_replace"},
        {BPF_PRE_APPEND,  "bpf_append_pre"},
        {BPF_POST_APPEND, "bpf_append_post"},
};

typedef struct plugin {
    /* ptr_args and ptr_heap are tightened together since
     * ptr_args is the very beginning of the extra memory
     * of a plugin. Thus :
     * ptr_heap = ptr_args + MAX_SIZE_ARGS_PLUGIN
     * If no extra mem are allowed both ptr_{args,heap}
     * are null */
    size_t size_allowed_mem; // 0 if no extra memory
    // otherwise heap length + size for memory arguments

    struct {
        struct {
            bump_t mp;
            int has_mp;
            uint8_t *block;
        } heap;
        struct {
            heap_t smp;
            int has_smp;
            uint8_t *block;
        } shared_heap;
        uint8_t *block;
    } mem;
    list_t *pre_append;
    list_t *post_append;
    map_vm_t pre_functions;
    map_vm_t post_functions;
    vm_container_t *replace_function;
    unsigned int plugin_id;

    int is_active_replace : 1;
    int is_active_pre : 1;
    int is_active_post : 1;
    int is_active_pre_append : 1;
    int is_active_post_append : 1;

} plugin_t;

plugin_t *init_plugin(size_t heap_size, size_t sheap_size, unsigned int plugid);

void destroy_plugin(plugin_t *p);

int add_pre_function(plugin_t *p, const uint8_t *bytecode, size_t len, const char *sub_plugin_name, uint8_t jit);

int add_post_function(plugin_t *p, const uint8_t *bytecode, size_t len, const char *sub_plugin_name, uint8_t jit);

int add_replace_function(plugin_t *p, const uint8_t *bytecode, size_t len, const char *sub_plugin_name, uint8_t jit);

int run_pre_functions(plugin_t *p, uint8_t *args, size_t args_size, uint64_t *ret);

int run_post_functions(plugin_t *p, uint8_t *args, size_t args_size, uint64_t *ret);

int run_replace_function(plugin_t *p, uint8_t *args, size_t args_size, uint64_t *ret_val);

int run_append_function(plugin_t *p, uint8_t *args, size_t args_size, uint64_t *ret_val, int type);

int run_plugin_pre_append(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

int run_plugin_post_append(int plugin_id, void *args, size_t args_len, uint64_t *ret_val);

int add_pre_append_function(plugin_t *p, const uint8_t *bytecode, size_t len, const char *after,
                            const char *sub_plugin_name, uint8_t jit);

int add_post_append_function(plugin_t *p, const uint8_t *bytecode, size_t len, const char *after,
                             const char *sub_plugin_name, uint8_t jit);


bpf_plugin_type_placeholder_t bpf_type_str_to_enum(const char *str);

const char *id_plugin_to_str(unsigned int id);

int ptr_to_string(char *dest, void *ptr, size_t len);

#endif //FRR_UBPF_BPF_PLUGIN_H
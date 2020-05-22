//
// Created by thomas on 7/02/19.
//

#ifndef FRR_UBPF_BPF_PLUGIN_H
#define FRR_UBPF_BPF_PLUGIN_H

#include <stdint.h>
#include "list.h"
#include "include/public.h"
#include "tree.h"
#include <ubpf_manager.h>

#define MAX_HEAP_PLUGIN 1048576 // 1MB
#define MAX_SIZE_ARGS_PLUGIN 512 // 512B must be checked before memcpy args

typedef enum BPF_PLUGIN_TYPE {
    BPF_PRE = 1,
    BPF_POST,
    BPF_REPLACE,
} bpf_plugin_type_placeholder_t;

typedef struct plugin {
    /* ptr_args and ptr_heap are tightened together since
     * ptr_args is the very beginning of the extra memory
     * of a plugin. Thus :
     * ptr_heap = ptr_args + MAX_SIZE_ARGS_PLUGIN
     * If no extra mem are allowed both ptr_{args,heap}
     * are null */
    size_t size_allowed_mem; // 0 if no extra memory
    // otherwise heap length + size for memory arguments
    unsigned int plugin_id;

    struct {
        struct {
            bump_t mp;
            int has_mp;
            uint8_t *block; // should point to mem.block + ARG_SIZE
        } heap;
        struct {
            heap_t smp;
            int has_smp;
            uint8_t *block; // mem.block + ARG_SIZE + total_sizeof(heap.block)
        } shared_heap;
        uint8_t *block; // master block
    } mem;

    tree_t pre_functions;
    tree_t post_functions;

    struct {
        int nb;
        tree_t replace_functions;
        int ret_val_set;
    } replace;

    int fallback_request;

    struct plugin *new_transaction;

} plugin_t;

unsigned int get_plugin_id(plugin_t *plugin);

void fallback_request(plugin_t *p);

int must_fallback(plugin_t *p);

void post_plugin_exec(plugin_t *p);

plugin_t *init_plugin(size_t heap_size, size_t sheap_size, unsigned int plugid);

int init_plugin_transaction(plugin_t *p);

int commit_transaction(plugin_t *p);

void destroy_plugin(plugin_t *p);

int add_pre_function(plugin_t *p, const uint8_t *bytecode, size_t len, uint32_t seq, uint8_t jit);

int add_post_function(plugin_t *p, const uint8_t *bytecode, size_t len, uint32_t seq, uint8_t jit);

int add_replace_function(plugin_t *p, const uint8_t *bytecode, size_t len, uint32_t seq, uint8_t jit);


int transaction_pre_function(plugin_t *p, const uint8_t *bytecode, size_t len, uint32_t seq, uint8_t jit);

int transaction_post_function(plugin_t *p, const uint8_t *bytecode, size_t len, uint32_t seq, uint8_t jit);

int transaction_replace_function(plugin_t *p, const uint8_t *bytecode, size_t len, uint32_t seq, uint8_t jit);

int run_pre_functions(plugin_t *p, uint8_t *args, size_t args_size, uint64_t *ret);

int run_post_functions(plugin_t *p, uint8_t *args, size_t args_size, uint64_t *ret);

int run_replace_function(plugin_t *p, uint8_t *args, size_t args_size, uint64_t *ret_val);

const char *id_plugin_to_str(unsigned int id);

int str_plugin_to_int(const char *plugin_str);

int rm_pre_function(plugin_t *p, uint32_t seq);

int rm_replace_function(plugin_t *p, uint32_t seq);

int rm_post_function(plugin_t *p, uint32_t seq);

int run_replace_next_replace_function(context_t *ctx);

#endif //FRR_UBPF_BPF_PLUGIN_H
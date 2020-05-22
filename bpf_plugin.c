//
// Created by thomas on 7/02/19.
//

#include "bpf_plugin.h"
#include "list.h"
#include "hashmap.h"
#include "ubpf_context.h"

#include <string.h>
#include <stdio.h>
#include <include/tools_ubpf_api.h>
#include <assert.h>


plugin_t *init_plugin(size_t heap_size, size_t sheap_size, unsigned int plugid) {

    size_t total_allowed_mem;
    uint8_t *super_block;
    plugin_t *p;

    heap_size = (heap_size + 7u) & (-8u);
    sheap_size = (sheap_size + 7u) & (-8u);

    total_allowed_mem = sheap_size + heap_size + MAX_SIZE_ARGS_PLUGIN;

    if (total_allowed_mem > MAX_HEAP_PLUGIN) {
        return NULL;
    }

    p = calloc(1, sizeof(plugin_t));
    if (!p) return NULL;

    p->size_allowed_mem = total_allowed_mem;
    super_block = malloc(total_allowed_mem);
    if (!super_block) {
        perror("Can't alloc mem for plugin");
        free(p);
        return NULL;
    }

    p->mem.block = super_block;

    if (heap_size > 0) {
        p->mem.heap.has_mp = 1;
        p->mem.heap.block = super_block + MAX_SIZE_ARGS_PLUGIN;
        init_bump(&p->mem.heap.mp, heap_size, p->mem.heap.block);
    } else {
        init_bump(&p->mem.heap.mp, 0, NULL);
    }
    if (sheap_size > 0) {
        p->mem.shared_heap.has_smp = 1;
        p->mem.shared_heap.block = super_block + MAX_SIZE_ARGS_PLUGIN + heap_size;
        init_heap(&p->mem.shared_heap.smp, p->mem.shared_heap.block, sheap_size);
    } else {
        init_heap(&p->mem.shared_heap.smp, NULL, 0);
    }

    new_tree(&p->pre_functions);
    new_tree(&p->post_functions);

    p->replace.nb = 0;
    p->replace.ret_val_set = 0;
    new_tree(&p->replace.replace_functions);

    if (plugid == 0) { // TODO additional check
        free(super_block);
        free(p);
        return NULL;
    }
    p->plugin_id = plugid;
    p->new_transaction = NULL;
    return p;
}

int must_fallback(plugin_t *p) {
    if (!p) return 1;
    return p->fallback_request;
}

void fallback_request(plugin_t *p) {
    if (!p) return;
    p->fallback_request = 1;
}

void post_plugin_exec(plugin_t *p) {
    if (!p) return;
    p->fallback_request = 0;
}

static inline void flush_vm_tree(tree_t *vms) {

    struct tree_iterator *it, _it;
    vm_container_t **curr_vm;

    it = new_tree_iterator(vms, &_it);
    if (!it) {
        fprintf(stderr, "Unable to remove replace function");
        return;
    }

    while (tree_iterator_has_next(it)) {
        curr_vm = tree_iterator_next(it);
        shutdown_vm(*curr_vm);
    }

}

inline unsigned int get_plugin_id(plugin_t *plugin) {
    return plugin ? plugin->plugin_id : -1;
}

static inline void _destroy_plugin(plugin_t *p, int free_p) {
    unsigned int i;
    if (!p) return;

    tree_t *it_list[] = {&p->pre_functions, &p->post_functions, &p->replace.replace_functions};

    for (i = 0; i < sizeof(it_list) / sizeof(it_list[0]); i++) {
        flush_vm_tree(it_list[i]);
    }

    destroy_memory_management(&p->mem.shared_heap.smp);
    free(p->mem.block);
    if (free_p) free(p);
}

void destroy_plugin(plugin_t *p) {
    _destroy_plugin(p, 1);
}

static int init_ebpf_code(plugin_t *p, vm_container_t **new_vm, uint32_t seq,
                          const uint8_t *bytecode, size_t len, int type, uint8_t jit) {


    context_t *ctx;

    if (!p) return -1; // plugin must be init before loading eBPF code

    ctx = new_context(p);
    if (!ctx) return -1;

    ctx->type = type;
    ctx->seq = seq;
    ctx->plugin_id = p->plugin_id;

    if (!register_context(ctx)) {
        free(ctx);
        return -1;
    }

    if (!vm_init(new_vm, ctx, p->mem.block, seq, p->size_allowed_mem, jit))
        return -1;

    if (!start_vm(*new_vm)) return -1;
    if (!inject_code_ptr(*new_vm, bytecode, len)) return -1;

    return 0;
}

static inline int
generic_add_function(plugin_t *p, const uint8_t *bytecode, size_t len,
                     uint32_t seq, int type, uint8_t jit) {

    tree_t *l = NULL;
    vm_container_t *new_vm, *get_vm;

    if (!p || !bytecode) return -1;

    switch (type) {
        case BPF_PRE:
            l = &p->pre_functions;
            break;
        case BPF_POST:
            l = &p->post_functions;
            break;
        case BPF_REPLACE:
            seq = p->replace.nb++; // update after storing
            l = &p->replace.replace_functions;
            break;
        default:
            return -1;
    }

    if (init_ebpf_code(p, &new_vm, seq, bytecode, len, type, jit) != 0) {
        return -1;
    }

    if (tree_get(l, seq, &get_vm) == 0) {
        shutdown_vm(get_vm);
    }
    tree_put(l, seq, &new_vm, sizeof(vm_container_t *));

    return 0;
}

int add_pre_function(plugin_t *p, const uint8_t *bytecode, size_t len, uint32_t seq, uint8_t jit) {
    if (!p) return -1;
    return generic_add_function(p, bytecode, len, seq, BPF_PRE, jit);
}

int add_post_function(plugin_t *p, const uint8_t *bytecode, size_t len, uint32_t seq, uint8_t jit) {
    if (!p) return -1;
    return generic_add_function(p, bytecode, len, seq, BPF_POST, jit);
}

int add_replace_function(plugin_t *p, const uint8_t *bytecode, size_t len, uint32_t seq, uint8_t jit) {
    if (!p) return -1;
    return generic_add_function(p, bytecode, len, seq, BPF_REPLACE, jit);
}

int transaction_pre_function(plugin_t *p, const uint8_t *bytecode, size_t len, uint32_t seq, uint8_t jit) {
    if (!p) return -1;
    if (!p->new_transaction) return -1;
    return generic_add_function(p->new_transaction, bytecode, len, seq, BPF_PRE, jit);
}

int transaction_post_function(plugin_t *p, const uint8_t *bytecode, size_t len, uint32_t seq, uint8_t jit) {
    if (!p) return -1;
    if (!p->new_transaction) return -1;
    return generic_add_function(p->new_transaction, bytecode, len, seq, BPF_PRE, jit);
}

int transaction_replace_function(plugin_t *p, const uint8_t *bytecode, size_t len, uint32_t seq, uint8_t jit) {
    if (!p) return -1;
    if (!p->new_transaction) return -1;
    return generic_add_function(p->new_transaction, bytecode, len, seq, BPF_PRE, jit);
}

int init_plugin_transaction(plugin_t *p) {

    plugin_t *new_p;
    if (p->new_transaction) return -1;

    new_p = init_plugin(p->mem.heap.mp.total_mem, p->mem.shared_heap.smp.heap_len, p->plugin_id);

    if (!new_p) return -1;
    return 0;
}

int commit_transaction(plugin_t *p) {

    plugin_t *p_tran;

    if (!p) return -1;
    if (!p->new_transaction) return -1;

    p_tran = p->new_transaction;
    _destroy_plugin(p, 0);

    memcpy(p, p_tran, sizeof(plugin_t));
    p->new_transaction = NULL;

    // free memcpy
    return 0;
}

static inline int generic_rm_function(plugin_t *p, uint32_t seq, int anchor) {

    vm_container_t *vm;

    switch (anchor) {
        case BPF_PRE:
            if (tree_get(&p->pre_functions, seq, &vm) != 0) return -1;
            break;
        case BPF_REPLACE:
            flush_vm_tree(&p->replace.replace_functions);
            p->replace.nb = 0;
            return 0;
        case BPF_POST:
            if (tree_get(&p->post_functions, seq, &vm) != 0) return -1;
            break;
        default:
            return -1;
    }

    shutdown_vm(vm);
    return 0;
}

int rm_pre_function(plugin_t *p, uint32_t seq) {
    if (!p) return -1;
    return generic_rm_function(p, seq, BPF_PRE);
}

int rm_replace_function(plugin_t *p, uint32_t seq) {
    if (!p) return -1;
    return generic_rm_function(p, seq, BPF_REPLACE);
}

int rm_post_function(plugin_t *p, uint32_t seq) {
    if (!p) return -1;
    return generic_rm_function(p, seq, BPF_POST);
}

static inline int generic_run_function(plugin_t *p, uint8_t *args, size_t args_size, int type, uint64_t *ret) {

    struct tree_iterator _it, *it;
    tree_t *t;
    vm_container_t **vm, *replace_vm;
    int exec_ok;

    switch (type) {
        case BPF_REPLACE:
            if (tree_get(&p->replace.replace_functions, 0, &replace_vm) != 0) return -1;
            exec_ok = run_injected_code(replace_vm, args, args_size, ret);
            return exec_ok;
        case BPF_PRE:
            t = &p->pre_functions;
            break;
        case BPF_POST:
            t = &p->post_functions;
            break;
        default:
            return -1;
    }


    it = new_tree_iterator(t, &_it);
    while ((vm = tree_iterator_next(it)) != NULL) {
        exec_ok = run_injected_code(*vm, args, args_size, ret);
        if (ret) {
            switch (*ret) {
                case BPF_FAILURE:
                case BPF_SUCCESS:
                    rm_tree_iterator(it);
                    return *ret;
                case BPF_CONTINUE:
                default:
                    break;
            }
        }
    }
    rm_tree_iterator(it);
    return 0;
}

int run_pre_functions(plugin_t *p, uint8_t *args, size_t args_size, uint64_t *ret) {
    if (!p) return -1;
    return generic_run_function(p, args, args_size, BPF_PRE, ret);
}

int run_post_functions(plugin_t *p, uint8_t *args, size_t args_size, uint64_t *ret) {
    if (!p) return -1;
    return generic_run_function(p, args, args_size, BPF_POST, ret);
}

int run_replace_function(plugin_t *p, uint8_t *args, size_t args_size, uint64_t *ret) {
    if (!p) return -1;
    return generic_run_function(p, args, args_size, BPF_REPLACE, ret);
}

int run_replace_next_replace_function(context_t *ctx) {

    plugin_t *plugin;
    vm_container_t *vmc;

    if (!ctx) return -1;
    if (ctx->type != BPF_REPLACE) return -1;

    plugin = ctx->p;

    if (!plugin) return -1;

    if (tree_get(&plugin->replace.replace_functions, ctx->seq + 1, &vmc) != 0) {
        // ask to run fallback code
        fallback_request(ctx->p);
        return -1;
    }

    // flush all memory taken by the previous call
    reset_bump(&vmc->ctx->p->mem.heap.mp);
    return run_injected_code(vmc, ctx->args, ctx->size_args, ctx->return_val);

}
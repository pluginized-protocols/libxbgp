//
// Created by thomas on 7/02/19.
//

#include "bpf_plugin.h"
#include "list.h"
#include "hashmap.h"
#include "ubpf_context.h"

#include <string.h>
#include <stdio.h>


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
    p->replace_function = NULL;

    if (plugid == 0) { // TODO additional check
        free(super_block);
        free(p);
        return NULL;
    }
    p->plugin_id = plugid;
    return p;
}

void destroy_plugin(plugin_t *p) {

    int i;
    struct tree_iterator *it, _it;
    vm_container_t **curr_vm;
    if (!p) return;

    tree_t *it_list[] = {&p->pre_functions, &p->post_functions};

    for (i = 0; i < 2; i++) {
        it = new_tree_iterator(it_list[i], &_it);
        while (tree_iterator_has_next(it)) {
            curr_vm = tree_iterator_next(it);
            shutdown_vm(*curr_vm);
        }
        rm_tree_iterator(it);
    }

    if (p->replace_function) shutdown_vm(p->replace_function);

    delete_tree(&p->pre_functions);
    delete_tree(&p->post_functions);

    destroy_memory_management(&p->mem.shared_heap.smp);
    free(p->mem.block);
    free(p);
}

static int init_ebpf_code(plugin_t *p, vm_container_t **new_vm, uint32_t seq,
                          const uint8_t *bytecode, size_t len, uint8_t jit) {


    context_t *ctx;

    if (!p) return -1; // plugin must be init before loading eBPF code

    ctx = new_context(p);
    if (!ctx) return -1;

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
    vm_container_t *new_vm;

    if (!p || !bytecode) return -1;

    switch (type) {
        case BPF_PRE:
            l = &p->pre_functions;
            break;
        case BPF_POST:
            l = &p->post_functions;
            break;
        case BPF_REPLACE:
            if (p->replace_function) {
                shutdown_vm(p->replace_function);
                p->replace_function = NULL;
            }
            break;
        default:
            return -1;
    }

    if (init_ebpf_code(p, &new_vm, seq, bytecode, len, jit) != 0) {
        return -1;
    }

    if (type != BPF_REPLACE) {
        tree_put(l, seq, &new_vm, sizeof(vm_container_t *));
    } else {
        p->replace_function = new_vm;
    }

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

static inline int generic_run_function(plugin_t *p, uint8_t *args, size_t args_size, int type, uint64_t *ret) {

    struct tree_iterator _it, *it;
    tree_t *t;
    vm_container_t **vm;
    int exec_ok;

    switch (type) {
        case BPF_REPLACE:
            exec_ok = run_injected_code(p->replace_function, args, args_size, ret);
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
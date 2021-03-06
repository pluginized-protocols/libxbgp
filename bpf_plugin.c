//
// Created by thomas on 7/02/19.
//

#include "bpf_plugin.h"
#include "ubpf_context.h"
#include "insertion_point.h"
#include "shared_memory.h"
#include "ubpf_manager.h"

#include <string.h>
#include <stdio.h>
#include <include/tools_ubpf_api.h>
#include <assert.h>


plugin_t *init_plugin(size_t heap_size, size_t sheap_size, const char *name, size_t name_len, int permissions) {

    size_t total_allowed_mem;
    uint8_t *super_block;
    plugin_t *p;

    heap_size = (heap_size + 7u) & (-8u);
    sheap_size = (sheap_size + 7u) & (-8u);

    total_allowed_mem = sheap_size + heap_size + MAX_SIZE_ARGS_PLUGIN;

    if (total_allowed_mem > MAX_HEAP_PLUGIN) {
        return NULL;
    }

    p = calloc(1, sizeof(plugin_t) + (sizeof(char) * (name_len + 1)));


    if (!p) return NULL;
    p->vms = NULL;
    memcpy(p->name, name, name_len);
    p->str_len = name_len;
    p->permissions = permissions;

    p->mem_len = total_allowed_mem;
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

    p->vms = NULL;

    return p;
}

static inline void destroy_plugin__(plugin_t *p, int free_p) {
    vm_container_t *curr_vm, *tmp;
    if (!p) return;
    destroy_memory_management(&p->mem.shared_heap.smp);
    free(p->mem.block);

    HASH_ITER(hh_plugin, p->vms, curr_vm, tmp) {
        HASH_DELETE(hh_plugin, p->vms, curr_vm);
        /* remove vm from insertion point too! */
        rm_vm_insertion_point(curr_vm);
        shutdown_vm(curr_vm);
    }

    if (free_p) free(p);
}

void destroy_plugin(plugin_t *p) {
    destroy_plugin__(p, 1);
}

int plugin_add_vm(plugin_t *p, vm_container_t *vm) {
    vm_container_t *the_vm;
    HASH_FIND(hh_plugin, p->vms, vm->vm_name, vm->vm_name_len, the_vm);
    if (the_vm) return -1; // VM is already added to the plugin.

    HASH_ADD(hh_plugin, p->vms, vm_name, vm->vm_name_len, vm);
    return 0;
}

int plugin_delete_vm(vm_container_t *vm) {
    HASH_DELETE(hh_plugin, vm->p->vms, vm);
    return 0;
}

//static int init_ebpf_code(plugin_t *p, vm_container_t **new_vm, uint32_t seq,
//                          const uint8_t *bytecode, size_t len, int type, uint8_t jit) {
//
//
//    context_t *ctx;
//
//    if (!p) return -1; // plugin must be init before loading eBPF code
//
//    ctx = new_context(p);
//    if (!ctx) return -1;
//
//    ctx->type = type;
//    ctx->seq = seq;
//    ctx->plugin_id = p->plugin_id;
//
//    if (!register_context(ctx)) {
//        free(ctx);
//        return -1;
//    }
//
//    if (!vm_init(new_vm, ctx, p->mem.block, seq, p->size_allowed_mem, jit))
//        return -1;
//
//    if (!start_vm(*new_vm)) return -1;
//    if (!inject_code_ptr(*new_vm, bytecode, len)) return -1;
//
//    return 0;
//}
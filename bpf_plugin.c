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

    heap_size = MEM_ALIGN(heap_size);
    sheap_size = MEM_ALIGN(sheap_size);

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

    p->mem.len = total_allowed_mem;
    super_block = malloc(total_allowed_mem);
    if (!super_block) {
        perror("Can't alloc mem for plugin");
        free(p);
        return NULL;
    }

    p->mem.master_block = super_block;

    if (heap_size > 0) {
        p->mem.has_heap = 1;

        // TODO give to the user the ability to change memory type
        if (init_memory_manager(&p->mem.mgr_heap, MICHELFRA_MEM) != 0) {
            return NULL;
        }

        mem_init(&p->mem.mgr_heap, super_block + MAX_SIZE_ARGS_PLUGIN, heap_size);

    } /*else {
        init_bump(&p->mem.heap.mp, 0, NULL);
    }*/

    if (sheap_size > 0) {
        p->mem.has_shared_heap = 1;

        if (init_memory_manager(&p->mem.mgr_shared_heap, MICHELFRA_MEM) != 0) {
            return NULL;
        }

        mem_init(&p->mem.mgr_shared_heap, super_block + MAX_SIZE_ARGS_PLUGIN + heap_size, sheap_size);
    }

    p->vms = NULL;

    dict_init(&p->runtime_dict);

    return p;
}

static inline void destroy_plugin__(plugin_t *p, int free_p) {
    vm_container_t *curr_vm, *tmp;
    if (!p) return;

    destroy_memory_manager(&p->mem.mgr_heap);
    destroy_memory_manager(&p->mem.mgr_shared_heap);
    destroy_shared_map(&p->mem.shared_blocks);
    free(p->mem.master_block);

    HASH_ITER(hh_plugin, p->vms, curr_vm, tmp) {
        HASH_DELETE(hh_plugin, p->vms, curr_vm);
        /* remove vm from insertion point too! */
        rm_vm_insertion_point(curr_vm);
        shutdown_vm(curr_vm);
    }

    dict_del(&p->runtime_dict);

    if (free_p) free(p);
}

void plugin_lock_ref(plugin_t *p) {
    if (!p) return;
    p->refcount += 1;
}

void plugin_unlock_ref(plugin_t *p) {
    if (!p) return;

    p->refcount -= 1;

    if (p->refcount <= 0) {
        destroy_plugin__(p, 1);
    }
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

int run_plugin(plugin_t *p) {
    vm_container_t *vm, *tmp;
    uint64_t ret_val;

    if (!p) return -1;

    HASH_ITER(hh_plugin, p->vms, vm, tmp) {
        if (run_injected_code(vm, &ret_val) == -1) {
            return -1;
        }
    }
    return 0;
}

void *new_runtime_data(plugin_t *p, const char *key, size_t key_len, void *data, size_t data_len) {
    return dict_add(&p->runtime_dict, key, key_len, data, data_len);
}

void *new_runtime_data_int_key(plugin_t *p, unsigned int key, void *data, size_t data_len) {
    return dict_add_key_int(&p->runtime_dict, key, data, data_len);
}

void *get_runtime_data(plugin_t *p, const char *key) {
    return dict_get(&p->runtime_dict, key);
}

void *get_runtime_data_int_key(plugin_t *p, unsigned int key) {
    return dict_get_by_int(&p->runtime_dict, key);
}

void del_runtime_data(plugin_t *p, const char *key) {
    return dict_entry_del(&p->runtime_dict, key);
}

void del_runtime_data_int_key(plugin_t *p, unsigned int key) {
    return dict_entry_del_key_int(&p->runtime_dict, key);
}
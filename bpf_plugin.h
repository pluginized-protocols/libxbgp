//
// Created by thomas on 7/02/19.
//

#ifndef FRR_UBPF_BPF_PLUGIN_H
#define FRR_UBPF_BPF_PLUGIN_H

#include <stdint.h>
#include <stddef.h>
#include "shared_memory.h"
#include "uthash.h"

#define MAX_HEAP_PLUGIN 1048576 // 1MB
#define MAX_SIZE_ARGS_PLUGIN 512 // 512B must be checked before memcpy args


typedef struct vm_container vm_container_t;

typedef struct plugin {
    /* ptr_args and ptr_heap are tightened together since
     * ptr_args is the very beginning of the extra memory
     * of a plugin. Thus :
     * ptr_heap = ptr_args + MAX_SIZE_ARGS_PLUGIN
     * If no extra mem are allowed both ptr_{args,heap}
     * are null */
    size_t mem_len; // 0 if no extra memory
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

    vm_container_t *vms; // hash table of vms attached to the plugin

    UT_hash_handle hh;

    /**/
    int permissions; // "ANDROID like" permissions

    size_t str_len;
    char name[0];

} plugin_t;

plugin_t *init_plugin(size_t heap_size, size_t sheap_size, const char *name, size_t name_len, int permission);

void destroy_plugin(plugin_t *p);

int plugin_add_vm(plugin_t *p, vm_container_t *vm);

int plugin_delete_vm(vm_container_t *vm);

void destroy_plugin(plugin_t *p);

int run_plugin(plugin_t *p);

#endif //FRR_UBPF_BPF_PLUGIN_H
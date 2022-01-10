//
// Created by thomas on 7/02/19.
//

#ifndef FRR_UBPF_BPF_PLUGIN_H
#define FRR_UBPF_BPF_PLUGIN_H

#include <stdint.h>
#include <stddef.h>
#include "shared_memory.h"
#include "uthash.h"
#include "dict.h"

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

    struct {
        uint8_t has_heap: 1;
        uint8_t has_shared_heap: 1;
        size_t len;
        uint8_t *master_block;

        struct memory_manager mgr_heap;
        struct memory_manager mgr_shared_heap;
        map_shared_t *shared_blocks;
    } mem;

    dict_t runtime_dict;

    vm_container_t *vms; // hash table of vms attached to the plugin

    UT_hash_handle hh;

    /**/
    int permissions; // "ANDROID like" permissions

    int refcount;

    size_t str_len;
    char name[0];

} plugin_t;

plugin_t *init_plugin(size_t heap_size, size_t sheap_size, const char *name, size_t name_len, int permission);

/**
 * Increase the reference counter by one.
 * It tells that another object keeps its
 * reference
 * @param p the plugin pointer
 */
void plugin_lock_ref(plugin_t *p);

/**
 * Decrease the reference counter by one.
 * If the counter reaches 0 or below, the
 * plugin is freed
 * @param p the plugin pointer
 */
void plugin_unlock_ref(plugin_t *p);

int plugin_add_vm(plugin_t *p, vm_container_t *vm);

int plugin_delete_vm(vm_container_t *vm);

int run_plugin(plugin_t *p);

void *new_runtime_data(plugin_t *p, const char *key, size_t key_len, void *data, size_t data_len);

void *new_runtime_data_int_key(plugin_t *p, unsigned int key, void *data, size_t data_len);

void *get_runtime_data(plugin_t *p, const char *key);

void *get_runtime_data_int_key(plugin_t *p, unsigned int key);

void del_runtime_data(plugin_t *p, const char *key);

void del_runtime_data_int_key(plugin_t *p, unsigned int key);

#endif //FRR_UBPF_BPF_PLUGIN_H
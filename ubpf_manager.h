//
// Created by thomas on 26/10/18.
//

#ifndef FRR_THESIS_UBPF_MANAGER_H
#define FRR_THESIS_UBPF_MANAGER_H


#include <ubpf_vm/vm/inc/ubpf.h>
#include <include/ebpf_mod_struct.h>
#include "uthash.h"
#include "bpf_plugin.h"
#include "insertion_point.h"


typedef struct context context_t;

typedef struct vm_container {
    struct ubpf_vm *vm;
    unsigned int num_ext_fun; // count the number of external API function already registered in this VM
    context_t *ctx;
    plugin_t *p;
    uint8_t *mem;// this pointer points on the top of extra memory granted for plugins
    size_t total_mem;
    uint8_t jit;
    ubpf_jit_fn fun;
    struct insertion_point_entry *pop;

    UT_hash_handle hh; // hh hash-table all vms
    UT_hash_handle hh_plugin; // for plugins
    UT_hash_handle hh_insertion_point;

    void ((*on_delete)(void *));

    size_t vm_name_len;
    char vm_name[0];

    // a vm_container contains the execution context for
    // one single eBPF function
} vm_container_t;

/**
 * Allocate space for uBPF machine and update the pointer given at argument
 * @param vmc, pointer to a vm_container_t structure
 * @return 1 if uBPF machine is successfully created, 0 otherwise
 */
vm_container_t *new_vm(anchor_t anchor, int seq, insertion_point_t *point, uint8_t jit,
                       const char *name, size_t name_len, plugin_t *p,
                       uint8_t *obj_data, size_t obj_len, proto_ext_fun_t *api_proto,
                       void (*on_delete)(void *));

/**
 * Destroy an uBPF machine. Memory related to the structure is not freed.
 * The caller must explicitly free the memory after using the wrapper
 * @param vmc structure containing a valid running instance of VM
 * @return void
 */
void shutdown_vm(vm_container_t *vmc);


/**
 * This is the last step, this function will execute the loaded code
 * by passing the memory located at the address contained in the mem
 * argument.
 * @param vmc a uBPF machine already started with loaded code inside it
 * @param mem pointer to the memory zone used by the loaded code
 * @param mem_len size of the memory pointed by mem
 * @return the result of the execution of the loaded code
 */
int run_injected_code(vm_container_t *vmc, uint64_t *ret_val);

void start_ubpf_plugin_listener(proto_ext_fun_t *fn);

int safe_ubpf_register(vm_container_t *vmc, const char *name, void *fn);


#endif //FRR_THESIS_UBPF_MANAGER_H

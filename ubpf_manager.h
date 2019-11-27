//
// Created by thomas on 26/10/18.
//

#ifndef FRR_THESIS_UBPF_MANAGER_H
#define FRR_THESIS_UBPF_MANAGER_H

#include "shared_memory.h"
#include <ubpf_vm/vm/inc/ubpf.h>
#include <include/public.h>
#include "include/plugin_arguments.h"
#include "map.h"


typedef struct bytecode_context context_t;

typedef struct vm_container {
    struct ubpf_vm *vm;
    unsigned int num_ext_fun;
    context_t *ctx;
    uint8_t *args;// this pointer points on the top of extra memory allowed for plugins
    size_t total_mem;
    char name[21];
    uint8_t jit;
    ubpf_jit_fn fun;

    void *ctx_specific; // extra field for specific state to maintain according the function

    // a vm_container contains the execution context for
    // one single eBPF function, however this heap is shared
    // by multiple VMs belonging to a set of VMs
    // Henceforth, a pointer to the "global" heap is passed to
    // this VM.
    /// THIS HEAP MUST NOT BE FREED BY THIS CONTAINER SINCE IT
    /// MAY BE USED BY OTHER VMs STILL RUNNING.
} vm_container_t;

typedef struct generic_args {
    context_t *ctx;
} generic_args_t;

typedef map_t(vm_container_t *) map_vm_t;

/**
 * Allocate space for uBPF machine and update the pointer given at argument
 * @param vmc, pointer to a vm_container_t structure
 * @return 1 if uBPF machine is successfuly created, 0 otherwise
 */
int vm_init(vm_container_t **vmc, context_t *ctx, uint8_t *args_mem, const char *name, size_t len,
            size_t tot_extra, uint8_t jit);

/**
 * Start the uBPF machine by allocating the freshly
 * created vm_container_t structure (made by the caller).
 * @param vmc, a structure which memory is already allocated but vm is not started yet
 * @return 1 if uBPF machine is correctly started
 *         0 if something wrong happened
 */
int start_vm(vm_container_t *vmc);

/**
 * Destroy an uBPF machine. Memory related to the structure is not freed.
 * The caller must explicitly free the memory after using the wrapper
 * @param vmc, structure containing a valid running instance of VM
 * @return void
 */
void shutdown_vm(vm_container_t *vmc);

/**
 * Load the code located in path_code into the vm
 * @param vmc an uBPF machine already started (i.e. start_vm must
 *            must be called before this function)
 * @param path_code path to the file system where the compiled
 *                  code is located (clang bytecode)
 * @return 1 if the injection has been successfully done
 *         0 otherwise
 */
int inject_code(vm_container_t *vmc, const char *path_code);

int inject_code_ptr(vm_container_t *vmc, const uint8_t *data, size_t len);

/**
 * This is the last step, this function will execute the loaded code
 * by passing the memory located at the address contained in the mem
 * argument.
 * @param vmc a uBPF machine already started with loaded code inside it
 * @param mem pointer to the memory zone used by the loaded code
 * @param mem_len size of the memory pointed by mem
 * @return the result of the execution of the loaded code
 */
int run_injected_code(vm_container_t *vmc, void *mem, size_t mem_len, uint64_t *ret_val);

void *readfileOwnPtr(const char *path, size_t maxlen, size_t *len, uint8_t *data);

void start_ubpf_plugin_listener(proto_ext_fun_t *fn);

context_t *get_curr_context(void);

int init_ubpf_manager(proto_ext_fun_t *fn);

bpf_full_args_t *new_argument(bpf_args_t *args, int plugin_id, int nargs, bpf_full_args_t *fargs);
int unset_args(bpf_full_args_t *args);
bpf_args_t *get_args(bpf_full_args_t *args);
bpf_full_args_t *valid_args(bpf_full_args_t *args);

int safe_ubpf_register(vm_container_t *vmc, const char *name, void *fn);




#endif //FRR_THESIS_UBPF_MANAGER_H

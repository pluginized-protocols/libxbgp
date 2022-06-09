//
// Created by thomas on 26/10/18.
//

#include <stdint.h>
#include "ubpf_manager.h"
#include "ubpf_api.h"
#include "ubpf_vm/vm/inc/ubpf.h"
#include "bpf_plugin.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>
#include <time.h>
#include <include/plugin_arguments.h>
#include "ubpf_context.h"
#include "insertion_point.h"
#include "plugins_manager.h"
#include <pthread.h>
#include <include/ebpf_mod_struct.h>
#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include "ebpf_mod_struct.h"
#include "context_function.h"
#include "utlist.h"

/* check permission */
int check_perms(int fun_perms, int plugin_perms) {
    int fun_masked;
    int plugin_masked;

    fun_masked = fun_perms & HELPER_ATTR_MASK;
    plugin_masked = plugin_perms & HELPER_ATTR_MASK;
    return (fun_masked & plugin_masked) == fun_masked;
}

int safe_ubpf_register(vm_container_t *vmc, const char *name, void *fn, int permissions) {

    if (!check_perms(permissions, vmc->p->permissions)) {
        // this is not an error. We simply don't load the
        // function inside the VM since the plugin does not
        // have sufficient rights to call the external function
        return 1;
    }

    if (vmc->num_ext_fun >= 128) {
        fprintf(stderr, "Number of external functions overflows\n");
        return 0;
    }

    if (vmc->num_ext_fun == 0x3F) vmc->num_ext_fun++; // skip because the ID is already taken for OOB call
    if (vmc->num_ext_fun == 0x7F) vmc->num_ext_fun++; // skip because the ID is already taken for next call
    if (ubpf_register(vmc->vm, vmc->num_ext_fun++, name, fn) == -1) return 0;

    return 1;
}


static inline int base_register(vm_container_t *vmc) {
    ssize_t i;
    closure_t *current_closure;
    void *api_fun;

    for (i = 0; i < base_api_fun_len__; i++) {
        if (vmc->use_libffi) {
            current_closure = make_closure(base_api_fun__[i].closure_fn,
                                           base_api_fun__[i].args_nb,
                                           base_api_fun__[i].args_type,
                                           base_api_fun__[i].return_type,
                                           vmc->ctx);
            if (!current_closure) {
                goto err;
            }
            api_fun = current_closure->fn;

            /* add closure to the current container */
            if (add_closure(vmc, current_closure) != 0) {
                goto err;
            }
        } else {
            api_fun = base_api_fun__[i].fn;
        }

        /* special handling of function */
        if (base_api_fun__[i].fn == next) {
            // DO NOT TOUCH THIS FUNCTION, NEITHER ITS ID.. USED TO SWITCH TO THE NEXT PART OF THE REPLACE INSERTION POINT
            if (vmc->ctx->pop->anchor == BPF_REPLACE) {
                if (ubpf_register(vmc->vm, 0x7F, base_api_fun__[i].name, api_fun) == -1) return 0;
            }
        } else if (base_api_fun__[i].fn == membound_fail) {
            // DO NOT TOUCH THIS FUNCTION, NEITHER ITS ID.. USED TO INFORM ILLEGAL MEM ACCESS
            if (ubpf_register(vmc->vm, 0x3F, base_api_fun__[i].name, api_fun) == -1) return 0;
        } else {
            if (!safe_ubpf_register(vmc, base_api_fun__[i].name, api_fun,
                                    base_api_fun__[i].attributes))
                goto err;
        }
    }


    return 1;
    err:
    remove_closures(vmc);
    return 0;
}


static int inject_code_ptr(vm_container_t *vmc, const uint8_t *data, size_t len) {

    int elf, err;
    char *errmsg;
    uint32_t ok_len;
    uintptr_t start_mem;
    uintptr_t ctx_id;
    ubpf_jit_fn fn;
    int call_next_rewrite;

    if (!data) return 0;

    elf = len >= SELFMAG && !memcmp(data, ELFMAG, SELFMAG);

    if (len >= UINT32_MAX - 1) {
        fprintf(stderr, "Too large eBPF bytecode\n");
        return 0;
    }

    call_next_rewrite = vmc->ctx->pop->anchor == BPF_REPLACE ? 1 : 0;

    ok_len = (uint32_t) len;
    start_mem = (uintptr_t) vmc->mem;

    /* to disable the rewriting of EBPF_CALL instructions, use_libffi != 0 */
    ctx_id = vmc->use_libffi ? 0 : ((uintptr_t) vmc->ctx);

    if (elf) {
        err = ubpf_load_elf(vmc->vm, data, ok_len, &errmsg, start_mem, (uint32_t) vmc->total_mem, ctx_id,
                            call_next_rewrite, vmc->add_memcheck_inst);
    } else {
        err = ubpf_load(vmc->vm, data, ok_len, &errmsg, start_mem, (uint32_t) vmc->total_mem, ctx_id,
                        call_next_rewrite, vmc->add_memcheck_inst);
    }
    //free(loaded_code);

    if (err < 0) {
        fprintf(stderr, "%s\n", errmsg);
        free(errmsg);
        return 0;
    }

    if (vmc->jit) {
        fn = ubpf_compile(vmc->vm, &errmsg);
        if (fn == NULL) {
            fprintf(stderr, "Couldn't compile eBPF code: %s\n", errmsg);
            free(errmsg);
            return 0;
        }
        vmc->fun = fn;
    }


    free(errmsg);
    return 1;
}

static int start_vm(vm_container_t *vmc, proto_ext_fun_t *api_proto) {
    int i;
    closure_t *closure;
    proto_ext_fun_t *current_fun;
    void *api_fun;

    assert(vmc->ctx != NULL);
    if (vmc == NULL) return 0;

    // usable functions inside the virtual machine

    if (!base_register(vmc)) {
        fprintf(stderr, "Base registering functions failed\n");
        goto end;
    }

    for (i = 0; !proto_ext_func_is_null(&api_proto[i]); i++) {
        current_fun = &api_proto[i];

        if (vmc->use_libffi) {
            closure = make_closure(current_fun->closure_fn, current_fun->args_nb,
                                   current_fun->args_type, current_fun->return_type,
                                   vmc->ctx);

            if (!closure) { goto end; }

            if (add_closure(vmc, closure) != 0) { goto end; }

            api_fun = closure->fn;
        } else {
            api_fun = current_fun->fn;
        }

        if (!safe_ubpf_register(vmc, api_proto[i].name,
                                api_fun, api_proto[i].attributes)) {
            goto end;
        }
    }

    return 1;

    end:
    if (vmc->use_libffi) remove_closures(vmc);
    return 0;
}


vm_container_t *new_vm(anchor_t anchor, int seq, insertion_point_t *point, uint8_t jit,
                       const char *name, size_t name_len, plugin_t *p,
                       const void *obj_data, size_t obj_len, proto_ext_fun_t *api_proto,
                       void (*on_delete)(void *), int add_memcheck_insts, int use_libffi) {

    vm_container_t *vm;

    vm = calloc(1, sizeof(*vm) + (sizeof(char) * (name_len + 1)));
    if (!vm) return NULL;


    vm->vm = ubpf_create();
    vm->mem = p->mem.master_block;
    vm->total_mem = p->mem.len;
    vm->num_ext_fun = 0;
    vm->use_libffi = use_libffi;

    if (vm->vm == NULL) {
        fprintf(stderr, "Unable to create uBPF machine\n");
        goto fail;
    }

    vm->pop = new_insertion_point_entry(anchor, seq, point, vm);
    vm->ctx = new_context();
    vm->ctx->p = p;
    vm->ctx->pop = vm->pop;
    vm->ctx->vm = vm;
    vm->ctx->ext_api = api_proto;
    vm->ctx->insertion_point_info = get_insertion_point_info();


    vm->p = p;
    vm->jit = jit;
    vm->add_memcheck_inst = add_memcheck_insts;
    vm->on_delete = on_delete;

    vm->vm_name_len = name_len;
    strncpy(vm->vm_name, name, name_len);
    vm->vm_name[name_len] = 0;

    if (!start_vm(vm, api_proto)) goto fail;
    if (!inject_code_ptr(vm, obj_data, obj_len)) goto fail;

    return vm;

    fail:

    if (vm) shutdown_vm(vm);
    return NULL;
}


void shutdown_vm(vm_container_t *vmc) {
    if (vmc == NULL) return;
    free_context(vmc->ctx);
    free_insertion_point_entry(vmc->pop);
    ubpf_destroy(vmc->vm);
    remove_closures(vmc);
    vmc->on_delete(vmc);
    free(vmc);
}

int run_injected_code(vm_container_t *vmc, uint64_t *ret_val, exec_info_t *info) {
    uint64_t ret;
    int this_fun_ret;
    exec_info_t *in_vm_info;

    vmc->ctx->return_val = ret_val;

    in_vm_info = ctx_malloc(vmc->ctx, sizeof(*info));
    if (!in_vm_info) {
        msg_log("Unable to allocate memory in vm\n");
        return -1;
    }
    memcpy(in_vm_info, info, sizeof(*info));

    // arguments are accessed via helper functions
    if (vmc->jit) { // NON INTERPRETED MODE
        ret = vmc->fun(in_vm_info, sizeof(*in_vm_info));
    } else {
        ret = ubpf_exec(vmc->vm, in_vm_info, sizeof(*in_vm_info));
    }

    if (ret == UINT64_MAX) {
        msg_log("Bytecode %s of plugin %s crashed in %s (%s seq %d)\n",
                vmc->vm_name,
                vmc->p->name,
                vmc->pop->point->name,
                vmc->pop->anchor == BPF_REPLACE ? "replace" :
                vmc->pop->anchor == BPF_PRE ? "pre" :
                vmc->pop->anchor == BPF_POST ? "post" : "unk",
                vmc->pop->seq);
    }

    // reset --> this VM is not in use for now

    if (ret_val) {
        if (vmc->pop->anchor == BPF_REPLACE) {
            if (!vmc->ctx->return_value_set) {
                vmc->ctx->return_value_set = 1;
                *ret_val = ret;
            }
        } else {
            *ret_val = ret;
        }
    }
    // flush heap is done just before returning
    mem_reset(&vmc->p->mem.mgr_heap);

    this_fun_ret = vmc->ctx->fallback ? -1 : 0;

    if (vmc->ctx->pop->anchor == BPF_REPLACE && vmc->hh_insertion_point.prev == 0) {
        vmc->ctx->return_value_set = 0;
        vmc->ctx->fallback = 0;
    }

    if (ret == UINT64_MAX) return -1;

    return this_fun_ret;
}

int add_closure(vm_container_t *vmc, closure_t *closure) {
    struct api_functions *api_closure;
    if (!closure) return -1;

    api_closure = malloc(sizeof(*api_closure));
    if (!api_closure) return -1;

    api_closure->closure = closure;

    DL_APPEND(vmc->api_closures, api_closure);
    return 0;
}

void remove_closures(vm_container_t *vmc) {
    struct api_functions *closure, *tmp_closure;

    DL_FOREACH_SAFE(vmc->api_closures, closure, tmp_closure) {
        DL_DELETE(vmc->api_closures, closure);
        free_closure(closure->closure);
        free(closure);
    }
}
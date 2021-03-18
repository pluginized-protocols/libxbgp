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

    // DO NOT TOUCH THIS FUNCTION, NEITHER ITS ID.. USED TO INFORM ILLEGAL MEM ACCESS
    if (ubpf_register(vmc->vm, 0x3F, "membound_fail", membound_fail) == -1) return 0;
    // DO NOT TOUCH THIS FUNCTION, NEITHER ITS ID.. USED TO SWITCH TO THE NEXT PART OF THE REPLACE INSERTION POINT
    if (vmc->ctx->pop->anchor == BPF_REPLACE) {
        if (ubpf_register(vmc->vm, 0x7F, "next", next) == -1) return 0;
    }

    /* helper from various things */
    if (!safe_ubpf_register(vmc, "super_log", super_log, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "clock", bpf_clock, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "get_time", get_time, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "ebpf_print", ebpf_print, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "ebpf_memcpy", ebpf_memcpy, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "ebpf_memcmp", ebpf_memcmp, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "ebpf_bvsnprintf", ebpf_bvsnprintf, HELPER_ATTR_NONE)) return 0;

    /* memory related*/
    if (!safe_ubpf_register(vmc, "ctx_malloc", ctx_malloc, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "ctx_calloc", ctx_calloc, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "ctx_realloc", ctx_realloc, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "ctx_free", ctx_free, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "ctx_shmnew", ctx_shmnew, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "ctx_shmget", ctx_shmget, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "ctx_shmrm", ctx_shmrm, HELPER_ATTR_NONE)) return 0;

    /* manipulating IP addresses */
    if (!safe_ubpf_register(vmc, "ebpf_ntohs", super_ntohs, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "ebpf_ntohl", super_ntohl, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "ebpf_ntohll", super_ntohll, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "ebpf_htons", super_htons, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "ebpf_htonl", super_htonl, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "ebpf_htonll", super_htonll, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "ebpf_inet_ntop", ebpf_inet_ntop, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "ebpf_inet_pton", ebpf_inet_pton, HELPER_ATTR_NONE)) return 0;

    /* args related */
    if (!safe_ubpf_register(vmc, "get_arg", get_arg, HELPER_ATTR_NONE)) return 0;

    /* maths */
    if (!safe_ubpf_register(vmc, "ebpf_sqrt", ebpf_sqrt, HELPER_ATTR_NONE)) return 0;

    /* getting global info from manifest */
    if (!safe_ubpf_register(vmc, "get_extra_info_value", get_extra_info_value, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "get_extra_info_lst_idx", get_extra_info_lst_idx, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "get_extra_info_dict", get_extra_info_dict, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "get_extra_info", get_extra_info, HELPER_ATTR_NONE)) return 0;

    /* socket API, to fetch data from somewhere */
    if (!safe_ubpf_register(vmc, "sk_open", sk_open, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "sk_write", sk_write, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "sk_read", sk_read, HELPER_ATTR_NONE)) return 0;
    if (!safe_ubpf_register(vmc, "sk_close", sk_close, HELPER_ATTR_NONE)) return 0;

    return 1;
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
    ctx_id = (uintptr_t) vmc->ctx;

    if (elf) {
        err = ubpf_load_elf(vmc->vm, data, ok_len, &errmsg, start_mem, (uint32_t) vmc->total_mem, ctx_id,
                            call_next_rewrite);
    } else {
        err = ubpf_load(vmc->vm, data, ok_len, &errmsg, start_mem, (uint32_t) vmc->total_mem, ctx_id,
                        call_next_rewrite);
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

    if (vmc == NULL) return 0;

    // usable functions inside the virtual machine

    if (!base_register(vmc)) {
        fprintf(stderr, "Base registering functions failed\n");
        ubpf_destroy(vmc->vm);
        return 0;
    }

    for (i = 0; !proto_ext_func_is_null(&api_proto[i]); i++) {
        if (!safe_ubpf_register(vmc, api_proto[i].name, api_proto[i].fn, api_proto[i].attributes)) {
            ubpf_destroy(vmc->vm);
            return 0;
        }
    }

    return 1;
}


vm_container_t *new_vm(anchor_t anchor, int seq, insertion_point_t *point, uint8_t jit,
                       const char *name, size_t name_len, plugin_t *p,
                       uint8_t *obj_data, size_t obj_len, proto_ext_fun_t *api_proto,
                       void (*on_delete)(void *)) {

    vm_container_t *vm;

    vm = calloc(1, sizeof(*vm) + (sizeof(char) * (name_len + 1)));
    if (!vm) return NULL;


    vm->vm = ubpf_create();
    vm->mem = p->mem.block;
    vm->total_mem = p->mem_len;
    vm->num_ext_fun = 0;

    if (vm->vm == NULL) {
        fprintf(stderr, "Unable to create uBPF machine\n");
        return 0;
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
    vm->on_delete = on_delete;

    vm->vm_name_len = name_len;
    strncpy(vm->vm_name, name, name_len);
    vm->vm_name[name_len] = 0;

    if (!start_vm(vm, api_proto)) return 0;
    if (!inject_code_ptr(vm, obj_data, obj_len)) return 0;

    return vm;
}


void shutdown_vm(vm_container_t *vmc) {
    if (vmc == NULL) return;
    free_context(vmc->ctx);
    free_insertion_point_entry(vmc->pop);
    ubpf_destroy(vmc->vm);
    vmc->on_delete(vmc);
    free(vmc);
}

int run_injected_code(vm_container_t *vmc, uint64_t *ret_val) {

    uint64_t ret;
    int this_fun_ret;

    vmc->ctx->return_val = ret_val;

    // arguments are accessed via helper functions
    if (vmc->jit) { // NON INTERPRETED MODE
        ret = vmc->fun(NULL, 0);
    } else {
        ret = ubpf_exec(vmc->vm, NULL, 0);
    }

    if (ret == UINT64_MAX) {
        fprintf(stderr, "Bytecode %s of plugin %s crashed in %s (%s seq %d)\n",
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
    reset_bump(&vmc->p->mem.heap.mp);

    this_fun_ret = vmc->ctx->fallback ? -1 : 0;

    if (vmc->ctx->pop->anchor == BPF_REPLACE && vmc->hh_insertion_point.prev == 0) {
        vmc->ctx->return_value_set = 0;
        vmc->ctx->fallback = 0;
    }

    if (ret == UINT64_MAX) return -1;

    return this_fun_ret;
}
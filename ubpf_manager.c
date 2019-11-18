//
// Created by thomas on 26/10/18.
//


#include "ubpf_manager.h"
#include "ubpf_api.h"
#include "ubpf/vm/inc/ubpf.h"
#include "bpf_plugin.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>
#include <time.h>
#include <ubpf_tools/include/plugin_arguments.h>
#include "ubpf_tools/ubpf_context.h"
#include "hashmap.h"
#include <pthread.h>
#include <ubpf_tools/include/ebpf_mod_struct.h>


static proto_ext_fun_t *proto_ext_fn = NULL;

static pthread_mutex_t _vm_call;
static pthread_mutex_t *vm_call = NULL;

static pthread_mutex_t _vm_args;
static pthread_mutex_t *vm_args = NULL;

static map_args_bpf_t _args_ebpf;
static map_args_bpf_t *args_ebpf = NULL;

static void *readfile(const char *path, size_t maxlen, size_t *len);

static uint16_t super_ntohs(context_t *ctx, uint16_t value) {

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (((value & 0x00FFu) << 8u) |
            ((value & 0xFF00u) >> 8u));
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return value;
#else
#    error unsupported endianness
#endif
}


static uint32_t super_ntohl(context_t *ctx, uint32_t value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (((value & 0x000000FFu) << 24u) |
            ((value & 0x0000FF00u) << 8u) |
            ((value & 0x00FF0000u) >> 8u) |
            ((value & 0xFF000000u) >> 24u));
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return value;
#else
#    error unsupported endianness
#endif
}

static uint64_t super_ntohll(context_t *ctx, uint64_t value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (
            ((u_int64_t) (super_ntohl(ctx, (int) ((value << 32u) >> 32u))) << 32u) |
            (unsigned int) super_ntohl(ctx, ((int) (value >> 32u)))
    );
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return value;
#else
#    error unsupported endianness
#endif
}

int safe_ubpf_register(vm_container_t *vmc, const char *name, void *fn) {

    if (vmc->num_ext_fun >= 128) {
        fprintf(stderr, "Number of external functions overflows\n");
        return 0;
    }

    if (vmc->num_ext_fun == 0x3F) vmc->num_ext_fun++; // skip because the ID is already taken for OOB call
    if (ubpf_register(vmc->vm, vmc->num_ext_fun++, name, fn) == -1) return 0;

    return 1;
}


static inline int base_register(vm_container_t *vmc) {

    // DO NOT TOUCH THIS FUNCTION, NEITHER ITS ID.. USED TO INFORM ILLEGAL MEM ACCESS
    if (ubpf_register(vmc->vm, 0x3F, "membound_fail", membound_fail) == -1) return 0;

    /* helper from various things */
    if (!safe_ubpf_register(vmc, "send_to_monitor", send_to_monitor)) return 0;
    if (!safe_ubpf_register(vmc, "clock", bpf_clock)) return 0;
    if (!safe_ubpf_register(vmc, "get_time", get_time)) return 0;
    if (!safe_ubpf_register(vmc, "ebpf_print", ebpf_print)) return 0;
    if (!safe_ubpf_register(vmc, "ebpf_memcpy", ebpf_memcpy)) return 0;
    if (!safe_ubpf_register(vmc, "set_error", set_error)) return 0;

    /* memory related*/
    if (!safe_ubpf_register(vmc, "ctx_malloc", ctx_malloc)) return 0;
    if (!safe_ubpf_register(vmc, "ctx_calloc", ctx_calloc)) return 0;
    if (!safe_ubpf_register(vmc, "ctx_realloc", ctx_realloc)) return 0;
    if (!safe_ubpf_register(vmc, "ctx_free", ctx_free)) return 0;
    if (!safe_ubpf_register(vmc, "ctx_shmnew", ctx_shmnew)) return 0;
    if (!safe_ubpf_register(vmc, "ctx_shmget", ctx_shmget)) return 0;
    if (!safe_ubpf_register(vmc, "ctx_shmrm", ctx_shmrm)) return 0;

    /* manipulating IP addresses */
    if (!safe_ubpf_register(vmc, "ebpf_ntohs", super_ntohs)) return 0;
    if (!safe_ubpf_register(vmc, "ebpf_ntohl", super_ntohl)) return 0;
    if (!safe_ubpf_register(vmc, "ebpf_ntohll", super_ntohll)) return 0;
    if (!safe_ubpf_register(vmc, "sockunion_cmp", bpf_sockunion_cmp)) return 0;

    /* custom msg send */
    if (!safe_ubpf_register(vmc, "send_ipc_msg", send_ipc_msg)) return 0;

    /* args related */
    if (!safe_ubpf_register(vmc, "bpf_get_args", bpf_get_args)) return 0;

    return 1;
}

context_t *get_curr_context() {
    return NULL;
}

int init_ubpf_manager(proto_ext_fun_t *fn) {

    proto_ext_fn = fn;

    if (!vm_call) {
        if (pthread_mutex_init(&_vm_call, NULL) != 0) {
            perror("Can't init mutex");
            return -1;
        }
        vm_call = &_vm_call;
    }

    if (!vm_args) {
        if (pthread_mutex_init(&_vm_args, NULL) != 0) {
            pthread_mutex_destroy(vm_call);
            perror("Can't init mutex");
            return -1;
        }
        vm_args = &_vm_args;
    }

    return 0;
}

int vm_init(vm_container_t **vmc, context_t *ctx, uint8_t *args_mem, const char *name, size_t len,
            size_t tot_extra, uint8_t jit) {
    *vmc = malloc(sizeof(vm_container_t));

    if (*vmc == NULL) {
        perror("Unable to allocate memory for uBPF machine");
        return 0;
    }

    (*vmc)->vm = ubpf_create();
    (*vmc)->args = args_mem;
    (*vmc)->num_ext_fun = 0;

    if ((*vmc)->vm == NULL) {
        fprintf(stderr, "Unable to create uBPF machine\n");
        return 0;
    }

    if (ctx) {
        if (tot_extra >= UINT32_MAX - 1) return 0; // heap too large exception
        (*vmc)->ctx = ctx;
    } else {
        return 0; // every plugin must have a context
    }
    memset((*vmc)->name, 0, 21);

    if (len <= 20) {
        memcpy((*vmc)->name, name, len);
        (*vmc)->name[20] = 0;
    }

    (*vmc)->total_mem = tot_extra;
    (*vmc)->jit = jit;
    (*vmc)->ctx_specific = NULL;

    return 1;
}


int start_vm(vm_container_t *vmc) {

    int i;

    if (vmc == NULL) return 0;

    // usable functions inside the virtual machine

    if (!base_register(vmc)) {
        fprintf(stderr, "Base registering functions failed\n");
        ubpf_destroy(vmc->vm);
        return 0;
    }

    for (i = 0; proto_ext_fn[i].fn != NULL && proto_ext_fn[i].name != NULL; i++) {
        if (!safe_ubpf_register(vmc, proto_ext_fn[i].name, proto_ext_fn[i].fn)) {
            ubpf_destroy(vmc->vm);
            return 0;
        }
    }

    return 1;
}

void shutdown_vm(vm_container_t *vmc) {

    if (vmc == NULL) return;

    ubpf_destroy(vmc->vm);
    unregister_context(vmc->ctx);
    free(vmc->ctx);
    free(vmc);
}

int inject_code_ptr(vm_container_t *vmc, const uint8_t *data, size_t len) {

    int elf, err;
    char *errmsg;
    uint32_t ok_len;
    uintptr_t start_mem;
    uintptr_t ctx_id;
    ubpf_jit_fn fn;

    if (!data) return 0;

    elf = len >= SELFMAG && !memcmp(data, ELFMAG, SELFMAG);

    if (len >= UINT32_MAX - 1) {
        fprintf(stderr, "Too large eBPF bytecode\n");
        return 0;
    }

    ok_len = (uint32_t) len;
    start_mem = (uintptr_t) vmc->args;
    ctx_id = (uintptr_t) vmc->ctx;

    if (elf) {
        err = ubpf_load_elf(vmc->vm, data, ok_len, &errmsg, start_mem, (uint32_t) vmc->total_mem, ctx_id);
    } else {
        err = ubpf_load(vmc->vm, data, ok_len, &errmsg, start_mem, (uint32_t) vmc->total_mem, ctx_id);
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

int inject_code(vm_container_t *vmc, const char *path_code) { // TODO useless function --> delete

    assert(0 && "Obsolete function");

    size_t code_len = 0;
    void *loaded_code;

    loaded_code = readfile(path_code, 1024 * 1024, &code_len);

    if (!inject_code_ptr(vmc, loaded_code, code_len)) return 0;

    free(loaded_code);
    return 1;
}

bpf_full_args_t *new_argument(bpf_args_t *args, int plugin_id, int nargs, bpf_full_args_t *fargs) {

    assert(fargs != NULL);

    fargs->args = args;
    fargs->plugin_type = plugin_id;
    fargs->nargs = nargs;

    if (pthread_mutex_lock(vm_args) != 0) {
        perror("Mutex lock error");
        exit(EXIT_FAILURE);
    }

    if (args_ebpf == NULL) {
        if (hashmap_new(&_args_ebpf, HASHMAP_INIT_SIZE) != 0) exit(EXIT_FAILURE);
        args_ebpf = &_args_ebpf;
    }

    if (hashmap_put(args_ebpf, (uint64_t) fargs, fargs) != 0) {
        return NULL;
    }

    if (pthread_mutex_unlock(vm_args) != 0) {
        perror("Mutex unlock error");
        exit(EXIT_FAILURE);
    }

    return fargs;
}

int unset_args(bpf_full_args_t *args) {
    if (args_ebpf == NULL) return -1;

    if (pthread_mutex_lock(vm_args) != 0) {
        perror("Mutex lock error");
        exit(EXIT_FAILURE);
    }

    hashmap_delete(args_ebpf, (uint64_t) args);

    if (pthread_mutex_unlock(vm_args) != 0) {
        perror("Mutex unlock error");
        exit(EXIT_FAILURE);
    }

    return 0;
}

bpf_args_t *get_args(bpf_full_args_t *args) {

    bpf_full_args_t *fa;

    if (!(fa = valid_args(args))) return NULL;
    return fa->args;
}

bpf_full_args_t *valid_args(bpf_full_args_t *args) {

    bpf_full_args_t **fa = hashmap_get(args_ebpf, (uint64_t) args);

    return fa != NULL ? *fa : NULL;

}

int run_injected_code(vm_container_t *vmc, void *mem, size_t mem_len, unsigned int id_args, uint64_t *ret_val) {

    uint64_t ret;

    if (!(id_args > 0 && id_args < ARGS_ID_KNOWN_MAX)) return -1; // bad ID

    vmc->ctx->args_type = id_args;
    vmc->ctx->args = mem; // bpf_full_args pointer

    if (vmc->jit) { // NON INTERPRETED MODE
        ret = vmc->fun(mem, mem_len);
    } else {
        ret = ubpf_exec(vmc->vm, mem, mem_len);
    }

    if (vmc->ctx->error_status) {
        // fprintf(stderr, "Virtual error : %s\n", vmc->ctx->error);
        vmc->ctx->error_status = 0; // reset error
    }

    if (ret == UINT64_MAX) {
        fprintf(stderr, "Plugin crashed (%s)\n", vmc->name);
    }

    // reset --> this VM is not in use for now
    vmc->ctx->args = NULL;
    vmc->ctx->args_type = 0;

    if (ret_val) *ret_val = ret;
    // flush heap is done just before returning
    reset_bump(&vmc->ctx->p->mem.heap.mp);
    return 0;
}

void *readfileOwnPtr(const char *path, size_t maxlen, size_t *len, uint8_t *data) {

    FILE *file;
    if (!strcmp(path, "-")) {
        file = fdopen(STDIN_FILENO, "r");
    } else {
        file = fopen(path, "r");
    }

    if (file == NULL) {
        fprintf(stderr, "Failed to open %s: %s (uid %u)\n", path, strerror(errno), getuid());
        return NULL;
    }

    if (!data) {
        data = calloc(maxlen, 1);
        if (!data) {
            perror("mem alloc failed");
            return NULL;
        }
    } else {
        memset(data, 0, maxlen);
    }

    size_t offset = 0;
    size_t rv;
    while ((rv = fread(data + offset, 1, maxlen - offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
        fclose(file);
        free(data);
        return NULL;
    }

    if (!feof(file)) {
        fprintf(stderr, "Failed to read %s because it is too large (max %u bytes)\n",
                path, (unsigned) maxlen);
        fclose(file);
        free(data);
        return NULL;
    }

    fclose(file);
    if (len) {
        *len = offset;
    }
    return data;

}

static void *readfile(const char *path, size_t maxlen, size_t *len) {
    return readfileOwnPtr(path, maxlen, len, NULL);
}
//
// Created by thomas on 11/01/22.
//

#include "context_function.h"

int ffi_closure_support() {
    return FFI_CLOSURES;
}

struct ubpf_closure *make_closure(api_function *fn, int args_nb,
                                  ffi_type **args_type, ffi_type *return_type,
                                  void *exec_context) {
    int i;
    struct ubpf_closure *closure = NULL;
    ffi_closure *closure_ = NULL;
    void *code;

    if (args_nb > 0 && args_type == NULL) {
        fprintf(stderr, "In function: %s, args_type should not be NULL if args_nb > 0\n", __FUNCTION__);
        goto end;
    }

    closure = malloc(sizeof(*closure) + (args_nb * sizeof(ffi_type *)));
    if (!closure) {
        perror("Malloc");
        goto end;
    }

    closure->args_nb = args_nb;
    closure->context_vm = exec_context;
    for (i = 0; i < args_nb; i++) {
        closure->arg_type[i] = args_type[i];
    }

    closure_ = ffi_closure_alloc(sizeof(ffi_closure), &code);
    if (!closure_) {
        fprintf(stderr, "Unable to alloc FFI closure\n");
        goto end;
    }

    closure->fn = code;
    closure->closure = closure_;

    if (FFI_OK != ffi_prep_cif(&closure->cif, FFI_DEFAULT_ABI,
                               args_nb, return_type,
                               closure->arg_type)) {
        fprintf(stderr, "ffi_prep_cif failed\n");
        goto end;
    }

    if (FFI_OK != ffi_prep_closure_loc(closure_, &closure->cif,
                                       fn, exec_context,
                                       closure->fn)) {
        fprintf(stderr, "ffi_prer_closure_loc failed\n");
        goto end;
    }

    return closure;

    end:
    if (closure) free(closure);
    if (closure_) ffi_closure_free(closure_);
    return NULL;
}

void free_closure(struct ubpf_closure *closure) {
    if (!closure) return;
    ffi_closure_free(closure->closure);
    free(closure);
}
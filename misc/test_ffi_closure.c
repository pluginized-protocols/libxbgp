#include <stdio.h>
#include <ffi.h>
#include <stdlib.h>

#define UNUSED __attribute__((unused))

struct context {
    ffi_cif cif;
    ffi_closure *closure;

    double (*fn)(double);

    ffi_type *arg_type[1];

    int a;
    int *b;
    double d;
    FILE *the_file;
    const char *super_string;
};

void poly_calc(UNUSED ffi_cif *cif, void *ret, void **args, void *my_context_);

struct context *make_poly2(int a, int *b, double d, const char *prefix, FILE *file);

void destroy_context(struct context *ctx);


void poly_calc(UNUSED ffi_cif *cif, void *ret, void **args, void *my_context_) {
    double x;
    double res;
    const char *format;
    struct context *my_context = my_context_;

    x = *((double **) args)[0];

    res = (my_context->a * x * x) + (*my_context->b * x) + my_context->d;

    if (my_context->the_file) {
        format = my_context->super_string != NULL ? "%s: %f\n" : "%f\n";
        fprintf(my_context->the_file, format, my_context->super_string, res);
    }

    *(double *) ret = res;
}


/**
 *  Builds and returns a function of type f(x) = a*x^2 + b*x + d
 *  This new function f writes the result to file (if != NULL). If
 *  prefix != NULL the function first writes the prefix string and
 *  then the result.
 */
struct context *make_poly2(int a, int *b, double d, const char *prefix, FILE *file) {
    struct context *ctx;
    void *code_ptr;

    ctx = malloc(sizeof(*ctx));
    if (!ctx) {
        perror("malloc");
        goto err;
    }

    code_ptr = &ctx->fn;
    ctx->closure = ffi_closure_alloc(sizeof(ffi_closure), code_ptr);
    if (!ctx->closure) {
        fprintf(stderr, "Unable to alloc closure\n");
        goto err;
    }

    ctx->the_file = file;
    ctx->a = a;
    ctx->b = b;
    ctx->d = d;
    ctx->super_string = prefix;

    ctx->arg_type[0] = &ffi_type_double;

    if (FFI_OK != ffi_prep_cif(&(ctx->cif), FFI_DEFAULT_ABI, 1, &ffi_type_double, ctx->arg_type)) {
        fprintf(stderr, "ffi_prep_cif failed\n");
        goto err;
    }

    if (FFI_OK != ffi_prep_closure_loc(ctx->closure, &(ctx->cif), poly_calc, ctx, ctx->fn)) {
        fprintf(stderr, "ffi_prep_closure_loc failed\n");
    }

    return ctx;

    err:
    if (ctx) {
        if (ctx->closure) ffi_closure_free(ctx->closure);
        free(ctx);
    }
    return NULL;
}

void destroy_context(struct context *ctx) {
    ffi_closure_free(ctx->closure);
    free(ctx);
}


/**
 *  Simple program that makes the same behavior as :
 *
 *   def make_poly2(a, b, d):
 *       def calc(x):
 *           return (a*(x**2)) + (b*x) + d
 *       return calc
 *
 *   if __name__ == '__main__':
 *       my_closure = make_poly2(5, 3, -2.63)
 *       for i in range(0, 10):
 *           print(my_closure(i))
 *
 */
int main(void) {
    int i;
    struct context *ctx;
    int a = 5;
    int b = 3;
    double d = -2.63;

    if (!FFI_CLOSURES) {
        fprintf(stderr, "Closures are not supported on this platform. Abort\n");
        return EXIT_FAILURE;
    }

    ctx = make_poly2(a, &b, d, "Computed value", stdout);
    if (!ctx) {
        fprintf(stderr, "Unable to make poly2\n");
        return EXIT_FAILURE;
    }

    for (i = 0; i < 10; i++) {
        double v = (double) i;
        double my_res;
        my_res = ctx->fn(v);
        fprintf(stdout, "Ret val of closure %f\n", my_res);
    }

    destroy_context(ctx);
    return EXIT_SUCCESS;
}

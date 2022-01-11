//
// Created by thomas on 11/01/22.
//

#include "ffi_closure_tests.h"
#include "context_hdr.h"
#include <CUnit/CUnit.h>
#include <context_function.h>


static uint64_t my_closure_fn(context_t *ctx, int a, int b) {
    return a + b + *ctx->return_val;
}

/* checks is ctx + *a is an even number */
static int my_closure_fn_ptr(context_t *ctx, const int *a) {
    return (*ctx->return_val + *a) % 2 == 0;
}

static def_fun_api(my_closure_fn, *(int *) ARGS[0], *(int *) ARGS[1])

static def_fun_api(my_closure_fn_ptr, *(int **) ARGS[0])


static int setup(void) {
    return 0;
}

static int teardown(void) {
    return 0;
}

static void test_simple_closure(void) {
    struct ubpf_closure *my_closure;
    uint64_t fake_return_val;
    uint64_t ret_val_closure;
    fake_return_val = 999;
    context_t ctx;
    ffi_type *args_type[] = {
            &ffi_type_sint,
            &ffi_type_sint,
    };
    ctx = (context_t) {
            .return_val = &fake_return_val,
    };

    my_closure = make_closure(api_name_closure(my_closure_fn), 2,
                              args_type, &ffi_type_uint64, &ctx);

    CU_ASSERT_PTR_NOT_NULL_FATAL(my_closure);

    ret_val_closure = ((uint64_t (*)(int, int)) my_closure->fn)(47, 65);

    CU_ASSERT_EQUAL(ret_val_closure, 1111);

    free_closure(my_closure);
}

static void test_simple_closure_pointer(void) {
    unsigned int i;
    struct ubpf_closure *closure;
    uint64_t fake_return_val = 1;
    int ret_val_closure;
    context_t ctx;
    ffi_type *args_type[] = {
            &ffi_type_pointer,
    };

    struct {
        int test_val;
        int expected_res;
    } test[] = {
            {.test_val = 0, .expected_res = 0},
            {.test_val = 1, .expected_res = 1},
            {.test_val = 42, .expected_res = 0},
            {.test_val = 197, .expected_res = 1},
            {.test_val = 222, .expected_res = 0},
    };

    ctx = (context_t) {
            .return_val = &fake_return_val,
    };

    closure = make_closure(api_name_closure(my_closure_fn_ptr), 1,
                           args_type, &ffi_type_sint, &ctx);

    CU_ASSERT_PTR_NOT_NULL_FATAL(closure);

    for (i = 0; i < sizeof(test) / sizeof(test[0]); i++) {
        ret_val_closure = ((int (*)(int *)) closure->fn)(&test[i].test_val);
        CU_ASSERT_EQUAL(ret_val_closure, test[i].expected_res);
    }

    free_closure(closure);
}

CU_ErrorCode ffi_closure_tests(void) {
    CU_pSuite pSuite = NULL;

    if (!ffi_closure_support()) {
        fprintf(stderr, "FFI closures are not supported on this platform\n");
        fflush(stderr);
        abort();
    }

    pSuite = CU_add_suite("ffi_closure_tests_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "Execute Closure", test_simple_closure)) ||
        (NULL == CU_add_test(pSuite, "Execute Closure Pointer args", test_simple_closure_pointer))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}
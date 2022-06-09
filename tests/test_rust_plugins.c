//
// Created by thomas on 10/03/22.
//

#include <CUnit/CUnit.h>
#include "context_function.h"
#include "ubpf_public.h"
#include "plugins_manager.h"

#include "test_rust_plugins.h"

static char plugin_folder_path[PATH_MAX - NAME_MAX - 1];

static int my_c_fun_called = 0;
static int parameter_get_arg = 0;

static int my_c_function(context_t *ctx UNUSED, int bool) {
    my_c_fun_called = 1;
    return !bool;
}

static def_fun_api(my_c_function, int, *(int *) ARGS[0]);

static int get_arg(context_t *ctx UNUSED, int b) {
    parameter_get_arg = b;
    return b + 42;
}

static def_fun_api(get_arg, int, *(int *) ARGS[0]);


static proto_ext_fun_t funcs[] = {
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_sint
                },
                .return_type = &ffi_type_sint,
                .args_nb = 1,
                .name = "my_c_function2",
                .fn = my_c_function,
                .attributes = HELPER_ATTR_NONE,
                .closure_fn  = api_name_closure(my_c_function)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_sint
                },
                .return_type = &ffi_type_sint,
                .args_nb = 1,
                .name = "get_arg",
                .fn = get_arg,
                .attributes = HELPER_ATTR_NONE,
                .closure_fn  = api_name_closure(get_arg)
        },

        proto_ext_func_null
};


static insertion_point_info_t plugins[] = {
        insertion_point_info_null
};


static inline int setup(void) {

    return init_plugin_manager(funcs, ".", plugins, 0, NULL);
}

static inline int teardown(void) {
    ubpf_terminate();
    return 0;
}

static void test_rust_plugin_exec(void) {
    char path_pluglet[PATH_MAX];
    int status;
    insertion_point_t *point;
    uint64_t ret_val = 0;

    memset(path_pluglet, 0, sizeof(path_pluglet));
    snprintf(path_pluglet, sizeof(path_pluglet), "%s/rust_test.o", plugin_folder_path);

    status = add_extension_code("job1", 4, 0,
                                0, 1, "job_plugins", 11,
                                BPF_REPLACE, 0, 0, path_pluglet,
                                0,"job1_vm", 7, funcs,
                                0, 1, BUMP_MEM, 0);

    args_t fargs = {
            .nargs = 1,
            .args = (entry_arg_t[]) {
                    entry_arg_null
            },
    };

    CU_ASSERT_EQUAL_FATAL(status, 0)
    point = insertion_point(1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(point);

    run_replace_function(point, &fargs, &ret_val);

    CU_ASSERT_EQUAL(my_c_fun_called, 1);
    CU_ASSERT_EQUAL(parameter_get_arg, 56);
    CU_ASSERT_EQUAL(ret_val, 0);

    CU_ASSERT_EQUAL_FATAL(remove_plugin("job1"), 0);
}


CU_ErrorCode rust_plugins_tests(const char *plugin_folder) {
    CU_pSuite pSuite = NULL;
    snprintf(plugin_folder_path, sizeof(plugin_folder_path), "%s/rust_plugins", plugin_folder);

    pSuite = CU_add_suite("rust_plugins_tests_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "Execute Rust extension code", test_rust_plugin_exec))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}
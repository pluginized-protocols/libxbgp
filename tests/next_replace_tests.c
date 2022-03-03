//
// Created by thomas on 7/05/20.
//

#include "next_replace_tests.h"
#include <CUnit/Util.h>
#include <include/ubpf_public.h>
#include <limits.h>
#include <bpf_plugin.h>
#include <plugins_manager.h>
#include "context_function.h"

static char plugin_folder_path[PATH_MAX];
static int return_value = -1;

static const char *format_code_path(void) {
    size_t len;
    len = strnlen(plugin_folder_path, PATH_MAX);

    if ('/' == plugin_folder_path[len - 1]) return "%s%s";

    return "%s/%s";

}

static inline void reset_ret_val(void) {
    return_value = -1;
}

static void set_return_value(context_t *ctx __attribute__((unused)), int a) {
    return_value = a;
}

static def_fun_api_void(set_return_value, *(int *) ARGS[0])

static insertion_point_info_t insertion_points[] = {
        {.insertion_point_str = "replace_chain", .insertion_point_id = 1},
        insertion_point_info_null
};

static proto_ext_fun_t funcs[] = {
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_sint,
                },
                .return_type = &ffi_type_void,
                .args_nb = 1,
                .fn = set_return_value,
                .name = "set_return_value",
                .closure_fn = api_name_closure(set_return_value),
                .attributes = HELPER_ATTR_NONE
        },
        proto_ext_func_null,
};

static inline int arg_check(uint64_t ret) {
    return ret == EXIT_SUCCESS ? 1 : 0;
}


static int setup(void) {
    int ret, i;
    char path[PATH_MAX];

    ret = init_plugin_manager(funcs, ".", insertion_points, 0, NULL);
    if (ret != 0) return -1;

    const char *elf_files[] = {
            "replace_part_1.o", "replace_part_2.o", NULL,
    };

    for (i = 0; elf_files[i] != NULL; i++) {
        memset(path, 0, sizeof(char) * PATH_MAX);
        snprintf(path, PATH_MAX - 1, format_code_path(), plugin_folder_path, elf_files[i]);

        if (add_extension_code("gros minet", 10, 512,
                               0, 1, "replace_chain",
                               13, BPF_REPLACE, i, 0, path, 0, elf_files[i],
                               strlen(elf_files[i]), funcs, 0, 1, BUMP_MEM) != 0) {
            return -1;
        }
    }

    return 0;
}

static int teardown(void) {
    ubpf_terminate();
    return 0;
}

static void test_replace_first_no_fallback(void) {

    int my_arg = 10;
    int my_2arg = 32;
    int must_next = 0;
    int must_fallback = 0;

    entry_arg_t args[] = {
            {.arg = &my_arg, .len=sizeof(int), .kind=kind_primitive, .type = 0},
            {.arg = &my_2arg, .len=sizeof(int), .kind=kind_primitive, .type = 1},
            {.arg = &must_next, .len=sizeof(int), .kind=kind_primitive, .type = 2},
            {.arg = &must_fallback, .len=sizeof(int), .kind=kind_primitive, .type = 3},
            entry_arg_null
    };
    reset_ret_val();

    CALL_REPLACE_ONLY(1, args, arg_check, {
        fprintf(stderr, "%lu\n", VM_RETURN_VALUE);
        CU_FAIL_FATAL("The fallback code must not be executed");
    }, {
                          CU_ASSERT_EQUAL(VM_RETURN_VALUE, EXIT_SUCCESS);
                          CU_ASSERT_EQUAL(return_value, 42);
                      });
    reset_ret_val();
}

static void test_replace_second_no_fallback(void) {
    int my_arg = 10;
    int my_2arg = 32;
    int must_next = 1;
    int must_fallback = 0;

    entry_arg_t args[] = {
            {.arg = &my_arg, .len=sizeof(int), .kind=kind_primitive, .type = 0},
            {.arg = &my_2arg, .len=sizeof(int), .kind=kind_primitive, .type = 1},
            {.arg = &must_next, .len=sizeof(int), .kind=kind_primitive, .type = 2},
            {.arg = &must_fallback, .len=sizeof(int), .kind=kind_primitive, .type = 3},
            entry_arg_null
    };

    reset_ret_val();

    CALL_REPLACE_ONLY(1, args, arg_check, {
        CU_FAIL_FATAL("The fallback code must not be executed");
    }, {
                          CU_ASSERT_EQUAL(VM_RETURN_VALUE, EXIT_SUCCESS);
                          CU_ASSERT_EQUAL(return_value, 222);
                      });

    reset_ret_val();
}

static void test_replace_chain_fallback(void) {

    int my_arg = 10;
    int my_2arg = 32;
    int must_next = 1;
    int must_fallback = 1;

    entry_arg_t args[] = {
            {.arg = &my_arg, .len=sizeof(int), .kind=kind_primitive, .type = 0},
            {.arg = &my_2arg, .len=sizeof(int), .kind=kind_primitive, .type = 1},
            {.arg = &must_next, .len=sizeof(int), .kind=kind_primitive, .type = 2},
            {.arg = &must_fallback, .len=sizeof(int), .kind=kind_primitive, .type = 3},
            entry_arg_null
    };

    reset_ret_val();

    CALL_REPLACE_ONLY(1, args, arg_check, {
        // THIS CODE MUST BE EXECUTED
        CU_ASSERT_TRUE(1)
        CU_ASSERT_EQUAL(return_value, -1)

    }, {
                          // THIS CODE IS NOT ALLOWED TO BE EXECUTED !
                          CU_FAIL_FATAL("The VM must fallback to the default code")
                      });

    reset_ret_val();

}

CU_ErrorCode next_replace_tests(const char *plugin_folder) {
    // ...
    CU_pSuite pSuite = NULL;
    memset(plugin_folder_path, 0, PATH_MAX * sizeof(char));
    realpath(plugin_folder, plugin_folder_path);
    // ...
    pSuite = CU_add_suite("next_replace_tests", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL ==
         CU_add_test(pSuite, "Replace must execute the first replace part and exit", test_replace_first_no_fallback)) ||
        (NULL ==
         CU_add_test(pSuite, "Replace must execute the second part and exit", test_replace_second_no_fallback)) ||
        (NULL == CU_add_test(pSuite, "Replace must fallback to the default code", test_replace_chain_fallback))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}

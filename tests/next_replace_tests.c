//
// Created by thomas on 7/05/20.
//

#include "next_replace_tests.h"
#include <CUnit/Util.h>
#include <include/public.h>
#include <limits.h>
#include <bpf_plugin.h>

static char plugin_folder_path[PATH_MAX];
static int return_value = -1;

static const char *format_code_path() {
    size_t len;
    len = strnlen(plugin_folder_path, PATH_MAX);

    if ('/' == plugin_folder_path[len - 1]) return "%s%s";

    return "%s/%s";

}

static inline void reset_ret_val() {
    return_value = -1;
}

static void set_return_value(context_t *ctx, int a) {
    return_value = a;
}

static plugin_info_t plugins[] = {
        {.plugin_str = "replace_chain", .plugin_id = 1},
        plugin_info_null
};

static proto_ext_fun_t funcs[] = {
        {.fn = set_return_value, .name = "set_return_value"},
        {NULL},
};

static inline int arg_check(uint64_t ret) {
    return ret == EXIT_SUCCESS ? 1 : 0;
}


static int setup(void) {

    int ret, i;

    char path[PATH_MAX];

    ret = init_plugin_manager(funcs, ".", 9, plugins,
                              NULL, NULL, 0);

    if (ret != 0) return -1;

    const char *elf_files[] = {
            "replace_part_1.o", "replace_part_2.o", NULL,
    };

    for (i = 0; elf_files[i] != NULL; i++) {
        memset(path, 0, sizeof(char) * PATH_MAX);
        snprintf(path, PATH_MAX - 1, format_code_path(), plugin_folder_path, elf_files[i]);

        if (add_pluglet(path, 512, 0, 1, BPF_REPLACE, 0, 0) != 0) {
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

    bpf_args_t args[] = {
            {.arg = &my_arg, .len=sizeof(int), .kind=kind_primitive, .type = 0},
            {.arg = &my_2arg, .len=sizeof(int), .kind=kind_primitive, .type = 0},
            {.arg = &must_next, .len=sizeof(int), .kind=kind_primitive, .type = 0},
            {.arg = &must_fallback, .len=sizeof(int), .kind=kind_primitive, .type = 0},
    };

    reset_ret_val();

    CALL_REPLACE_ONLY(1, args, 4, arg_check, {
        CU_FAIL_FATAL("The fallback code must not be executed");
    }, {
                          CU_ASSERT_EQUAL(VM_RETURN_VALUE, EXIT_SUCCESS);
                          CU_ASSERT_EQUAL(return_value, 42);
                      })

    reset_ret_val();
}

static void test_replace_second_no_fallback(void) {
    int my_arg = 10;
    int my_2arg = 32;
    int must_next = 1;
    int must_fallback = 0;

    bpf_args_t args[] = {
            {.arg = &my_arg, .len=sizeof(int), .kind=kind_primitive, .type = 0},
            {.arg = &my_2arg, .len=sizeof(int), .kind=kind_primitive, .type = 0},
            {.arg = &must_next, .len=sizeof(int), .kind=kind_primitive, .type = 0},
            {.arg = &must_fallback, .len=sizeof(int), .kind=kind_primitive, .type = 0},
    };

    reset_ret_val();

    CALL_REPLACE_ONLY(1, args, 4, arg_check, {
        CU_FAIL_FATAL("The fallback code must not be executed");
    }, {
                          CU_ASSERT_EQUAL(VM_RETURN_VALUE, EXIT_SUCCESS);
                          CU_ASSERT_EQUAL(return_value, 222);
                      })

    reset_ret_val();
}

static void test_replace_chain_fallback(void) {

    int my_arg = 10;
    int my_2arg = 32;
    int must_next = 1;
    int must_fallback = 1;

    bpf_args_t args[] = {
            {.arg = &my_arg, .len=sizeof(int), .kind=kind_primitive, .type = 0},
            {.arg = &my_2arg, .len=sizeof(int), .kind=kind_primitive, .type = 0},
            {.arg = &must_next, .len=sizeof(int), .kind=kind_primitive, .type = 0},
            {.arg = &must_fallback, .len=sizeof(int), .kind=kind_primitive, .type = 0},
    };

    reset_ret_val();

    CALL_REPLACE_ONLY(1, args, 4, arg_check, {
        // THIS CODE MUST BE EXECUTED
        CU_ASSERT_TRUE(1)
        CU_ASSERT_EQUAL(return_value, -1)

    }, {
                          // THIS CODE IS NOT ALLOWED TO BE EXECUTED !
                          CU_FAIL_FATAL("The VM must fallback to the default code")
                      })

    reset_ret_val();

}

int next_replace_tests(const char *plugin_folder) {
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

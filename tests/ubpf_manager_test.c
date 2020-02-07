//
// Created by thomas on 29/11/19.
//

#include <include/ebpf_mod_struct.h>
#include <include/public.h>
#include <bpf_plugin.h>
#include <CUnit/Util.h>
#include <limits.h>
#include <include/tools_ubpf_api.h>
#include <unistd.h>

#include "ubpf_manager_test.h"

#define STRING_MAX 2048

#define XCU_ASSERT_EQUAL(actual, expected) \
  { char expl[STRING_MAX]; memset(expl, 0, STRING_MAX * sizeof(char));\
  snprintf(expl, STRING_MAX, "CU_ASSERT_EQUAL(actual %lu, expected %s)", (actual), #expected);\
  CU_assertImplementation(((actual) == (expected)), __LINE__, (expl), __FILE__, "", CU_FALSE); }


enum custom_user_type {
    INT_EXAMPLE,
};

static unsigned int plugin_set_post = -1;

char plugin_folder_path[PATH_MAX];

static inline int my_very_super_function_to_pluginize(int a, char b, uint32_t c, short d) {

    bpf_args_t args[] = {
            [0] = {.arg = &a, .len = sizeof(a), .kind = kind_primitive, .type = 0},
            [1] = {.arg = &b, .len = sizeof(b), .kind = kind_primitive, .type = 0},
            [2] = {.arg = &c, .len = sizeof(c), .kind = kind_primitive, .type = 0},
            [3] = {.arg = &d, .len = sizeof(d), .kind = kind_primitive, .type = 0},
    };

    VM_CALL(3, args, 4, {

        int temp = a * b;
        int temp2 = b + c;
        int temp4 = c % d;


        RETURN_VM_VAL(temp * temp2 * temp4)
    })
}

static inline void my_function_void(int *a) {

    bpf_args_t args[] = {
            [0] = {.arg = a, .len = sizeof(int), .kind = kind_ptr, .type = INT_EXAMPLE},
    };


    VM_CALL_VOID(1, args, 1, {
        *a = 42;
    })
}


int add_two(context_t *ctx, int a) {
    ((void) ctx); // trick to avoid generating useless compilation warnings
    return a + 2;
}

static int set_int_example(api_args, int new_int_val) {

    int *int_from_args = auto_get(INT_EXAMPLE, int *);
    if (!int_from_args) return -1;

    *int_from_args = new_int_val;
    return 0;
}

static void post_function_call(context_t *ctx) {
    plugin_set_post = ctx->p->plugin_id;
}


static proto_ext_fun_t funcs[] = {
        {.name = "add_two", .fn = add_two},
        {.name = "set_int_example", .fn = set_int_example},
        {.name = "post_function_call", .fn = post_function_call},
        {NULL}
};

static plugin_info_t plugins[] = {
        {.plugin_str = "add_two_insert", .plugin_id = 1},
        {.plugin_str = "full_plugin", .plugin_id = 2},
        {.plugin_str = "macro_test", .plugin_id = 3},
        plugin_info_null
};

static int setup(void) {

    return init_plugin_manager(funcs, ".", 9, plugins,
                               NULL, NULL, 0);

}

static int teardown(void) {
    ubpf_terminate();
    return 0;
}

void test_file_id_exist(void) {

    CU_ASSERT_EQUAL(access("./queue.id", F_OK), 0)
    CU_ASSERT_EQUAL(access("./shared.id", F_OK), 0)
}

void test_add_plugin(void) {

    int status;
    int super_arg = 40;
    uint64_t ret_val;

    char path_pluglet[PATH_MAX];
    memset(path_pluglet, 0, PATH_MAX * sizeof(char));
    snprintf(path_pluglet, PATH_MAX, "%s/%s", plugin_folder_path, "simple_test_api.o");


    bpf_args_t args[1] = {
            {.arg = &super_arg, .len = sizeof(int), .kind = kind_primitive, .type = 0}
    };

    bpf_full_args_t fargs;
    new_argument(args, 1, 1, &fargs);

    status = add_pluglet(path_pluglet, 8,
                         0, 1, BPF_REPLACE, 0, 0);

    CU_ASSERT_EQUAL(status, 0);
    run_plugin_replace(1, &fargs, sizeof(bpf_full_args_t *), &ret_val);
    CU_ASSERT_EQUAL(ret_val, 42);
    unset_args(&fargs);

    rm_plugin(1, NULL);
}

void test_read_json_add_plugins(void) {

    int super_arg = 12;
    uint64_t ret_val = 0;

    bpf_args_t args[1] = {
            {.arg = &super_arg, .len = sizeof(int), .kind = kind_primitive, .type = 0}
    };

    char path_json[PATH_MAX];
    snprintf(path_json, PATH_MAX, "%s/plugins.json", plugin_folder_path);
    int status;

    status = load_plugin_from_json(path_json, plugin_folder_path, strnlen(plugin_folder_path, PATH_MAX));
    CU_ASSERT_EQUAL(status, 0);

    bpf_full_args_t fargs, fargs_0;
    new_argument(args, 1, 1, &fargs);
    new_argument(args, 2, 1, &fargs_0);

    run_plugin_replace(1, &fargs_0, sizeof(bpf_full_args_t *), &ret_val);
    XCU_ASSERT_EQUAL(ret_val, 14)
    unset_args(&fargs_0);


    run_plugin_pre(2, &fargs, sizeof(bpf_full_args_t *), &ret_val);
    XCU_ASSERT_EQUAL(ret_val, 22)
    run_plugin_replace(2, &fargs, sizeof(bpf_full_args_t *), &ret_val);
    XCU_ASSERT_EQUAL(ret_val, 32)
    run_plugin_post(2, &fargs, sizeof(bpf_full_args_t *), &ret_val);
    XCU_ASSERT_EQUAL(ret_val, 42)

    unset_args(&fargs);

    rm_plugin(1, NULL);
    rm_plugin(2, NULL);
}

static void test_macro_function(void) {

    int return_value, status;

    char path_pluglet[PATH_MAX];
    memset(path_pluglet, 0, PATH_MAX * sizeof(char));
    snprintf(path_pluglet, PATH_MAX, "%s/%s", plugin_folder_path, "replace_fun_macro.o");

    return_value = my_very_super_function_to_pluginize(1, 2, 3, 4);
    CU_ASSERT_EQUAL(return_value, 30);

    status = add_pluglet(path_pluglet, 64,
                         0, 3, BPF_REPLACE, 0, 0);

    CU_ASSERT_EQUAL(status, 0)
    return_value = my_very_super_function_to_pluginize(1, 2, 3, 4);
    CU_ASSERT_EQUAL(return_value, 10) // plugin should only make a sum (instead of weird computation)

    rm_plugin(3, NULL);
}

static void macro_void_example_with_set(void) {

    int status;
    char path_pluglet[PATH_MAX];
    int my_arg_to_be_modified = 2142;

    memset(path_pluglet, 0, PATH_MAX * sizeof(char));
    snprintf(path_pluglet, PATH_MAX, "%s/%s", plugin_folder_path, "macro_void_test.o");

    my_function_void(&my_arg_to_be_modified);
    CU_ASSERT_EQUAL(my_arg_to_be_modified, 42);

    // reset arg;
    my_arg_to_be_modified = 2142;

    status = add_pluglet(path_pluglet, 64, 0, 1,
                         BPF_REPLACE, 0, 0);
    CU_ASSERT_EQUAL(status, 0);

    memset(path_pluglet, 0, PATH_MAX * sizeof(char));
    snprintf(path_pluglet, PATH_MAX, "%s/%s", plugin_folder_path, "macro_void_test_post.o");

    status = add_pluglet(path_pluglet, 64, 0,
                         1, BPF_POST, 0, 0);
    CU_ASSERT_EQUAL(status, 0);

    my_function_void(&my_arg_to_be_modified);
    CU_ASSERT_EQUAL(my_arg_to_be_modified, 2150);

    // only way to check if 1) the post pluglet is executed
    //                      2) the set function is applied on the real argument
    //                         and not the one copied into the VM memory
    CU_ASSERT_EQUAL(plugin_set_post, 1);

    rm_plugin(1, NULL);
}

int ubpf_manager_tests(const char *plugin_folder) {
    // ...
    CU_pSuite pSuite = NULL;
    memset(plugin_folder_path, 0, PATH_MAX * sizeof(char));
    realpath(plugin_folder, plugin_folder_path);
    // ...
    pSuite = CU_add_suite("ubpf_manager_test_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "Files ID to communicate with the library", test_file_id_exist)) ||
        (NULL == CU_add_test(pSuite, "Adding plugin and execute it", test_add_plugin)) ||
        (NULL == CU_add_test(pSuite, "Reading json plugin and execute it", test_read_json_add_plugins)) ||
        (NULL == CU_add_test(pSuite, "\"Pluginize\" function with macro", test_macro_function)) ||
        (NULL == CU_add_test(pSuite, "Setter and void function macro", macro_void_example_with_set))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}
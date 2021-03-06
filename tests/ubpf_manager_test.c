//
// Created by thomas on 29/11/19.
//

#include <include/ebpf_mod_struct.h>
#include <include/ubpf_public.h>
#include <bpf_plugin.h>
#include <CUnit/Util.h>
#include <limits.h>
#include <include/tools_ubpf_api.h>
#include <unistd.h>
#include <plugins_manager.h>

#include "ubpf_manager_test.h"
#include "ubpf_context.h"

#define STRING_MAX 2048

#define XCU_ASSERT_EQUAL(actual, expected) \
  { char expl[STRING_MAX]; memset(expl, 0, STRING_MAX * sizeof(char)); uint64_t actu=actual;\
  snprintf(expl, STRING_MAX, "CU_ASSERT_EQUAL(actual %lu, expected %s)", (actu), #expected);\
  CU_assertImplementation(((actual) == (expected)), __LINE__, (expl), __FILE__, "", CU_FALSE); }


enum custom_user_type {
    INT_EXAMPLE = 0,
};

static int plugin_set_post = 0;

static char plugin_folder_path[PATH_MAX - NAME_MAX - 1];

static inline int check(uint64_t l UNUSED) {
    return 1;
}

static inline int my_very_super_function_to_pluginize(int a, char b, uint32_t c, short d) {

    entry_args_t args[] = {
            [0] = {.arg = &a, .len = sizeof(a), .kind = kind_primitive, .type = 32},
            [1] = {.arg = &b, .len = sizeof(b), .kind = kind_primitive, .type = 33},
            [2] = {.arg = &c, .len = sizeof(c), .kind = kind_primitive, .type = 34},
            [3] = {.arg = &d, .len = sizeof(d), .kind = kind_primitive, .type = 35},
            entry_arg_null
    };

    CALL_ALL(3, args, check, 1, {

        int temp = a * b;
        int temp2 = b + c;
        int temp4 = c % d;

        RETURN(temp * temp2 * temp4);
    }, {
                 RETURN(VM_RETURN_VALUE);
             })
}

static inline void my_function_void(int *a) {
    entry_args_t args[] = {
            [0] = {.arg = a, .len = sizeof(int), .kind = kind_ptr, .type = INT_EXAMPLE},
            [1] = entry_arg_null,
    };
    CALL_ALL_VOID(1, args, check, {
        *a = 42;
    })
}


int add_two(context_t *ctx UNUSED, int a) {
    return a + 2;
}

static int set_int_example(context_t *ctx, int type_arg, int new_int_val) {
    int *int_from_args = get_arg_from_type(ctx, type_arg);
    if (!int_from_args) return -1;

    *int_from_args = new_int_val;
    return 0;
}

static void post_function_call(context_t *ctx) {
    plugin_set_post = ctx->pop->point->id;
}


static proto_ext_fun_t funcs[] = {
        {.name = "add_two", .fn = add_two, .attributes = HELPER_ATTR_NONE},
        {.name = "set_int_example", .fn = set_int_example, .attributes = HELPER_ATTR_NONE},
        {.name = "post_function_call", .fn = post_function_call, .attributes = HELPER_ATTR_NONE},
        proto_ext_func_null
};

static insertion_point_info_t plugins[] = {
        {.insertion_point_str = "add_two_insert_ip", .insertion_point_id = 1},
        {.insertion_point_str = "full_plugin_ip", .insertion_point_id = 2},
        {.insertion_point_str = "macro_test", .insertion_point_id = 3},
        insertion_point_info_null
};

static int setup(void) {

    return init_plugin_manager(funcs, ".", plugins, 0, NULL);

}

static int teardown(void) {
    ubpf_terminate();
    return 0;
}

void test_add_plugin(void) {

    int status;
    insertion_point_t *point;
    int super_arg = 40;
    uint64_t ret_val;

    char path_pluglet[PATH_MAX];
    memset(path_pluglet, 0, PATH_MAX * sizeof(char));
    snprintf(path_pluglet, PATH_MAX - 19, "%s/%s", plugin_folder_path, "simple_test_api.o");

    entry_args_t args[2] = {
            {.arg = &super_arg, .len = sizeof(int), .kind = kind_primitive, .type = 42},
            entry_arg_null
    };

    args_t fargs;
    fargs.nargs = 1;
    fargs.args = args;

    status = add_extension_code("add_two_insert", 14, 8,
                                0, 1, "add_two_insert_ip", 17,
                                BPF_REPLACE, 0, 0, path_pluglet, 0,
                                "simple_test_api", 15, funcs, 0, 1);

    CU_ASSERT_EQUAL(status, 0);
    point = insertion_point(1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(point);

    run_replace_function(point, &fargs, &ret_val);
    CU_ASSERT_EQUAL(ret_val, 42);

    // remove VM
    CU_ASSERT_EQUAL(remove_extension_code("simple_test_api"), 0);
}

static void test_read_json_add_plugins(void) {

    int super_arg = 12;
    uint64_t ret_val = 0;
    insertion_point_t *point2;
    insertion_point_t *point1;

    entry_args_t args[2] = {
            {.arg = &super_arg, .len = sizeof(int), .kind = kind_primitive, .type = 42},
            entry_arg_null
    };

    char path_json[PATH_MAX];
    snprintf(path_json, PATH_MAX - 14, "%s/plugins.json", plugin_folder_path);
    int status;

    status = load_extension_code(path_json, plugin_folder_path, funcs, plugins);
    CU_ASSERT_EQUAL_FATAL(status, 0);

    args_t fargs;

    fargs.nargs = 1;
    fargs.args = args;

    point1 = insertion_point(1);
    point2 = insertion_point(2);

    run_replace_function(point1, &fargs, &ret_val);
    XCU_ASSERT_EQUAL(ret_val, 14)

    run_pre_functions(point2, &fargs, &ret_val);
    XCU_ASSERT_EQUAL(ret_val, 22)
    run_replace_function(point2, &fargs, &ret_val);
    XCU_ASSERT_EQUAL(ret_val, 32)
    run_post_functions(point2, &fargs, &ret_val);
    XCU_ASSERT_EQUAL(ret_val, 42)


    remove_plugin("add_two_insert");
    remove_plugin("full_plugin");
}

static void test_macro_function(void) {

    int return_value, status;

    char path_pluglet[PATH_MAX];
    memset(path_pluglet, 0, PATH_MAX * sizeof(char));
    snprintf(path_pluglet, PATH_MAX - 20, "%s/%s", plugin_folder_path, "replace_fun_macro.o");

    // should not execute any plugins
    return_value = my_very_super_function_to_pluginize(1, 2, 3, 4);
    CU_ASSERT_EQUAL(return_value, 30);

    status = add_extension_code("my_plugin", 9, 64,
                                0, 3, "macro_test", 10,
                                BPF_REPLACE, 0, 0, path_pluglet, 0,
                                "fun_vm", 6, funcs, 0, 1);

    CU_ASSERT_EQUAL(status, 0)
    return_value = my_very_super_function_to_pluginize(1, 2, 3, 4);
    XCU_ASSERT_EQUAL(return_value, 10) // plugin should only make a sum (instead of weird computation)

    CU_ASSERT_EQUAL(remove_plugin("my_plugin"), 0);
}

static void macro_void_example_with_set(void) {

    int status;
    char path_pluglet[PATH_MAX];
    int my_arg_to_be_modified = 2142;

    memset(path_pluglet, 0, PATH_MAX * sizeof(char));
    snprintf(path_pluglet, PATH_MAX - 23, "%s/%s", plugin_folder_path, "macro_void_test.o");

    my_function_void(&my_arg_to_be_modified);
    XCU_ASSERT_EQUAL(my_arg_to_be_modified, 42);

    // reset arg;
    my_arg_to_be_modified = 2142;

    status = add_extension_code("my_plugin", 9, 64,
                                0, 1, "add_two_insert_ip",
                                17, BPF_REPLACE, 0, 0, path_pluglet, 0,
                                "super_vm", 8, funcs, 0, 1);
    CU_ASSERT_EQUAL(status, 0);

    memset(path_pluglet, 0, PATH_MAX * sizeof(char));
    snprintf(path_pluglet, PATH_MAX - 25, "%s/%s", plugin_folder_path, "macro_void_test_post.o");

    status = add_extension_code("my_plugin", 9, 64,
                                0, 1, "add_two_insert_ip",
                                6, BPF_POST, 0, 0, path_pluglet, 0,
                                "super_vm_post", 13, funcs, 0, 1);
    CU_ASSERT_EQUAL(status, 0);

    my_function_void(&my_arg_to_be_modified);
    CU_ASSERT_EQUAL(my_arg_to_be_modified, 2150);

    // only way to check if 1) the post pluglet is executed
    //                      2) the set function is applied on the real argument
    //                         and not the one copied into the VM memory
    CU_ASSERT_EQUAL(plugin_set_post, 1);

    CU_ASSERT_EQUAL(remove_plugin("my_plugin"), 0);
}

CU_ErrorCode ubpf_manager_tests(const char *plugin_folder) {
    // ...
    CU_pSuite pSuite = NULL;
    memset(plugin_folder_path, 0, sizeof(plugin_folder_path));
    realpath(plugin_folder, plugin_folder_path);
    // ...
    pSuite = CU_add_suite("ubpf_manager_test_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "Adding plugin and execute it", test_add_plugin)) ||
        (NULL == CU_add_test(pSuite, "Reading json plugin and execute it", test_read_json_add_plugins)) ||
        (NULL == CU_add_test(pSuite, "\"Pluginize\" function with macro", test_macro_function)) ||
        (NULL == CU_add_test(pSuite, "Setter and void function macro", macro_void_example_with_set))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}
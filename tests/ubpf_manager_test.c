//
// Created by thomas on 29/11/19.
//

#include <include/ebpf_mod_struct.h>
#include <include/public.h>
#include <bpf_plugin.h>
#include <CUnit/Util.h>
#include <limits.h>


#include "ubpf_manager_test.h"

char plugin_folder_path[PATH_MAX];

int add_two(context_t *ctx, int a) {
    ((void) ctx); // trick to avoid generating useless compilation warnings
    return a + 2;
}


proto_ext_fun_t funcs[] = {
        {.name = "add_two", .fn = add_two},
        {NULL}
};

plugin_info_t plugins[] = {
        {.plugin_str = "add_two_insert", .plugin_id = 1},
        {.plugin_str = "full_plugin", .plugin_id = 2},
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

    status = add_pluglet(path_pluglet, 4,
                         0, 1, BPF_REPLACE, 0, 0);

    CU_ASSERT_EQUAL(status, 0);
    run_plugin_replace(1, &fargs, sizeof(bpf_full_args_t *), &ret_val);
    CU_ASSERT_EQUAL(ret_val, 42);
    unset_args(&fargs);

    rm_plugin(1, NULL);
}

void test_read_json_add_plugins(void) {

    int super_arg = 12;
    uint64_t ret_val;

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
    CU_ASSERT_EQUAL(ret_val, 14);
    unset_args(&fargs_0);


    run_plugin_pre(2, &fargs, sizeof(bpf_full_args_t *), &ret_val);
    CU_ASSERT_EQUAL(ret_val, 22)
    run_plugin_replace(2, &fargs, sizeof(bpf_full_args_t *), &ret_val);
    CU_ASSERT_EQUAL(ret_val, 32)
    run_plugin_post(2, &fargs, sizeof(bpf_full_args_t *), &ret_val);
    CU_ASSERT_EQUAL(ret_val, 42)

    unset_args(&fargs);

    rm_plugin(1, NULL);
    rm_plugin(2, NULL);
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

    if ((NULL == CU_add_test(pSuite, "Test adding plugin and execute it", test_add_plugin)) ||
        (NULL == CU_add_test(pSuite, "Test reading json plugin and execute it", test_read_json_add_plugins))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}
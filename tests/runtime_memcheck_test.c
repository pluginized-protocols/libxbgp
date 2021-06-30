//
// Created by thomas on 29/04/21.
//

#include "runtime_memcheck_test.h"
#include <stdlib.h>
#include <CUnit/CUnit.h>
#include <limits.h>
#include <include/ubpf_public.h>
#include <plugins_manager.h>
#include <include/ebpf_mod_struct.h>

#define MAGIC 0xcafebabe
#define BASE_FOLDER "memcheck_runtime"

static char plugin_folder_path[PATH_MAX - 2 * NAME_MAX]; // Mystic length to avoid compiler warnings....

static proto_ext_fun_t funcs[] = {
        proto_ext_func_null
};

static insertion_point_info_t plugins[] = {
        {.insertion_point_str = "insertion_1", .insertion_point_id = 1},
        {.insertion_point_str = "insertion_2", .insertion_point_id = 2},
        insertion_point_info_null
};


static int setup(void) {
    return init_plugin_manager(funcs, ".", plugins, 0, NULL);
}

static int teardown(void) {
    ubpf_terminate();
    return 0;
}

#define TEMPLATE_TEST_CODE(extension_code_name, runtime_memcheck, invalid_rw)                                   \
do {                                                                                                            \
    int  status;                                                                                                \
    uint64_t ret_val;                                                                                           \
    insertion_point_t *point;                                                                                   \
    char path_pluglet[PATH_MAX];                                                                                \
    int *super_malloc = malloc(sizeof(int));                                                                    \
    if (!super_malloc)   {                                                                                      \
        CU_FAIL_FATAL("Unable to retrieve memory");                                                             \
        return;                                                                                                 \
    }                                                                                                           \
    *super_malloc = MAGIC;                                                                                      \
    memset(path_pluglet, 0, sizeof(path_pluglet));                                                              \
    snprintf(path_pluglet, sizeof(path_pluglet), "%s/%s", plugin_folder_path, extension_code_name);             \
                                                                                                                \
    entry_args_t args[] = {                                                                                     \
            {.arg = &super_malloc, .len = sizeof(void *), .kind = kind_primitive, .type = 42},                  \
            entry_arg_null                                                                                      \
    };                                                                                                          \
                                                                                                                \
    args_t fargs;                                                                                               \
    fargs.nargs = 1;                                                                                            \
    fargs.args = args;                                                                                          \
                                                                                                                \
    status = add_extension_code("plugin_1", 8, 8,                                                               \
                                0, 1, "insertion_1", 11,                                                        \
                                BPF_REPLACE, 0, 1, path_pluglet, 0,                                             \
                                "simple_test", 11, funcs, 0, runtime_memcheck);                                 \
                                                                                                                \
    CU_ASSERT_EQUAL_FATAL(status, 0);                                                                           \
    point = insertion_point(1);                                                                                 \
                                                                                                                \
    CU_ASSERT_PTR_NOT_NULL_FATAL(point);                                                                        \
                                                                                                                \
    status = run_replace_function(point, &fargs, &ret_val);                                                     \
                                                                                                                \
    if (!(invalid_rw)) {                                                                                        \
        CU_ASSERT_EQUAL(status, 0);                                                                             \
        CU_ASSERT_EQUAL(ret_val, 42);                                                                           \
        CU_ASSERT_EQUAL(*super_malloc, MAGIC);                                                                  \
    } else if (!(runtime_memcheck)) {                                                                           \
        CU_ASSERT_EQUAL(status, 0);                                                                             \
        CU_ASSERT_EQUAL(ret_val, 42);                                                                           \
        CU_ASSERT_NOT_EQUAL(*super_malloc, MAGIC);                                                              \
    } else {                                                                                                    \
        CU_ASSERT_EQUAL(status, -1);                                                                            \
        CU_ASSERT_EQUAL(*super_malloc, MAGIC);                                                                  \
    }                                                                                                           \
                                                                                                                \
    CU_ASSERT_EQUAL(remove_extension_code("simple_test"), 0);                                                   \
} while(0)


// no invalid read write (no memcheck)
static void no_invalid_rw_no_memcheck(void) {
    TEMPLATE_TEST_CODE(BASE_FOLDER"/no_invalid_rw.o", 0, 0);
}

// no invalid read write (with memcheck)
static void no_invalid_rw_with_memcheck(void) {
    TEMPLATE_TEST_CODE(BASE_FOLDER"/no_invalid_rw.o", 1, 0);
}

// invalid read write (no memcheck)
static void invalid_rw_no_memcheck(void) {
    TEMPLATE_TEST_CODE(BASE_FOLDER"/invalid_rw.o", 0, 1);
}

// invalid read write (with memcheck)
static void invalid_rw_with_memcheck(void) {
    TEMPLATE_TEST_CODE(BASE_FOLDER"/invalid_rw.o", 1, 1);
}

// manifest
static void load_with_manifest(void) {
    int status;
    char sub_dir[PATH_MAX - NAME_MAX];
    memset(sub_dir, 0, sizeof(sub_dir));

    uint64_t ret_val = 0;
    insertion_point_t *point2;
    insertion_point_t *point1;

    int *super_malloc = malloc(sizeof(int));
    if (!super_malloc) {
        CU_FAIL_FATAL("Unable to allocate memory");
        return;
    }

    *super_malloc = MAGIC;

    snprintf(sub_dir, sizeof(sub_dir), "%s/"BASE_FOLDER, plugin_folder_path);


    entry_args_t args[] = {
            {.arg = &super_malloc, .len = sizeof(void *), .kind = kind_primitive, .type = 42},
            entry_arg_null
    };

    char path_json[PATH_MAX];
    snprintf(path_json, sizeof(path_json), "%s/plugins.json", sub_dir);

    status = load_extension_code(path_json, sub_dir, funcs, plugins);
    CU_ASSERT_EQUAL_FATAL(status, 0);

    args_t fargs;

    fargs.nargs = 1;
    fargs.args = args;

    point1 = insertion_point(1); // memcheck at runtime
    point2 = insertion_point(2); // no memchecks at runtime

    status = run_replace_function(point1, &fargs, &ret_val);
    CU_ASSERT_EQUAL(status, -1); // should crash since we add memcheck
    CU_ASSERT_EQUAL(*super_malloc, MAGIC);

    // reset my super_malloc value
    *super_malloc = MAGIC;
    status = run_replace_function(point2, &fargs, &ret_val);
    CU_ASSERT_EQUAL_FATAL(status, 0);
    CU_ASSERT_NOT_EQUAL(*super_malloc, MAGIC);

    remove_plugin("plugin_1");
    remove_plugin("plugin_2");
}


CU_ErrorCode runtime_memcheck_test_suite(const char *plugin_folder) {
    // ...
    CU_pSuite pSuite = NULL;
    memset(plugin_folder_path, 0, sizeof(plugin_folder_path));
    realpath(plugin_folder, plugin_folder_path);
    // ...
    pSuite = CU_add_suite("runtime_memcheck_test_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "No invalid read/write without runtime checks", no_invalid_rw_no_memcheck)) ||
        (NULL == CU_add_test(pSuite, "No invalid read/write with runtime checks", no_invalid_rw_with_memcheck)) ||
        (NULL == CU_add_test(pSuite, "Invalid read/write without runtime checks", invalid_rw_no_memcheck)) ||
        (NULL == CU_add_test(pSuite, "Invalid read/wrtie with runtime check", invalid_rw_with_memcheck)) ||
        (NULL == CU_add_test(pSuite, "Load pluglet with manifest (with and w/o runtime checks)", load_with_manifest))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}

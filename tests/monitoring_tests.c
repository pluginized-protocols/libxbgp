//
// Created by twirtgen on 7/01/20.
//

#include "monitoring_tests.h"


#include <include/ubpf_public.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <bpf_plugin.h>
#include <CUnit/CUnit.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <fcntl.h>
#include <assert.h>
#include <plugins_manager.h>

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

static char plugin_folder_path[PATH_MAX];

static proto_ext_fun_t funcs[] = {};

static insertion_point_info_t plugins[] = {
        {.insertion_point_str = "send_monitoring_data", .insertion_point_id = 1},
        {.insertion_point_str = "send_a_lot_of_record", .insertion_point_id = 2},
        {.insertion_point_str = "pultiple_type_record", .insertion_point_id = 3},
        insertion_point_info_null
};

static int setup(void) {

    char log_tmp_name[] = "/tmp/test_monitubfplogXXXXXX";
    log_config_t *conf = NULL;


    if (mktemp(log_tmp_name) == NULL) {
        perror("mktemp");
        return -1;
    }

    add_log_entry(&conf, log_tmp_name, MASK_ALL);

    // the logger should write to syslog, stderr and the temporary file;
    return init_plugin_manager(funcs, ".", 1, plugins, 1, conf);
}

static int teardown(void) {
    ubpf_terminate();
    return 0;
}

void send_monitoring_record_test(void) {

    uint64_t ret_val;
    int status;
    int dummy_arg = 0;
    char path_pluglet[PATH_MAX];
    args_t fargs;
    insertion_point_t *point;

    memset(path_pluglet, 0, PATH_MAX * sizeof(char));
    snprintf(path_pluglet, PATH_MAX - 24, "%s/%s", plugin_folder_path, "send_monitoring_data.o");

    entry_args_t args[] = {
            {.arg = &dummy_arg, .len = sizeof(int), .kind = kind_primitive, .type = 0},
            entry_arg_null,
    };

    status = add_extension_code("monitoring_example", 18, 64, 0, 1, "point", 5, BPF_REPLACE,
                                0, 0, path_pluglet, 0, "send_monit", 10, funcs, 0);

    fargs.args = args;
    fargs.nargs = 1;

    CU_ASSERT_EQUAL(status, 0)
    point = insertion_point(1);
    run_replace_function(point, &fargs, &ret_val);
    CU_ASSERT_EQUAL(ret_val, EXIT_SUCCESS)

    remove_plugin("monitoring_example");
}

static void send_multiple_records_test(void) {
    uint64_t ret_val;
    int status;
    int dummy_arg = 0;
    char path_pluglet[PATH_MAX];
    args_t fargs;
    insertion_point_t *point;

    memset(path_pluglet, 0, PATH_MAX * sizeof(char));
    snprintf(path_pluglet, PATH_MAX - 24, "%s/%s", plugin_folder_path, "send_a_lot_of_record.o");

    entry_args_t args[] = {
            {.arg = &dummy_arg, .len = sizeof(int), .kind = kind_primitive, .type = 0},
            entry_arg_null
    };

    fargs.nargs = 1;
    fargs.args = args;

    status = add_extension_code("multiple_monitoring", 19, 64, 0, 3, "point", 5, BPF_REPLACE,
                                0, 0, path_pluglet, 0, "multiple_send", 13, funcs, 0);
    CU_ASSERT_EQUAL(status, 0)
    point = insertion_point(3);
    run_replace_function(point, &fargs, &ret_val);
    CU_ASSERT_EQUAL(ret_val, EXIT_SUCCESS)

    remove_plugin("multiple_monitoring");
}

static void send_multiple_records_type_test(void) {
    uint64_t ret_val;
    int status;
    int dummy_arg = 0;
    char path_pluglet[PATH_MAX];
    args_t fargs;
    insertion_point_t *point;

    memset(path_pluglet, 0, PATH_MAX * sizeof(char));
    snprintf(path_pluglet, PATH_MAX - 25, "%s/%s", plugin_folder_path, "multiple_type_record.o");

    entry_args_t args[] = {
            {.arg = &dummy_arg, .len = sizeof(int), .kind = kind_primitive, .type = 0},
            entry_arg_null
    };
    fargs.args = args;
    fargs.nargs = 1;

    status = add_extension_code("multiple_record", 15, 64, 0, 2, "point", 5, BPF_REPLACE, 0, 0,
                                path_pluglet, 0, "the_vm_name", 11, funcs, 0);
    CU_ASSERT_EQUAL(status, 0)

    point = insertion_point(2);

    run_replace_function(point, &fargs, &ret_val);
    CU_ASSERT_EQUAL(ret_val, EXIT_SUCCESS)

    remove_plugin("multiple");
}

CU_ErrorCode ubpf_monitoring_tests(const char *plugin_folder) {

    CU_pSuite pSuite = NULL;
    memset(plugin_folder_path, 0, PATH_MAX * sizeof(char));
    realpath(plugin_folder, plugin_folder_path);

    pSuite = CU_add_suite("ubpf_monitoring_tests_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "Send one record of data", send_monitoring_record_test)) ||
        (NULL == CU_add_test(pSuite, "Send multiple records", send_multiple_records_test)) ||
        (NULL == CU_add_test(pSuite, "Send different type", send_multiple_records_type_test))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}
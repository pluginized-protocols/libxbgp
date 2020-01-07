//
// Created by twirtgen on 7/01/20.
//

#include "monitoring_tests.h"


#include <include/public.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <bpf_plugin.h>
#include <CUnit/CUnit.h>

char plugin_folder_path[PATH_MAX];

static proto_ext_fun_t funcs[] = {};

static plugin_info_t plugins[] = {
        {.plugin_str = "send_monitoring_data", .plugin_id = 1}
};

static int setup(void) {
    return init_plugin_manager(funcs, ".", 1, plugins,
                               "localhost", "6789", 1);
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
    bpf_full_args_t fargs;

    memset(path_pluglet, 0, PATH_MAX * sizeof(char));
    snprintf(path_pluglet, PATH_MAX, "%s/%s", plugin_folder_path, "send_monitoring_data.o");

    bpf_args_t args[] = {
            {.arg = &dummy_arg, .len = sizeof(int), .kind = kind_primitive, .type = 0},
    };
    new_argument(args, 1, 1, &fargs);

    status = add_pluglet(path_pluglet, 8, 0,
                         1, BPF_REPLACE, 0, 0);

    CU_ASSERT_EQUAL(status, 0)
    run_plugin_replace(1, &fargs, sizeof(bpf_full_args_t *), &ret_val);
    CU_ASSERT_EQUAL(ret_val, EXIT_SUCCESS)

    flush_buffer();

    rm_plugin(1, NULL);
}


int ubpf_monitoring_tests(const char *plugin_folder) {

    CU_pSuite pSuite = NULL;
    memset(plugin_folder_path, 0, PATH_MAX * sizeof(char));
    realpath(plugin_folder, plugin_folder_path);

    pSuite = CU_add_suite("ubpf_monitoring_tests_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "Send one record of data", send_monitoring_record_test))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}
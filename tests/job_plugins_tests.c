//
// Created by thomas on 1/07/21.
//

#include <time.h>
#include <plugins_manager.h>
#include "job_plugins_tests.h"

#include <CUnit/CUnit.h>
#include <evt_plugins.h>
#include <event.h>
#include <static_injection.h>
#include "tools_ubpf_api.h"
#include "context_function.h"

#define compute_time(...) ({   \
  long __start__, __end__;     \
  __start__ = get_monotime();  \
  {__VA_ARGS__}                \
  __end__ = get_monotime();    \
  __end__ - __start__;         \
})

/* block related stuffs */
static event_t event__;
static event_t *event = &event__;

static char plugin_folder_path[PATH_MAX - NAME_MAX - 1];
static int value = 0;
static int value1 = 0;
static int value2 = 0;

static long get_monotime(void) {
    struct timespec tp = {0};

    if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
        perror("Clock gettime");
        return -1;
    }

    return tp.tv_sec;
}

static int set_value(context_t *ctx UNUSED, int a) {
    value = a;
    event_broadcast(event);
    return value;
}

static def_fun_api(set_value, int, *(int *) ARGS[0])

static int set_value1(context_t *ctx UNUSED, int a) {
    value1 = a;
    event_broadcast(event);
    return value1;
}

static def_fun_api(set_value1, int, *(int *) ARGS[0])

static int set_value2(context_t *ctx UNUSED, int a) {
    value2 = a;
    event_broadcast(event);
    return value2;
}

static def_fun_api(set_value2, int, *(int *) ARGS[0])


static proto_ext_fun_t funcs[] = {
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_sint
                },
                .return_type = &ffi_type_sint,
                .args_nb = 1,
                .name = "set_value",
                .fn = set_value,
                .attributes = HELPER_ATTR_NONE,
                .closure_fn  = api_name_closure(set_value)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_sint
                },
                .return_type = &ffi_type_sint,
                .args_nb = 1,
                .name = "set_value1",
                .fn = set_value1,
                .attributes = HELPER_ATTR_NONE,
                .closure_fn  = api_name_closure(set_value1)
        },
        {
                .args_type = (ffi_type *[]) {
                        &ffi_type_sint
                },
                .return_type = &ffi_type_sint,
                .args_nb = 1,
                .name = "set_value2",
                .fn = set_value2,
                .attributes = HELPER_ATTR_NONE,
                .closure_fn  = api_name_closure(set_value2)
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

static void test_one_job_plugin(void) {
    char path_pluglet[PATH_MAX];
    int status;
    plugin_t *p;
    long elapsed_time;

    memset(path_pluglet, 0, sizeof(path_pluglet));
    snprintf(path_pluglet, sizeof(path_pluglet), "%s/job1_test.o", plugin_folder_path);

    status = add_extension_code("job1", 4, 0,
                                0, 1, "job_plugins", 11,
                                BPF_REPLACE, 0, 0, path_pluglet, 0,
                                "job1_vm", 7, funcs, 0, 1);

    CU_ASSERT_EQUAL_FATAL(status, 0)

    p = plugin_by_name("job1");

    CU_ASSERT_PTR_NOT_NULL_FATAL(p);

    // delay execution in 5 seconds
    add_plugin_job(p, 1, 5);

    elapsed_time = compute_time({
                                    event_wait(event);
                                });

    CU_ASSERT_TRUE(elapsed_time >= 5)
    CU_ASSERT_EQUAL(value, 131);

    CU_ASSERT_EQUAL_FATAL(remove_plugin_job_by_name("job1"), 0);
    CU_ASSERT_EQUAL_FATAL(remove_plugin("job1"), 0);
}

static void test_one_job_plugin_reschedule(void) {
    char path_pluglet[PATH_MAX];
    int status;
    plugin_t *p;
    long elapsed_time;

    memset(path_pluglet, 0, sizeof(path_pluglet));
    snprintf(path_pluglet, sizeof(path_pluglet), "%s/job2_test.o", plugin_folder_path);

    status = add_extension_code("job1", 4, 32,
                                256, 1, "job_plugins", 11,
                                BPF_REPLACE, 0, 0, path_pluglet, 0,
                                "job2_vm", 7, funcs, 0, 1);

    CU_ASSERT_EQUAL_FATAL(status, 0)

    p = plugin_by_name("job1");

    CU_ASSERT_PTR_NOT_NULL_FATAL(p);

    value = 0; // global

    // delay execution in 5 seconds
    add_plugin_job(p, 1, 5);

    elapsed_time = compute_time({
                                    event_wait(event);
                                });

    // 5 for the first execution + 10 for rescheduling in the plugin
    CU_ASSERT_TRUE(elapsed_time >= 15);
    CU_ASSERT_EQUAL(value, 56);

    CU_ASSERT_EQUAL_FATAL(remove_plugin_job_by_name("job1"), 0);
    CU_ASSERT_EQUAL_FATAL(remove_plugin("job1"), 0);
}

static void test_one_job_plugin_manifest(void) {
    char path_manifest[PATH_MAX];
    long elapsed_time;

    memset(path_manifest, 0, sizeof(path_manifest));
    snprintf(path_manifest, sizeof(path_manifest), "%s/meta_manifest.conf", plugin_folder_path);

    CU_ASSERT_EQUAL_FATAL(
            load_extension_code(path_manifest, plugin_folder_path, funcs, plugins),
            0);

    elapsed_time = compute_time({
                                    event_wait(event);
                                });

    CU_ASSERT_TRUE(elapsed_time >= 7);
    CU_ASSERT_EQUAL(value, 78);
}

static void test_two_jobs_plugin_manifest(void) {
    char path_job[PATH_MAX];
    long elapsed_time;
    int status;

    memset(path_job, 0, sizeof(path_job));
    snprintf(path_job, sizeof(path_job), "%s/job41_test.o", plugin_folder_path);

    status = add_extension_code("job1", 4, 0,
                                0, 1, "job_plugins", 11,
                                BPF_REPLACE, 0, 0, path_job, 0,
                                "job2_vm", 7, funcs, 0, 1);

    CU_ASSERT_EQUAL_FATAL(status, 0);

    memset(path_job, 0, sizeof(path_job));
    snprintf(path_job, sizeof(path_job), "%s/job42_test.o", plugin_folder_path);

    status = add_extension_code("job2", 4, 0,
                                0, 1, "job_plugins", 11,
                                BPF_REPLACE, 0, 0, path_job, 0,
                                "job42_vm", 8, funcs, 0, 1);

    CU_ASSERT_EQUAL_FATAL(status, 0);

    add_plugin_job(plugin_by_name("job1"), 1, 5);
    add_plugin_job(plugin_by_name("job2"), 1, 2);

    // should have 2 events
    elapsed_time = compute_time({
                                    event_wait(event);
                                });

    CU_ASSERT_TRUE(elapsed_time >= 2);
    CU_ASSERT_EQUAL(value2, 111);

    elapsed_time = compute_time({
                                    event_wait(event);
                                });

    CU_ASSERT_TRUE(elapsed_time >= 3);
    CU_ASSERT_EQUAL(value1, 678);

    CU_ASSERT_EQUAL_FATAL(remove_plugin_job_by_name("job1"), 0);
    CU_ASSERT_EQUAL_FATAL(remove_plugin_job_by_name("job2"), 0);
    CU_ASSERT_EQUAL_FATAL(remove_plugin("job1"), 0);
    CU_ASSERT_EQUAL_FATAL(remove_plugin("job2"), 0);
}


CU_ErrorCode job_plugins_tests(const char *plugin_folder) {
    CU_pSuite pSuite = NULL;
    snprintf(plugin_folder_path, sizeof(plugin_folder_path), "%s/job_plugins", plugin_folder);

    pSuite = CU_add_suite("job_plugins_tests_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "Add one job plugin and execute is 5s later", test_one_job_plugin)) ||
        (NULL == CU_add_test(pSuite, "Add one job 5s, then reschedule 10s later", test_one_job_plugin_reschedule)) ||
        (NULL == CU_add_test(pSuite, "Add job 7s with manifest", test_one_job_plugin_manifest)) ||
        (NULL == CU_add_test(pSuite, "Add 2 jobs: 2s and 5s", test_two_jobs_plugin_manifest))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();

}
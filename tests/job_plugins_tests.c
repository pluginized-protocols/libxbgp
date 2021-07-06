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

static inline int sleep_sec(int seconds) {
    const struct timespec tp = {.tv_sec = seconds, .tv_nsec = 0};

    if (nanosleep(&tp, NULL) == -1) {
        perror("Nanosleep");
        return -1;
    }
    return 0;
}

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

static proto_ext_fun_t funcs[] = {
        {.name = "set_value", .fn = set_value, .attributes = HELPER_ATTR_NONE},
        proto_ext_func_null
};

static insertion_point_info_t plugins[] = {
        {.insertion_point_str = "job_plugins", .insertion_point_id = 1},
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
}

static void test_one_job_plugin_manifest(void) {
    char path_manifest[PATH_MAX];
    long elapsed_time;

    memset(path_manifest, 0, sizeof(path_manifest));
    snprintf(path_manifest, sizeof(path_manifest), "%s/job_manifest.json", plugin_folder_path);

    CU_ASSERT_EQUAL_FATAL(
            load_extension_code(path_manifest, plugin_folder_path, funcs, plugins),
            0);

    elapsed_time = compute_time({
                                    event_wait(event);
                                });

    CU_ASSERT_TRUE(elapsed_time >= 7);
    CU_ASSERT_EQUAL(value, 78);

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
        (NULL == CU_add_test(pSuite, "Add job 7s with manifest", test_one_job_plugin_manifest))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();

}
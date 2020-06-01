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
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <fcntl.h>
#include <assert.h>

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

static char plugin_folder_path[PATH_MAX];

pid_t exporter_pid = -1;

static proto_ext_fun_t funcs[] = {};

static plugin_info_t plugins[] = {
        {.plugin_str = "send_monitoring_data", .plugin_id = 1},
        {.plugin_str = "send_a_lot_of_record", .plugin_id = 2},
        {.plugin_str = "pultiple_type_record", .plugin_id = 3}
};

static int setup(void) {

    int null_fd, cloned_fd;
    struct timespec ts = {.tv_sec = 2, .tv_nsec = 0};

    pid_t exporter_proc;
    exporter_proc = fork();

    if (exporter_proc == -1) {
        return -1;
    } else if (exporter_proc == 0) { // child

        char this_file_path[PATH_MAX];
        char this_file_dirname[PATH_MAX];
        char server_process[PATH_MAX];

        if ((null_fd = open("/dev/null", O_WRONLY)) == -1) {
            perror("Unable to open /dev/null");
            exit(EXIT_FAILURE);
        }

        if (close(STDOUT_FILENO) == -1 || close(STDERR_FILENO) == -1) {
            perror("Unable to close stdin and stderr");
            exit(EXIT_FAILURE);
        }

        if ((cloned_fd = dup(null_fd)) == -1) {
            perror("Redirecting stdout to /dev/null failed");
            exit(EXIT_FAILURE);
        }
        assert(cloned_fd == MIN(STDOUT_FILENO, STDERR_FILENO));

        if ((cloned_fd = dup(null_fd)) == -1) {
            perror("Redirecting stderr to /dev/null failed");
            exit(EXIT_FAILURE);
        }
        assert(cloned_fd == MAX(STDOUT_FILENO, STDERR_FILENO));

        if (close(null_fd) == -1) {
            perror("Unable to close higher /dev/null file descriptor");
            exit(EXIT_FAILURE);
        }

        memset(server_process, 0, sizeof(char) * PATH_MAX);
        memset(this_file_dirname, 0, sizeof(char) * PATH_MAX);
        memset(this_file_path, 0, sizeof(char) * PATH_MAX);

        strncpy(this_file_path, __FILE__, PATH_MAX);
        strncpy(this_file_dirname, dirname(this_file_path), sizeof(char) * PATH_MAX);
        snprintf(server_process, PATH_MAX - 22, "%s/exporter_example.py", this_file_dirname);

        char *const args[] = {basename(server_process), NULL};
        char *const env[] = {NULL};
        if (execve(server_process, args, env) == -1) {
            perror("execve");
            fprintf(stderr, "Unable to launch the server %s\n", server_process);
            exit(EXIT_FAILURE);
        }

        // should not be reached
        _exit(127);

    } else {

        // wait the exporter has been launched...
        exporter_pid = exporter_proc;
        if (nanosleep(&ts, NULL) != 0) return -1;

        return init_plugin_manager(funcs, ".", 1, plugins,
                                   "localhost", "6789", 1);
    }
}

static int teardown(void) {

    struct timespec ts = {.tv_sec = 2, .tv_nsec = 0};

    ubpf_terminate();
    if (nanosleep(&ts, NULL) != 0) return -1;
    if (exporter_pid != -1) kill(exporter_pid, SIGINT);
    return 0;
}

void send_monitoring_record_test(void) {

    uint64_t ret_val;
    int status;
    int dummy_arg = 0;
    char path_pluglet[PATH_MAX];
    bpf_full_args_t fargs;

    struct timespec tv = {.tv_sec = 5, .tv_nsec = 0};

    memset(path_pluglet, 0, PATH_MAX * sizeof(char));
    snprintf(path_pluglet, PATH_MAX - 24, "%s/%s", plugin_folder_path, "send_monitoring_data.o");

    bpf_args_t args[] = {
            {.arg = &dummy_arg, .len = sizeof(int), .kind = kind_primitive, .type = 0},
    };
    new_argument(args, 1, 1, &fargs);

    status = add_pluglet(path_pluglet, 8, 0,
                         1, BPF_REPLACE, 0, 0);

    CU_ASSERT_EQUAL(status, 0)
    run_plugin_replace(1, &fargs, sizeof(bpf_full_args_t *), &ret_val);
    CU_ASSERT_EQUAL(ret_val, EXIT_SUCCESS)

    nanosleep(&tv, NULL);

    rm_plugin(1, NULL);
}

static void send_multiple_records_test(void) {
    uint64_t ret_val;
    int status;
    int dummy_arg = 0;
    char path_pluglet[PATH_MAX];
    bpf_full_args_t fargs;

    struct timespec tv = {.tv_sec = 5, .tv_nsec = 0};

    memset(path_pluglet, 0, PATH_MAX * sizeof(char));
    snprintf(path_pluglet, PATH_MAX - 24, "%s/%s", plugin_folder_path, "send_a_lot_of_record.o");

    bpf_args_t args[] = {
            {.arg = &dummy_arg, .len = sizeof(int), .kind = kind_primitive, .type = 0},
    };
    new_argument(args, 3, 1, &fargs);

    status = add_pluglet(path_pluglet, 8, 0,
                         3, BPF_REPLACE, 0, 0);

    CU_ASSERT_EQUAL(status, 0)
    run_plugin_replace(3, &fargs, sizeof(bpf_full_args_t *), &ret_val);
    CU_ASSERT_EQUAL(ret_val, EXIT_SUCCESS)

    nanosleep(&tv, NULL);

    rm_plugin(3, NULL);
}

static void send_multiple_records_type_test(void) {
    uint64_t ret_val;
    int status;
    int dummy_arg = 0;
    char path_pluglet[PATH_MAX];
    bpf_full_args_t fargs;

    struct timespec tv = {.tv_sec = 5, .tv_nsec = 0};

    memset(path_pluglet, 0, PATH_MAX * sizeof(char));
    snprintf(path_pluglet, PATH_MAX - 25, "%s/%s", plugin_folder_path, "multiple_type_record.o");

    bpf_args_t args[] = {
            {.arg = &dummy_arg, .len = sizeof(int), .kind = kind_primitive, .type = 0},
    };
    new_argument(args, 1, 1, &fargs);

    status = add_pluglet(path_pluglet, 8, 0,
                         2, BPF_REPLACE, 0, 0);

    CU_ASSERT_EQUAL(status, 0)
    run_plugin_replace(2, &fargs, sizeof(bpf_full_args_t *), &ret_val);
    CU_ASSERT_EQUAL(ret_val, EXIT_SUCCESS)

    nanosleep(&tv, NULL);

    rm_plugin(2, NULL);
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

    if ((NULL == CU_add_test(pSuite, "Send one record of data", send_monitoring_record_test)) ||
        (NULL == CU_add_test(pSuite, "Send multiple records", send_multiple_records_test)) ||
        (NULL == CU_add_test(pSuite, "Send different type", send_multiple_records_type_test))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}
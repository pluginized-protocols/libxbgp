//
// Created by thomas on 29/11/19.
//

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>


#include "tree_test.h"
#include "ubpf_manager_test.h"
#include "monitoring_tests.h"
#include "list_test.h"
#include "mempool_tests.h"
#include "internal_tests.h"
#include "next_replace_tests.h"
#include "extra_info_test.h"
#include "extra_info_big.h"
#include "socket_tests.h"
#include "utils_tests.h"
#include "permissions_test.h"

#define MIN(a, b) (((a) > (b)) ? (b) : (a))

int std_stream_to_file(int std_stream, const char *file) {
    switch (std_stream) {
        case STDIN_FILENO:
        case STDERR_FILENO:
        case STDOUT_FILENO:
            break;
        default:
            return -1;
    }

    fsync(std_stream);

    int dev_null = open(file, O_WRONLY);
    if (dev_null < 0) {
        fprintf(stderr, "Failed to open %s: %s", file, strerror(errno));
        return -1;
    }

    if (close(std_stream) == -1) {
        perror("Unable to close stream");
        return -1;
    }

    if (dup(dev_null) == -1) {
        fprintf(stderr, "dup %s: %s", file, strerror(errno));
        return -1;
    }

    if (close(dev_null) == -1) {
        fprintf(stderr, "Unable to close dev_null %s fd: %s", file, strerror(errno));
        perror("Unable to close dev_null fd");
    }

    return 0;
}


static inline int stderr_to_dev_null(void) {
    return std_stream_to_file(STDERR_FILENO, "/dev/null");
}


int main(int argc, char *argv[]) {
    int c;
    int option_index = 0;

    char *plugin_folder_path;
    int have_folder = 0;


    static struct option long_options[] = {
            {"plugin-folder", required_argument, 0, 'p'},
            {0, 0,                               0, 0}
    };


    while (1) {
        c = getopt_long(argc, argv, "p:",
                        long_options, &option_index);
        if (c == -1) break;

        switch (c) {
            case 'p':
                if (have_folder) {
                    return EXIT_FAILURE;
                }
                plugin_folder_path = optarg;
                printf("%s\n", plugin_folder_path);
                have_folder = 1;
                break;
            default:
                return EXIT_FAILURE;
        }

    }

    if (!have_folder) {
        fprintf(stderr, "Must take -p parameter to locate the plugin folder test\n");
        return EXIT_FAILURE;
    }

    if (stderr_to_dev_null() == -1) {
        return EXIT_FAILURE;
    }


    /* initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    if ((internal_tests() != CUE_SUCCESS) ||
        (tree_tests() != CUE_SUCCESS) ||
        (list_tests() != CUE_SUCCESS) ||
        (test_socket_api(plugin_folder_path) != CUE_SUCCESS) ||
        (mem_pool_tests() != CUE_SUCCESS) ||
        (ubpf_manager_tests(plugin_folder_path) != CUE_SUCCESS) ||
        (next_replace_tests(plugin_folder_path) != CUE_SUCCESS) ||
        (test_permissions_plugins(plugin_folder_path) != CUE_SUCCESS) ||
        (extra_info_tests() != CUE_SUCCESS) ||
        (extra_info_big_tests() != CUE_SUCCESS) ||
        (ubpf_monitoring_tests(plugin_folder_path) != CUE_SUCCESS)) {

        fprintf(stderr, "%s\n", CU_get_error_msg());
        CU_cleanup_registry();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    CU_basic_show_failures(CU_get_failure_list());
    CU_cleanup_registry();
    return EXIT_SUCCESS;

}
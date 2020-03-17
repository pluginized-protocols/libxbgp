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


#include "tree_test.h"
#include "ubpf_manager_test.h"
#include "monitoring_tests.h"
#include "list_test.h"
#include "mempool_tests.h"

int main(int argc, char *argv[]) {

    int c;
    int option_index = 0;

    char plugin_folder_path[PATH_MAX];
    int have_folder = 0;
    memset(plugin_folder_path, 0, PATH_MAX * sizeof(char));


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
                strncpy(plugin_folder_path, optarg, PATH_MAX - 1);
                printf("%s\n", plugin_folder_path);
                have_folder = 1;
                break;
            default:
                return EXIT_FAILURE;
        }

    }

    if (!have_folder) return EXIT_FAILURE;


    /* initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    if ((tree_tests() != CUE_SUCCESS) ||
        (list_tests() != CUE_SUCCESS) ||
        (mem_pool_tests() != CUE_SUCCESS) ||
        (ubpf_manager_tests(plugin_folder_path) != CUE_SUCCESS) ||
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
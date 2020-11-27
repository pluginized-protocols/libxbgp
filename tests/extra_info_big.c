//
// Created by thomas on 5/06/20.
//

#include <CUnit/CUnit.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <libgen.h>
#include <plugin_extra_configuration.h>

#include "extra_info_big.h"

static char json_path[PATH_MAX];

static int setup(void) {
    char cpy_folder_file[PATH_MAX];
    char *folder;

    memset(json_path, 0, PATH_MAX);

    strncpy(cpy_folder_file, __FILE__, PATH_MAX);
    folder = dirname(cpy_folder_file);
    snprintf(json_path, PATH_MAX - 17, "%s/extra_info_rpki_valid_big.json", folder);

    if (extra_info_from_json(json_path, "conf") != 0) return -1;

    return 0;
}

static int teardown(void) {
    delete_all();
    return 0;
}

static void test_big_walk(void) {

    int i;

    struct global_info info = {.type = 0, .hidden_ptr = NULL};
    struct global_info current_lst = {.type = 0, .hidden_ptr = NULL};
    struct global_info current_int = {.type = 0, .hidden_ptr = NULL};
    struct global_info current_prefix = {.type = 0, .hidden_ptr = NULL};

    union ubpf_prefix pfx;
    uint64_t as;

    memset(&pfx, 0, sizeof(pfx));

    CU_ASSERT_EQUAL_FATAL(get_global_info("allowed_prefixes", &info), 0);

    for (i = 0;; i++) {

        if (get_info_lst_idx(&info, i, &current_lst) != 0) break;

        CU_ASSERT_EQUAL_FATAL(get_info_lst_idx(&current_lst, 0, &current_int), 0);
        CU_ASSERT_EQUAL_FATAL(get_info_lst_idx(&current_lst, 1, &current_prefix), 0);

        CU_ASSERT_EQUAL_FATAL(extra_info_copy_data(&current_int, &as, sizeof(as)), 0);
        CU_ASSERT_EQUAL_FATAL(extra_info_copy_data(&current_prefix, &pfx, sizeof(pfx)), 0);

    }

    /* should be at least 10 000 items */
    CU_ASSERT(i >= 623316);

}

int extra_info_big_tests(void) {
    CU_pSuite pSuite = NULL;

    pSuite = CU_add_suite("extra_info_big_tests_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "BIG json walk", test_big_walk))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}
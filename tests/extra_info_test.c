//
// Created by thomas on 1/06/20.
//

#include <CUnit/CUnit.h>
#include <plugin_extra_configuration.h>
#include "extra_info_test.h"

#include <limits.h>
#include <libgen.h>

#include <arpa/inet.h>

#include "utlist.h"

char json_path[PATH_MAX];


static int setup(void) {
    json_object *manifest;
    char cpy_folder_file[PATH_MAX];
    char *folder;

    memset(json_path, 0, PATH_MAX);

    strncpy(cpy_folder_file, __FILE__, PATH_MAX);
    folder = dirname(cpy_folder_file);
    snprintf(json_path, PATH_MAX - 17, "%s/extra_info.json", folder);

    if (extra_info_from_json(json_path, &manifest, "router_info") != 0) return -1;
    if (json_parse_extra_info(manifest) != 0) return -1;

    json_object_put(manifest);

    return 0;
}

static int teardown(void) {
    delete_all();
    return 0;
}

static void test_parse_extra_info(void) {

    struct conf_val *val;

    val = get_extra_from_key("my_int");


    CU_ASSERT_PTR_NOT_NULL_FATAL(val);

    CU_ASSERT_EQUAL(val->type, conf_val_type_int)
    CU_ASSERT_EQUAL(val->val.int_val, 42)

}

static void test_list_iter(void) {

    int i;
    struct conf_val *val;
    struct conf_lst *curr_val;
    uint8_t seen[2];
    const char *ip4_str[] = {[0] = "192.168.56.12", [1] = "192.168.56.13"};
    struct in_addr ips[2];

    val = get_extra_from_key("my_list");
    memset(seen, 0, sizeof(uint8_t) * 2);

    for (i = 0; i < 2; i++) {
        if (!inet_pton(AF_INET, ip4_str[i], ips + i)) CU_FAIL_FATAL("Unable to convert IPs");
    }

    CU_ASSERT_PTR_NOT_NULL_FATAL(val);

    CU_ASSERT_EQUAL(val->type, conf_val_type_list)

    DL_FOREACH(val->val.lst, curr_val) {
        CU_ASSERT_EQUAL(curr_val->cf_val->type, conf_val_type_ipv4);
        for (i = 0; i < 2; i++) {
            if (ips[i].s_addr == curr_val->cf_val->val.ip4.s_addr) {
                seen[i] = 1;
            }
        }
    }

    for (i = 0; i < 2; i++) {
        CU_ASSERT_EQUAL(seen[i], 1);
    }
}


int extra_info_tests(void) {
    CU_pSuite pSuite = NULL;

    pSuite = CU_add_suite("extra_info_tests_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "Parse JSON", test_parse_extra_info)) ||
        (NULL == CU_add_test(pSuite, "Iterator extra Info", test_list_iter))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}
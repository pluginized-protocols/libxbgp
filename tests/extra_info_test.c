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

static char json_path[PATH_MAX];


static int setup(void) {
    char cpy_folder_file[PATH_MAX];
    char *folder;

    memset(json_path, 0, PATH_MAX);

    strncpy(cpy_folder_file, __FILE__, PATH_MAX);
    folder = dirname(cpy_folder_file);
    snprintf(json_path, PATH_MAX - 17, "%s/extra_info.json", folder);

    if (extra_info_from_json(json_path, "router_info") != 0) return -1;

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

    unsigned int i, j;
    struct conf_val *val;
    struct conf_val *curr_val;
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

    for (i = 0; i < val->val.lst.len; i++) {

        curr_val = val->val.lst.array[i];

        CU_ASSERT_EQUAL(curr_val->type, conf_val_type_ipv4);
        for (j = 0; j < 2; j++) {
            if (ips[j].s_addr == curr_val->val.ip4.s_addr) {
                seen[j] = 1;
            }
        }
    }

    for (i = 0; i < 2; i++) {
        CU_ASSERT_EQUAL(seen[i], 1);
    }
}

static void test_nested_list(void) {
    unsigned int g, h, i;
    struct conf_val *val;
    struct conf_val *curr_val, *nested_curr_val;

    const char *ip4_str[] = {[0] = "192.168.56.2", [1] = "192.168.56.3"};
    struct in_addr ips[2];
    uint8_t seen_ip[] = {0, 0};

    for (i = 0; i < 2; i++) {
        if (!inet_pton(AF_INET, ip4_str[i], ips + i)) CU_FAIL_FATAL("Unable to convert IPs");
    }

    uint64_t expected_val[] = {5698, 9999};
    uint8_t seen_int[] = {0, 0};

    val = get_extra_from_key("nested_list");
    CU_ASSERT_PTR_NOT_NULL_FATAL(val);

    for (g = 0; g < val->val.lst.len; g++) {
        curr_val = val->val.lst.array[g];
        CU_ASSERT_EQUAL_FATAL(curr_val->type, conf_val_type_list);
        for (h = 0; h < curr_val->val.lst.len; h++) {
            nested_curr_val = curr_val->val.lst.array[h];

            if (nested_curr_val->type == conf_val_type_int) {

                for (i = 0; i < 2; i++) {
                    if (expected_val[i] == nested_curr_val->val.int_val) {
                        seen_int[i] = 1;
                    }
                }

            } else if (nested_curr_val->type == conf_val_type_ipv4) {

                for (i = 0; i < 2; i++) {
                    if (ips[i].s_addr == nested_curr_val->val.ip4.s_addr) {
                        seen_ip[i] = 1;
                    }
                }


            } else {
                CU_FAIL_FATAL("UNEXPECTED TYPE !")
            }

        }
    }


    for (i = 0; i < 2; i++) {
        CU_ASSERT_EQUAL(seen_int[i], 1);
        CU_ASSERT_EQUAL(seen_ip[i], 1);
    }

}

static void test_dict_value(void) {

    struct global_info info;
    struct global_info curr_dict_as1;
    struct global_info curr_dict_as2;

    uint64_t as1, as2;

    CU_ASSERT_EQUAL_FATAL(get_global_info("super_hash", &info), 0);

    CU_ASSERT_EQUAL_FATAL(get_info_dict(&info, "192.168.56.0/24", &curr_dict_as1), 0);
    CU_ASSERT_EQUAL_FATAL(get_info_dict(&info, "192.168.57.0/24", &curr_dict_as2), 0);

    CU_ASSERT_EQUAL_FATAL(extra_info_copy_data(&curr_dict_as1, &as1, sizeof(as1)), 0);
    CU_ASSERT_EQUAL_FATAL(extra_info_copy_data(&curr_dict_as2, &as2, sizeof(as2)), 0);

    CU_ASSERT_EQUAL(as1, 65002);
    CU_ASSERT_EQUAL(as2, 65003)
}

static void test_nested_dict(void) {

    int i;
    struct global_info info;
    struct global_info info_lst;
    struct global_info curr_val;

    struct prefix_ip4 pfx;

    const char *ip4_str[] = {[0] = "192.168.56.0", [1] = "192.168.57.0"};
    struct in_addr ips[2];

    for (i = 0; i < 2; i++) {
        if (!inet_pton(AF_INET, ip4_str[i], ips + i)) CU_FAIL_FATAL("Unable to convert IPs");
    }

    CU_ASSERT_EQUAL_FATAL(get_global_info("super_hash_nested", &info), 0);
    CU_ASSERT_EQUAL_FATAL(get_info_dict(&info, "65002", &info_lst), 0);

    for (i = 0;; i++) {
        CU_ASSERT_FATAL(i <= 2)
        if (get_info_lst_idx(&info_lst, i, &curr_val) != 0) break;

        CU_ASSERT_EQUAL_FATAL(extra_info_copy_data(&curr_val, &pfx, sizeof(pfx)), 0)

        CU_ASSERT_EQUAL(pfx.family, AF_INET);
        CU_ASSERT_EQUAL(pfx.p.s_addr, ips[i].s_addr)
        CU_ASSERT_EQUAL(pfx.prefix_len, 24)

    }

    CU_ASSERT_EQUAL(i, 2);

}

CU_ErrorCode extra_info_tests(void) {
    CU_pSuite pSuite = NULL;

    pSuite = CU_add_suite("extra_info_tests_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "Parse JSON", test_parse_extra_info)) ||
        (NULL == CU_add_test(pSuite, "Iterator extra Info", test_list_iter)) ||
        (NULL == CU_add_test(pSuite, "Nested List", test_nested_list)) ||
        (NULL == CU_add_test(pSuite, "Getting Values from dict arg", test_dict_value)) ||
        (NULL == CU_add_test(pSuite, "Nested list from dict arg", test_nested_dict))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}
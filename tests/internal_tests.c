//
// Created by thomas on 24/03/20.
//

#include <CUnit/CUnit.h>
#include "internal_tests.h"

#include "ubpf_api.h"


/* taken for test */

#define __NUMARGS(...)  (sizeof((uintptr_t[]){__VA_ARGS__})/sizeof(uintptr_t))

#define ubpf_sprintf(str, size, format, ...)\
bvsnprintf(NULL, str, size, format, (uintptr_t[]) {__NUMARGS(__VA_ARGS__), ##__VA_ARGS__ })


static int setup(void) {
    return 0;
}

static int teardown(void) {
    return 0;
}

static void test_my_snprintf(void) {

    int bytes_written = 0;
    char buf[30];
    const char *expected_output = "Coucou 6-9";

    memset(buf, 0, sizeof(char) * 30);
    bytes_written = ubpf_sprintf(buf, 29, "Coucou %d-%d", 6, 9);

    CU_ASSERT_EQUAL(bytes_written, 10)
    CU_ASSERT_NSTRING_EQUAL(buf, expected_output, 11)

}

static void test_my_snprintf_string(void) {

    int bytes_written = 0;
    const char *name = "Thomas";
    const char *expected_output = "Hello Thomas!";
    char buf[30];
    memset(buf, 0, sizeof(char) * 30);

    bytes_written = ubpf_sprintf(buf, 29, "Hello %s!", name);

    CU_ASSERT_EQUAL(bytes_written, 13);
    CU_ASSERT_NSTRING_EQUAL(buf, expected_output, 14);

}

static void test_my_snprintf_mix(void) {

    int bytes_written = 0;
    int big_number = -65798;
    const char *name = "Thomas";
    const char *expected_output = "Hello Thomas! Big number is -65798";
    char buf[40];
    memset(buf, 0, sizeof(char) * 40);

    bytes_written = ubpf_sprintf(buf, 39, "Hello %s! Big number is %d", name, big_number);

    CU_ASSERT_EQUAL(bytes_written, 34);
    CU_ASSERT_NSTRING_EQUAL(buf, expected_output, 35);

}

int internal_tests(void) {
    CU_pSuite pSuite = NULL;

    pSuite = CU_add_suite("internal_test_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "Custom snprintf", test_my_snprintf)) ||
        (NULL == CU_add_test(pSuite, "Custom snprintf mix", test_my_snprintf_mix)) ||
        (NULL == CU_add_test(pSuite, "Custom snprintf string", test_my_snprintf_string))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}
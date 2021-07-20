//
// Created by thomas on 13/03/20.
//

#include <CUnit/CUnit.h>
#include <stdint.h>
#include "list_test.h"
#include "list.h"
#include <inttypes.h>


static int setup(void) {
    return 0;
}

static int teardown(void) {
    return 0;
}

static void test_list(void) {
    list_t *list;

    uint64_t i;
    uint64_t element;

    list = ebpf_init_list(sizeof(uint64_t));
    CU_ASSERT_PTR_NOT_NULL_FATAL(list)

    for (i = 1; i <= 10; i++) {
        CU_ASSERT_EQUAL_FATAL(enqueue_s(list, &i), 0);
    }


    for (i = 1; size(list); i++) {
        dequeue_s(list, &element);
        CU_ASSERT_EQUAL(element, i);
    }

}

static void test_ititerator_list(void) {

    list_t *list;
    list_iterator_t _it, *it;

    int i, *curr_element;

    it = &_it;
    list = ebpf_init_list(sizeof(int));
    CU_ASSERT_PTR_NOT_NULL_FATAL(list);

    for (i = 1; i <= 10; i++) {
        CU_ASSERT_EQUAL(enqueue_s(list, &i), 0);
    }

    list_iterator(list, it);

    i = 10;
    while ((curr_element = iterator_next(it)) != NULL) {
        CU_ASSERT_EQUAL(*curr_element, i);
        if (i % 2 != 0) iterator_remove(it);
        i--;
    }

    list_iterator(list, it);
    i = 10;
    while ((curr_element = iterator_next(it))) {
        CU_ASSERT_EQUAL(*curr_element, i);
        i -= 2;
    }
}


CU_ErrorCode list_tests(void) {
    CU_pSuite pSuite = NULL;

    pSuite = CU_add_suite("list_tests_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "Test list enqueue dequeue", test_list)) ||
        (NULL == CU_add_test(pSuite, "Test iterator", test_ititerator_list))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}
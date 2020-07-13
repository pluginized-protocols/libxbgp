//
// Created by thomas on 19/03/20.
//

#include <CUnit/CUnit.h>
#include "hashmap_tests.h"
#include "hashmap.h"

typedef hashmap_t(int) hashint_t;
typedef hashmap_iterator(int) hashint_iterator_t;

static int setup(void) {
    return 0;
}

static int teardown(void) {
    return 0;
}

void test_hashmap_iterator(void) {
    int i;
    int *j;
    hashint_t myhashmap;
    hashint_iterator_t it;
    char seen[10];

    memset(seen, 0, sizeof(char) * 10);
    hashmap_new(&myhashmap, sizeof(int));
    for (i = 1; i <= 10; i++) {
        CU_ASSERT_EQUAL_FATAL(hashmap_put(&myhashmap, i, i), 0)
    }
    CU_ASSERT_EQUAL_FATAL(hashmap_iterator_new(&it, &myhashmap), 0)

    while (hashmap_iterator_hasnext(&it)) {
        j = hashmap_iterator_next(&it);
        CU_ASSERT_PTR_NOT_NULL_FATAL(j)
        CU_ASSERT_TRUE_FATAL(*j <= 10)

        if (seen[(*j) - 1]) CU_FAIL("Element already seen")
        seen[(*j) - 1] = 1;
    }

    for (i = 0; i < 10; i++) {
        // Are all inserted values successfully seen ?
        CU_ASSERT_TRUE(seen[i] == 1)
    }

    hashmap_destroy(&myhashmap);
}

int hashmap_tests(void) {
    CU_pSuite pSuite = NULL;

    pSuite = CU_add_suite("hashmap_test_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "Test hashmap iterator", test_hashmap_iterator))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}
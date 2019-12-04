//
// Created by thomas on 28/11/19.
//

#include <CUnit/CUnit.h>

#include "tree_test.h"
#include <../tree.h>

static int setup(void) { return 0; }

static int teardown(void) { return 0; }


static void test_tree_add(void) {

    int one = 1;
    int two = 2;
    int three = 3;
    int four = 4;
    int five = 5;

    struct tree_iterator _it, *it;

    tree_t tree;
    new_tree(&tree);

    tree_put(&tree, 5, &five, sizeof(int));
    tree_put(&tree, 1, &one, sizeof(int));
    tree_put(&tree, 2, &two, sizeof(int));
    tree_put(&tree, 4, &four, sizeof(int));
    tree_put(&tree, 3, &three, sizeof(int));

    it = new_tree_iterator(&tree, &_it);

    CU_ASSERT_EQUAL(*((int *) tree_iterator_next(it)), 1)
    CU_ASSERT_EQUAL(*((int *) tree_iterator_next(it)), 2)
    CU_ASSERT_EQUAL(*((int *) tree_iterator_next(it)), 3)
    CU_ASSERT_EQUAL(*((int *) tree_iterator_next(it)), 4)
    CU_ASSERT_EQUAL(*((int *) tree_iterator_next(it)), 5)
    CU_ASSERT_PTR_NULL(tree_iterator_next(it))

    rm_tree_iterator(it);
    delete_tree(&tree);
}


static void test_tree_replace(void) {

    int one = 1;
    int two = 2;
    int three = 3;
    int four = 4;
    int five = 5;

    struct tree_iterator _it, *it;

    tree_t tree;
    new_tree(&tree);

    tree_put(&tree, 5, &five, sizeof(int));
    tree_put(&tree, 1, &one, sizeof(int));
    tree_put(&tree, 2, &two, sizeof(int));
    tree_put(&tree, 4, &four, sizeof(int));
    tree_put(&tree, 3, &three, sizeof(int));

    //replace
    tree_put(&tree, 3, &one, sizeof(int));

    it = new_tree_iterator(&tree, &_it);

    CU_ASSERT_EQUAL(*((int *) tree_iterator_next(it)), 1)
    CU_ASSERT_EQUAL(*((int *) tree_iterator_next(it)), 2)
    CU_ASSERT_EQUAL(*((int *) tree_iterator_next(it)), 1)
    CU_ASSERT_EQUAL(*((int *) tree_iterator_next(it)), 4)
    CU_ASSERT_EQUAL(*((int *) tree_iterator_next(it)), 5)
    CU_ASSERT_PTR_NULL(tree_iterator_next(it))

    rm_tree_iterator(it);
    delete_tree(&tree);
}

static void test_delete_node(void) {
    int one = 1;
    int two = 2;
    int three = 3;
    int four = 4;
    int five = 5;

    struct tree_iterator _it, *it;

    tree_t tree;
    new_tree(&tree);

    tree_put(&tree, 5, &five, sizeof(int));
    tree_put(&tree, 1, &one, sizeof(int));
    tree_put(&tree, 2, &two, sizeof(int));
    tree_put(&tree, 4, &four, sizeof(int));
    tree_put(&tree, 3, &three, sizeof(int));

    //replace
    tree_rm_key(&tree, 3);

    it = new_tree_iterator(&tree, &_it);

    CU_ASSERT_EQUAL(*((int *) tree_iterator_next(it)), 1)
    CU_ASSERT_EQUAL(*((int *) tree_iterator_next(it)), 2)
    CU_ASSERT_EQUAL(*((int *) tree_iterator_next(it)), 4)
    CU_ASSERT_EQUAL(*((int *) tree_iterator_next(it)), 5)

    CU_ASSERT_PTR_NULL(tree_iterator_next(it))

    rm_tree_iterator(it);
    delete_tree(&tree);
}


static void test_get_value(void) {

    int one = 1;
    int two = 2;
    int three = 3;
    int four = 4;
    int five = 5;
    int value;

    int six_million_three_hundred_fifty_four_thousand_four_hundred_twenty_one = 6354421;

    tree_t tree;
    new_tree(&tree);

    tree_put(&tree, 5, &five, sizeof(int));
    tree_put(&tree, 1, &one, sizeof(int));
    tree_put(&tree, 2, &two, sizeof(int));
    tree_put(&tree, 4, &four, sizeof(int));
    tree_put(&tree, 3, &three, sizeof(int));
    tree_put(&tree, 0, &six_million_three_hundred_fifty_four_thousand_four_hundred_twenty_one, sizeof(int));


    CU_ASSERT_EQUAL(tree_get(&tree, 0, &value), 0)
    CU_ASSERT_EQUAL(value, 6354421)

    delete_tree(&tree);
}

CU_ErrorCode tree_tests(void) {
    // ...
    CU_pSuite pSuite = NULL;
    // ...
    pSuite = CU_add_suite("tree_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "Test adding values to the tree", test_tree_add)) ||
        (NULL == CU_add_test(pSuite, "Test replacing values", test_tree_replace)) ||
        (NULL == CU_add_test(pSuite, "Test deleting node", test_delete_node)) ||
        (NULL == CU_add_test(pSuite, "Test getting value from key", test_get_value))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}

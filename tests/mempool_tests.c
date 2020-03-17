//
// Created by thomas on 16/03/20.
//

#include <CUnit/CUnit.h>
#include "mempool_tests.h"
#include "public.h"


enum {
    TYPE_INT = 1,
    TYPE_RAW,
    TYPE_U64,
    TYPE_U16,
    TYPE_SUPER_STRUCT_PTR,
};

struct test_struct {
    uint64_t a;
    uint64_t b;
    uint64_t c;
};

struct test_struct_to_free {

    uint64_t a;
    uint64_t b;
    uint64_t *ptr_c;
    char *str;

};

static int setup(void) {
    return 0;
}

static int teardown(void) {
    return 0;
}

static void test_single_value_u16(void) {

    uint16_t u16bval;
    mem_pool *mp;
    mp = new_mempool();
    CU_ASSERT_PTR_NOT_NULL_FATAL(mp);

    u16bval = 63311;
    add_single_mempool(mp, TYPE_U16, NULL, sizeof(uint16_t), &u16bval);

    CU_ASSERT_EQUAL(get_mempool_u64(mp, TYPE_U16), u16bval);

    delete_mempool(mp);
}

static void test_ptr_value(void) {

    struct test_struct ts, *retrieved;

    mem_pool *mp;
    mp = new_mempool();
    CU_ASSERT_PTR_NOT_NULL_FATAL(mp);

    ts.a = 4937063535816211458;
    ts.b = 74391594270028887;
    ts.c = 2836770417;


    add_single_mempool(mp, TYPE_SUPER_STRUCT_PTR, NULL, sizeof(ts), &ts);
    retrieved = get_mempool_ptr(mp, TYPE_SUPER_STRUCT_PTR);

    CU_ASSERT_EQUAL(retrieved->a, ts.a);
    CU_ASSERT_EQUAL(retrieved->b, ts.b);
    CU_ASSERT_EQUAL(retrieved->c, ts.c);

    delete_mempool(mp);
}

static inline void cleanup_my_struct(void *_struct) {
    struct test_struct_to_free *my_struct = _struct;

    free(my_struct->str);
    free(my_struct->ptr_c);
}

static void test_ptr_with_memory_to_free(void) {

    struct test_struct_to_free my_struct, *retrieved;
    const char *my_str = "Hello World!";
    mem_pool *mp;

    mp = new_mempool();
    CU_ASSERT_PTR_NOT_NULL_FATAL(mp);

    my_struct.a = 461871689768;
    my_struct.b = 0xffffffffffffffff;
    my_struct.ptr_c = malloc(sizeof(int));
    my_struct.str = calloc(13, sizeof(char));

    if (!my_struct.ptr_c || !my_struct.str) CU_FAIL("Memory not allocated");

    *my_struct.ptr_c = 6554;
    strncpy(my_struct.str, my_str, 13);
    my_struct.str[12] = 0; // safe copy


    add_single_mempool(mp, TYPE_SUPER_STRUCT_PTR, cleanup_my_struct, sizeof(my_struct), &my_struct);
    retrieved = get_mempool_ptr(mp, TYPE_SUPER_STRUCT_PTR);

    CU_ASSERT_NSTRING_EQUAL(retrieved->str, my_str, 13);
    CU_ASSERT_EQUAL(*retrieved->ptr_c, 6554);
    CU_ASSERT_EQUAL(retrieved->a, 461871689768)
    CU_ASSERT_EQUAL(retrieved->b, 0xffffffffffffffff)

    delete_mempool(mp);
}

static void test_list_value(void) {

    int i, *current_value;

    mem_pool *mp;
    mempool_iterator *it;
    mp = new_mempool();

    CU_ASSERT_PTR_NOT_NULL_FATAL(mp);


    for (i = 1; i <= 10; i++)
        add_lst_mempool(mp, TYPE_INT, NULL, sizeof(int), &i);

    i = 10;
    for (it = new_iterator_mempool(mp, TYPE_INT); !end_mempool_iterator(it); i--) {
        current_value = get_mempool_iterator(it);
        CU_ASSERT_PTR_NOT_NULL_FATAL(current_value);

        CU_ASSERT_EQUAL(*current_value, i);
    }

    destroy_mempool_iterator(it);
    delete_mempool(mp);
}

static void test_raw_pointer(void) {

    const char *string = "Bonjour le monde!";
    mem_pool *mp;

    mp = new_mempool();
    CU_ASSERT_PTR_NOT_NULL_FATAL(mp);
    char *my_string = calloc(18, sizeof(char));

    strncpy(my_string, string, 18);
    my_string[17] = 0;

    add_raw_ptr_mempool(mp, TYPE_RAW, free, my_string);

    CU_ASSERT_NSTRING_EQUAL(get_mempool_ptr(mp, TYPE_RAW), string, 18);
    delete_mempool(mp);
}


int mem_pool_tests(void) {

    CU_pSuite pSuite = NULL;

    pSuite = CU_add_suite("Memory_pool_tests_suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "Test mempool list", test_list_value)) ||
        (NULL == CU_add_test(pSuite, "Test mempool single value uint 16 bits", test_single_value_u16)) ||
        (NULL == CU_add_test(pSuite, "Memory pool pointer value", test_ptr_value)) ||
        (NULL == CU_add_test(pSuite, "Adding/Deleting raw pointers", test_raw_pointer)) ||
        (NULL == CU_add_test(pSuite, "Delete ptr Memory Pool", test_ptr_with_memory_to_free))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CU_get_error();
}
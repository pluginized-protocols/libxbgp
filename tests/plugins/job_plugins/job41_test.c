//
// Created by thomas on 6/07/21.
//

#include "include/bytecode_public.h"


int set_value1(int a);

uint64_t job_test(args_t *args UNUSED) {
    set_value1(678);
    return 0;
}
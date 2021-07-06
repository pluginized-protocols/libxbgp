//
// Created by thomas on 6/07/21.
//

#include "include/bytecode_public.h"


int set_value(int a);

uint64_t job_test(args_t *args UNUSED) {
    set_value(78);
    return 0;
}
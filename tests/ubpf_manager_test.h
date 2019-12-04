//
// Created by twirtgen on 2/12/19.
//

#ifndef UBPF_TOOLS_UBPF_MANAGER_TEST_H
#define UBPF_TOOLS_UBPF_MANAGER_TEST_H

#include <ubpf_manager.h>

int add_two(context_t *ctx, int a);

void test_add_plugin(void);

int ubpf_manager_tests(const char *plugin_folder_path);

#endif //UBPF_TOOLS_UBPF_MANAGER_TEST_H

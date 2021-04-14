//
// Created by twirtgen on 7/01/20.
//

#ifndef UBPF_TOOLS_MONITORING_TESTS_H
#define UBPF_TOOLS_MONITORING_TESTS_H

#include <CUnit/CUnit.h>

void send_monitoring_record_test(void);

CU_ErrorCode ubpf_monitoring_tests(const char *plugin_folder);

#endif //UBPF_TOOLS_MONITORING_TESTS_H

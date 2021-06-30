//
// Created by thomas on 29/06/21.
//

#ifndef UBPF_TOOLS_EVT_PLUGINS_H
#define UBPF_TOOLS_EVT_PLUGINS_H

#include <stddef.h>

void *job_loop(void *arg);

void start_events_loop(void);

int add_plugin_job(const char *plugin_name, size_t name_len,
                   int insertion_point_id, int schedule);

#endif //UBPF_TOOLS_EVT_PLUGINS_H

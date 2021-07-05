//
// Created by thomas on 29/06/21.
//

#ifndef UBPF_TOOLS_EVT_PLUGINS_H
#define UBPF_TOOLS_EVT_PLUGINS_H

#include <stddef.h>
#include "bpf_plugin.h"

void *job_loop(void *arg);

int start_events_loop(void);

void cancel_event_loop(void);

int has_active_jobs(void);

int is_job_plugin(plugin_t *p);

int reschedule_job(plugin_t *plugin, const time_t *time);

int add_plugin_job(plugin_t *plugin, int insertion_point_id, int schedule);

#endif //UBPF_TOOLS_EVT_PLUGINS_H

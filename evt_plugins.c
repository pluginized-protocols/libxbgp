//
// Created by thomas on 29/06/21.
//

#include "evt_plugins.h"
#include "plugins_manager.h"

#include <time.h>
#include <stdio.h>
#include <utlist.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

typedef struct plugin_job {
    struct plugin_job *prev;
    struct plugin_job *next;
    time_t next_event;
    uint64_t schedule;
    size_t len_name;
    unsigned int insertion_point_id;
    char name[0];
} plugin_job_t;

static plugin_job_t *jobs = NULL;
static _Atomic int cancel_jobs = 0;

static inline int job_cmp(plugin_job_t *job1, plugin_job_t *job2) {
    time_t diff;
    diff = job1->next_event - job2->next_event;

    return diff;
}

static inline time_t monotime() {
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
        perror("clock_gettime");
        return -1;
    }

    return ts.tv_sec;
}

void *job_loop(void *arg __attribute__((unused))) {
    plugin_job_t *job, *tmp;
    time_t current_time;
    struct timespec tp;

    while (!cancel_jobs) {
        current_time = monotime();
        tp.tv_sec = job->next_event - current_time;
        if (nanosleep(&tp, NULL) == -1) {
            perror("Nanosleep");
        }

        DL_FOREACH_SAFE(jobs, job, tmp) {
            if (job->next_event > current_time) {
                break; // the list is ordered so, useless to reach le remaining jobs
            }

            DL_DELETE(jobs, job); // delete at the top to reinsert at the end

            insertion_point_t *point = insertion_point(job->insertion_point_id);
            if (!point) {
                fprintf(stderr, "Insertion point not found !");
            } else {
                run_replace_function(point, NULL, NULL);
                job->next_event += job->schedule;
                DL_INSERT_INORDER(jobs, job, job_cmp); // should reinsert at the end
            }
        }
    }

    return NULL;
}


void start_events_loop() {
    pthread_t pthread;
    pthread_attr_t attr;

    plugin_job_t *job;
    int count;

    DL_COUNT(jobs, job, count);

    if (count <= 0) {
        // no jobs useless to start the "event" manager
        return;
    }

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&pthread, &attr, job_loop, NULL) != 0) {
        fprintf(stderr, "phtread_create failed");
    }

    pthread_attr_destroy(&attr);
}

int add_plugin_job(const char *plugin_name, size_t name_len,
                   int insertion_point_id, int schedule) {
    plugin_job_t *job;
    job = malloc(sizeof(*job) + (sizeof(const char) * name_len));

    if (!job) {
        perror("Job malloc");
        return -1;
    }

    job->schedule = schedule;
    job->len_name = name_len;
    job->insertion_point_id = insertion_point_id;
    strncpy(job->name, plugin_name, name_len);

    job->next_event = monotime();
    DL_INSERT_INORDER(jobs, job, job_cmp);

    return 0;
}

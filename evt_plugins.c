//
// Created by thomas on 29/06/21.
//

#include "evt_plugins.h"
#include "plugins_manager.h"
#include "bpf_plugin.h"
#include "queue.h"
#include "event.h"

#include <time.h>
#include <stdio.h>
#include <utlist.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

typedef struct plugin_job {
    UT_hash_handle hh;
    time_t next_event;
    uint64_t schedule;
    int active;
    plugin_t *plugin;
    unsigned int insertion_point_id;
} plugin_job_t;

static pthread_t event_thread__;
static pthread_t *event_thread = &event_thread__;

static plugin_job_t *jobs = NULL;
static queue_t active_jobs__;
static queue_t *active_jobs = &active_jobs__;
static _Atomic int cancel_jobs = 0;

static event_t event__;
static event_t *event = &event__;

static inline int job_cmp(void *job1_, void *job2_) {
    plugin_job_t *job1 = job1_;
    plugin_job_t *job2 = job2_;

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
    plugin_job_t *job;
    plugin_job_t *peak_job;
    plugin_job_t **peakj;
    int res;
    long delta_ms;
    time_t current_time;

    while (!cancel_jobs && active_jobs != NULL) {
        if (!has_active_jobs()) {
            // wait until one job is in the queue
            event_wait(event);
            continue;
        }

        peakj = peak(active_jobs);
        if (peakj == NULL) {
            // no job ? Go to the beginning of the loop
            continue;
        }
        peak_job = *peakj;

        current_time = monotime();

        if (peak_job->next_event > current_time) {
            // need to wait remaining time or wait signal
            // for a change of priority in the queue
            delta_ms = (peak_job->next_event - current_time) * 1000;

            res = event_timedwait(event, delta_ms);

            if (res == 1) {
                // another thread has interrupted the wait.
                // We should recheck if another job shall be
                // executed first
                continue;
            } else if (res == -1) {
                return NULL; // error
            } else if (res != 0) {
                assert(0);
            }
            // res == 0 -> the thread has at least
            // slept delta_s microseconds. We can continue
        }

        // we have one job ready to be executed !
        assert(peak_job->next_event <= monotime());

        // dequeue blocks until a data can be dequeued
        if (dequeue(active_jobs, &job, sizeof(job)) != 0) {
            fprintf(stderr, "Dequeue failed !");
            return NULL;
        }

        job->active = 0; // job no longer in active_jobs
        // but run plugin can reactivate it once via API
        // function __reschedule_plugin
        run_plugin(job->plugin);
    }
    return NULL;
}

int reschedule_job(plugin_t *plugin, const time_t *time) {
    time_t current_time;
    plugin_job_t *pjob = NULL;
    HASH_FIND_STR(jobs, plugin->name, pjob);

    if (!pjob) return -1;
    if (pjob->active) return -1; // job is already active

    if (time) {
        pjob->schedule = *time;
    }

    current_time = monotime();
    pjob->next_event = current_time + pjob->schedule;
    pjob->active = 1;

    if (enqueue_inorder(active_jobs, &pjob, sizeof(pjob), job_cmp) != 0) {
        return -1;
    }

    return 0;
}

int start_events_loop() {
    cancel_jobs = 0;
    jobs = NULL;

    if (init_queue(active_jobs) == NULL) {
        return -1;
    }

    if (init_event(event) != 0) {
        return -1;
    }

    if (pthread_create(event_thread, NULL, job_loop, NULL) != 0) {
        fprintf(stderr, "phtread_create failed");
        return -1;
    }
    return 0;
}

void cancel_event_loop() {
    plugin_job_t *job, *tmp;

    cancel_jobs = 1;
    event_broadcast(event);

    pthread_join(*event_thread, NULL);

    destroy_queue(active_jobs);
    HASH_ITER(hh, jobs, job, tmp) {
        HASH_DEL(jobs, job);
        free(job);
    }

    jobs = NULL;

    event_destroy(event);
}

inline int has_active_jobs() {
    return q_size(active_jobs) > 0;
}

int is_job_plugin(plugin_t *p) {
    plugin_job_t *job;
    if (!p) return -1;

    HASH_FIND_STR(jobs, p->name, job);

    return job != NULL;
}

int add_plugin_job(plugin_t *plugin, int insertion_point_id, int schedule) {
    plugin_job_t *job;
    job = malloc(sizeof(*job));

    if (!job) {
        perror("Job malloc");
        return -1;
    }

    memset(job, 0, sizeof(*job));
    job->schedule = schedule;
    job->insertion_point_id = insertion_point_id;
    job->active = 1;
    job->plugin = plugin;
    job->next_event = monotime() + job->schedule;

    if (enqueue_inorder(active_jobs, &job, sizeof(job), job_cmp) != 0) {
        return -1;
    }
    HASH_ADD_STR(jobs, plugin->name, job);

    // Notify to the loop thread that
    // a new job has been added
    event_broadcast(event);

    return 0;
}
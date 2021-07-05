//
// Created by thomas on 2/07/21.
//

#include "event.h"
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <assert.h>


/// NOTE: strongly inspired from
/// https://github.com/microsoft/msquic/blob/main/src/inc/quic_platform_posix.h


#define NANOSEC_PER_MS       (1000000u)
#define NANOSEC_PER_SEC      (1000000000u)
#define MS_PER_SECOND        (1000u)

static inline int abs_time(long ms, struct timespec *tp) {
    int err;

    if (ms < 0) return -1;

    memset(tp, 0, sizeof(*tp));

    err = clock_gettime(CLOCK_MONOTONIC, tp);
    if (err != 0) return -1;

    tp->tv_sec += (ms / MS_PER_SECOND);
    tp->tv_nsec += ((ms % MS_PER_SECOND) * NANOSEC_PER_MS);

    if (tp->tv_nsec >= NANOSEC_PER_SEC) {
        tp->tv_sec += 1;
        tp->tv_nsec -= NANOSEC_PER_SEC;
    }
    return 0;
}


int init_event(event_t *event) {
    int err;
    pthread_condattr_t attr;

    memset(event, 0, sizeof(*event));
    *event = (event_t) {
            .mutex = PTHREAD_MUTEX_INITIALIZER,
            .event_set = 0
    };

    err = pthread_condattr_init(&attr);
    if (err != 0) return -1;

    err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    if (err != 0) return -1;

    err = pthread_cond_init(&event->cond, &attr);
    if (err != 0) return -1;

    err = pthread_condattr_destroy(&attr);
    return err;
}

int event_destroy(event_t *event) {
    pthread_mutex_destroy(&event->mutex);
    pthread_cond_destroy(&event->cond);
    return 0;
}

int event_broadcast(event_t *event) {
    int err;

    err = pthread_mutex_lock(&event->mutex);
    if (err != 0) return -1;

    event->event_set = 1;

    err = pthread_cond_broadcast(&event->cond);
    if (err != 0) return -1;

    err = pthread_mutex_unlock(&event->mutex);
    if (err != 0) return -1;
    return 0;
}


int event_wait(event_t *e) {
    int err;

    err = pthread_mutex_lock(&e->mutex);
    if (err != 0) return -1;

    while (!e->event_set) {
        err = pthread_cond_wait(&e->cond, &e->mutex);
        if (err != 0) return -1;
    }

    e->event_set = 0;

    err = pthread_mutex_unlock(&e->mutex);
    if (err != 0) return -1;

    return 0;
}

int event_timedwait(event_t *e, long msec) {
    int wait_satisfied;
    struct timespec tp = {.tv_sec = 0, .tv_nsec = 0};
    int err;

    abs_time(msec, &tp);

    err = pthread_mutex_lock(&e->mutex);
    if (err != 0) return -1;

    while (!e->event_set) {
        err = pthread_cond_timedwait(&e->cond, &e->mutex, &tp);

        if (err == ETIMEDOUT) {
            wait_satisfied = 0;
            goto exit;
        }

        if (err != 0) {
            wait_satisfied = -1;
            goto exit;
        }
    }

    e->event_set = 0;

    wait_satisfied = 1;

    exit:

    err = pthread_mutex_unlock(&e->mutex);
    if (err != 0) wait_satisfied = -1;

    return wait_satisfied;
}
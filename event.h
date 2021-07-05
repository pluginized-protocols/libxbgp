//
// Created by thomas on 2/07/21.
//

#ifndef UBPF_TOOLS_EVENT_H
#define UBPF_TOOLS_EVENT_H

#include <pthread.h>
#include <stdint.h>

typedef struct event {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int event_set;
} event_t;

int init_event(event_t *event);

int event_destroy(event_t *event);

int event_broadcast(event_t *event);

int event_wait(event_t *e);

int event_timedwait(event_t *e, long msec);


#endif //UBPF_TOOLS_EVENT_H

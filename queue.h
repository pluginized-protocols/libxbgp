//
// Created by thomas on 4/11/18.
//

#ifndef FRR_THESIS_QUEUE_H
#define FRR_THESIS_QUEUE_H

#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "utlist.h"

#define MAX_SIZE_QUEUE 2048

struct qdata {
    struct qdata *prev;
    struct qdata *next;

    size_t data_len;
    void *data[0];
};

typedef struct queue {
    pthread_mutex_t q_mutex;
    sem_t q_add;
    sem_t q_rm;

    _Atomic int q_size;
    struct qdata *elems;
} queue_t;

/**
 * Initialize the queue pointed by the "queue" pointer
 * @return the pointer passed in argument. NULL if
 *         the initialization fails
 */
queue_t *init_queue(queue_t *queue);

/**
 * Delete resources associated to the queue.
 * @return 0 if operation succeeded
 */
int destroy_queue(queue_t *);

/**
 * Enqueue the data pointed by elem inside the queue.
 * A new copy of the element is created!
 * @param q pointer related to the queue
 * @param elem pointer related to the element to copy inside the queue
 * @param len_data total length of the data to enqueue
 * @return  0 if enqueue succeeded
 *         -1 otherwise
 */
int enqueue(queue_t *q, void *elem, size_t len);

int enqueue_inorder(queue_t *q, void *elem, size_t len, int (*comp)(void *, void *));

/**
 * Dequeue a eleement and copy it to the space pointed by
 * elem given as argument of this function.
 * @param q pointer related to the function;
 * @param elem SHOULD NOT BE NULL since the data contained in the
 *             queue will be copied inside it
 * @return 1 if operation succeeds
 *         0 otherwise.
 */
int dequeue(queue_t *q, void *elem, size_t len);

void *peak(queue_t *queue);

int q_size(queue_t *q);

#endif //FRR_THESIS_QUEUE_H

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

#include "ubpf_tools/list.h"

#define MAX_SIZE_QUEUE 2048

typedef struct queue {
    pthread_mutex_t q_mutex;
    sem_t q_add;
    sem_t q_rm;

    list_t *list;
} queue_t;

/**
 * Allocate new space for the concurrent queue
 * @return a pointer associated to the new allocated structure
 *         NULL if out of memory
 */
queue_t *init_queue(size_t len);

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
 * @return 1 if enqueue succeeded
 *         0 otherwise
 */
int enqueue(queue_t *q, void *elem);

/**
 * Dequeue a eleement and copy it to the space pointed by
 * elem given as argument of this function.
 * @param q pointer related to the function;
 * @param elem SHOULD NOT BE NULL since the data contained in the
 *             queue will be copied inside it
 * @return 1 if operation succeeds
 *         0 otherwise.
 */
int dequeue(queue_t *q, void *elem);


#endif //FRR_THESIS_QUEUE_H

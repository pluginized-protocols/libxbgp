//
// Created by thomas on 4/11/18.
//

#include "queue.h"


queue_t *init_queue(queue_t *queue) {
    memset(queue, 0, sizeof(*queue));

    *queue = (queue_t) {
            .q_mutex = PTHREAD_MUTEX_INITIALIZER,
            .q_size = 0,
            .elems = NULL,
    };

    if (sem_init(&queue->q_add, 0, MAX_SIZE_QUEUE) == -1) {
        perror("Cannot create semaphore");
        return NULL;
    }
    if (sem_init(&queue->q_rm, 0, 0) == -1) {
        perror("Cannot create semaphore (2nd)");
        sem_destroy(&queue->q_add);
        return NULL;
    }

    return queue;
}

int destroy_queue(queue_t *q) {
    struct qdata *elem, *tmp;
    DL_FOREACH_SAFE(q->elems, elem, tmp) {
        DL_DELETE(q->elems, elem);
        free(elem);
    }

    pthread_mutex_destroy(&q->q_mutex);
    sem_destroy(&q->q_rm);
    sem_destroy(&q->q_add);

    return 0;
}

static inline int die(const char *str) {
    perror(str);
    return -1;
}


int enqueue_inorder(queue_t *q, void *elem, size_t len, int (*comp)(void *, void *)) {
    struct qdata *ndata;

    if (sem_wait(&q->q_add) != 0) return die("Sem Wait");
    if (pthread_mutex_lock(&q->q_mutex) != 0) return die("Mutex Lock");
    {
        ndata = calloc(1, sizeof(*ndata) + len);
        if (!ndata) return -1;

        ndata->data_len = len;
        memcpy(ndata->data, elem, len);

        q->q_size += 1;

        if (comp == NULL) {
            DL_APPEND(q->elems, ndata);
        } else {
            DL_INSERT_INORDER(q->elems, ndata, comp);
        }
    }
    if (pthread_mutex_unlock(&q->q_mutex) != 0) return die("Mutex Unlock");
    if (sem_post(&q->q_rm) != 0) return die("Sem post");
    return 0;
}

int enqueue(queue_t *q, void *elem, size_t len) {
    return enqueue_inorder(q, elem, len, NULL);
}

int dequeue(queue_t *q, void *elem, size_t len) {
    struct qdata *data;

    if (sem_wait(&q->q_rm) != 0) return die("Sem Wait");
    if (pthread_mutex_lock(&q->q_mutex) != 0) return die("Mutex Lock");
    {
        data = q->elems;
        DL_DELETE(q->elems, q->elems);
        memcpy(elem, data->data, len);
        free(data);
        q->q_size -= 1;
    }
    if (pthread_mutex_unlock(&q->q_mutex) != 0) return die("Mutex unlock");
    if (sem_post(&q->q_add) != 0) return die("Sem post");
    return 0;
}

void *peak(queue_t *queue) {
    void *data = NULL;
    if (pthread_mutex_lock(&queue->q_mutex) != 0) return NULL;
    {
        if (q_size(queue) != 0) {
            data = queue->elems->data;
        }
    }
    if (pthread_mutex_unlock(&queue->q_mutex) != 0) return NULL;
    return data;
}


int q_size(queue_t *q) {
    return q != NULL ? q->q_size : -1;
}
//
// Created by thomas on 4/11/18.
//

#include "queue.h"
#include "list.h"


queue_t *init_queue(size_t len) {
    queue_t *new_q;
    list_t *new_stack;
    pthread_mutex_t mutex;
    sem_t sem_add, sem_rm;

    if (pthread_mutex_init(&mutex, NULL) != 0) {
        perror("Cannot create mutex");
        return NULL;
    }
    if (sem_init(&sem_add, 0, MAX_SIZE_QUEUE) == -1) {
        perror("Cannot create semaphore");
        pthread_mutex_destroy(&mutex);
        return NULL;
    }
    if (sem_init(&sem_rm, 0, 0) == -1) {
        perror("Cannot create semaphore (2nd)");
        pthread_mutex_destroy(&mutex);
        sem_destroy(&sem_add);
        return NULL;
    }
    new_q = malloc(sizeof(queue_t));


    if (!new_q) {
        pthread_mutex_destroy(&mutex);
        sem_destroy(&sem_add);
        sem_destroy(&sem_rm);
        perror("Cannot create queue");
        return NULL;
    }

    new_stack = ebpf_init_list(len);

    if (!new_stack) {
        pthread_mutex_destroy(&mutex);
        sem_destroy(&sem_add);
        sem_destroy(&sem_rm);
        free(new_q);
        return NULL;
    }

    memcpy(&(new_q->q_mutex), &mutex, sizeof(pthread_mutex_t));
    memcpy(&(new_q->q_add), &sem_add, sizeof(sem_t));
    memcpy(&(new_q->q_rm), &sem_rm, sizeof(sem_t));
    new_q->list = new_stack;

    return new_q;
}

int destroy_queue(queue_t *q) {

    destroy_list(q->list);

    pthread_mutex_destroy(&q->q_mutex);
    sem_destroy(&q->q_rm);
    sem_destroy(&q->q_add);
    free(q);

    return 0;

}

static inline int die(const char *str) {
    perror(str);
    return 0;
}


int enqueue(queue_t *q, void *elem) {

    int err;

    if (sem_wait(&q->q_add) != 0) return die("Sem Wait");
    if (pthread_mutex_lock(&q->q_mutex) != 0) return die("Mutex Lock");
    {
        err = enqueue_s(q->list, elem);
    }
    if (pthread_mutex_unlock(&q->q_mutex) != 0) return die("Mutex Unlock");
    if (sem_post(&q->q_rm) != 0) return die("Sem post");
    return err == 0 ? 1 : 0;
}

int dequeue(queue_t *q, void *elem) {

    int err;

    if (sem_wait(&q->q_rm) != 0) return die("Sem Wait");
    if (pthread_mutex_lock(&q->q_mutex) != 0) return die("Mutex Lock");
    {
        err = dequeue_s(q->list, elem);
    }
    if (pthread_mutex_unlock(&q->q_mutex) != 0) return die("Mutex unlock");
    if (sem_post(&q->q_add) != 0) return die("Sem post");
    return err == 0 ? 1 : 0;
}


int q_size(queue_t *q) {
    return size(q->list);
}
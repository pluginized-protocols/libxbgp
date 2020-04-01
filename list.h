//
// Created by thomas on 27/12/18.
//

#ifndef FRR_UBPF_STACK_H
#define FRR_UBPF_STACK_H

#include <stddef.h>

#define iterator_next(iterator) \
    ((iterator)->next((iterator)))

#define iterator_get(iterator) \
    (iterator)->get((iterator))

#define iterator_end(iterator) \
    (iterator)->end((iterator))

#define iterator_remove(iterator) (iterator)->remove((iterator))


struct node {
    struct node *next;
    struct node *previous;
    void *data;
};

typedef struct linked_list_node {
    uint32_t size;
    size_t len;
    struct node *top;
    struct node *bot;
} list_t;

typedef struct list_iterator {
    list_t *from_lst;
    struct node *curr;
    struct node *fwd;

    void *(*get)(struct list_iterator *self);

    void *(*next)(struct list_iterator *self);

    int (*end)(struct list_iterator *self);

    int (*remove)(struct list_iterator *self);

} list_iterator_t;

typedef int (*comp_list)(void *list_elem);

list_t *ebpf_init_list(size_t len);

int push(list_t *stack, void *data);

int pop(list_t *stack, void *store);

int enqueue_s(list_t *stack, void *data);

int enqueue_after(list_t *l, void *data, comp_list compare);

int dequeue_s(list_t *stack, void *store);

void flush(list_t *stack);

void destroy_list(list_t *list);

uint32_t size(list_t *stack);

int list_iterator(list_t *list, list_iterator_t *iterator);


#endif //FRR_UBPF_STACK_H

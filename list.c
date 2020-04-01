//
// Created by thomas on 27/12/18.
//

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "list.h"

list_t *ebpf_init_list(size_t len) {

    list_t *new = malloc(sizeof(list_t));

    if (!new) {
        perror("List allocation failed");
        return NULL;
    }

    new->size = 0;
    new->len = len;
    new->top = NULL;
    new->bot = NULL;

    return new;
}

static struct node *init_node(size_t len) {
    struct node *node = malloc(sizeof(struct node));
    if (!node) return NULL;

    void *internal_data = malloc(len);
    if (!len) {
        free(node);
        return NULL;
    }
    node->next = NULL;
    node->previous = NULL;
    node->data = internal_data;
    return node;
}

static void free_node(struct node *node) {
    if (node) {
        free(node->data);
        free(node);
    }
}

int push(list_t *stack, void *data) {
    if (!stack || !data) return -1;

    struct node *node = init_node(stack->len);
    if (!node) return -1;
    memcpy(node->data, data, stack->len);

    if (stack->size != 0) {
        stack->top->previous = node;
    }

    node->next = stack->top;
    stack->top = node;

    if (stack->size == 0) {
        stack->bot = node;
    }

    stack->size++;

    return 0;
}

int pop(list_t *stack, void *store) {

    if (!stack) return -1;
    if (stack->size == 0) return -1;

    if (store)
        memcpy(store, stack->top->data, stack->len);

    struct node *to_free = stack->top;

    stack->top = stack->top->next;
    if (stack->size > 1)
        stack->top->previous = NULL; /* this is the top of the stack now */

    if (stack->size == 1) {
        stack->bot = NULL;
    }

    stack->size--;

    free_node(to_free);

    return 0;

}

int enqueue_s(list_t *stack, void *data) {
    return push(stack, data);
}

int dequeue_s(list_t *stack, void *store) {

    if (!stack) return -1;
    if (stack->size == 0) return -1;

    struct node *to_free = stack->bot;

    if (store)
        memcpy(store, to_free->data, stack->len);

    stack->bot = stack->bot->previous;

    if (stack->size > 1)
        stack->bot->next = NULL;
    if (stack->size == 1) {
        stack->top = NULL;
    }

    stack->size--;

    free_node(to_free);

    return 0;
}

int enqueue_after(list_t *l, void *data, comp_list compare) {

    struct node *current, *previous;
    struct node *new_node = init_node(l->len);
    if (!new_node) return -1;
    memcpy(new_node->data, data, l->len);

    l->size++;
    previous = NULL;

    for (current = l->top; current; current = current->next) {

        if (compare(current->data)) {
            new_node->next = current->next;
            current->next->previous = new_node;
            new_node->previous = current;
            current->next = new_node;
            return 0;
        }
        previous = current;
    }

    if (!previous) {
        l->top = new_node;
        l->bot = new_node;
        new_node->next = NULL;
        new_node->previous = NULL;
    } else {
        previous->next = new_node;
        new_node->previous = previous;
        new_node->next = NULL;
        l->bot = new_node;
    }

    return 0;
}

uint32_t size(list_t *stack) {
    if (!stack) return UINT32_MAX;
    return stack->size;
}

void flush(list_t *stack) {
    if (!stack) return;
    while (stack->size > 0) {
        pop(stack, NULL);
    }
}

void destroy_list(list_t *list) {
    if (!list) return;
    flush(list);
    free(list);
}

static void *__next(list_iterator_t *it) {
    if (!it) return NULL;

    it->curr = it->fwd;

    if (it->fwd) {
        it->fwd = it->fwd->next ? it->fwd->next : NULL;
    }

    return it->curr ? it->curr->data : NULL;
}

static int __end(list_iterator_t *it) {
    if (!it) {
        return 1;
    }
    if (!it->fwd && !it->curr) {
        return 1;
    }
    return 0;
}

static void *__get(list_iterator_t *it) {
    if (!it) return NULL;
    if (__end(it)) return NULL;
    return it->curr ? it->curr->data : NULL;
}

static int __remove(list_iterator_t *it) {

    list_t *lst;

    if (!it) return -1;
    if (!it->curr) return -1;

    lst = it->from_lst;

    if (lst->len == 1) {
        lst->top = NULL;
        lst->bot = NULL;
        it->curr = NULL;
        it->fwd = NULL;
    } else if (lst->top == it->curr) {
        lst->top = it->curr->next;
        lst->top->previous = NULL;
    } else if (lst->bot == it->curr) {
        lst->bot = lst->bot->previous;
        lst->bot->next = NULL;
        it->curr = NULL;
        it->fwd = NULL;
    } else {
        it->curr->previous->next = it->curr->next;
        it->curr->next->previous = it->curr->previous;
    }

    --lst->size;

    return 0;
}

int list_iterator(list_t *list, list_iterator_t *iterator) {

    if (!iterator || !list) return -1;

    iterator->from_lst = list;
    iterator->fwd = list->top;
    iterator->curr = NULL;
    iterator->next = &__next;
    iterator->get = &__get;
    iterator->end = &__end;
    iterator->remove = &__remove;

    return 0;
}
//
// Created by thomas on 27/11/19.
//

#include <stdio.h>
#include "tree.h"
#include <string.h>


struct tree_node *new_node(uint32_t key, void *value, int color, size_t val_len, size_t n_size) {

    struct tree_node *new;
    void *data;
    if (color != BLACK && color != RED) return NULL;

    new = malloc(sizeof(struct tree_node));
    if (!new) return NULL;

    data = malloc(val_len);
    if (!data) {
        free(new);
        return NULL;
    }
    memcpy(data, value, val_len);

    new->right = NULL;
    new->left = NULL;
    new->n = n_size;
    new->parent_color = color;
    new->val_len = val_len;
    new->value = data;
    new->key = key;

    return new;
}

void delete_tree_node(struct tree_node *node) {
    if (!node) return;
    free(node->value);
    free(node);
}

inline struct tree_node *rotate_left(struct tree_node *h) {
    struct tree_node *x = h->right;

    h->right = x->left;
    x->left = h;
    x->parent_color = h->parent_color;
    h->parent_color = RED;

    x->n = h->n;
    h->n = 1 + size(h->left) + size(h->right);

    return x;
}


inline struct tree_node *rotate_right(struct tree_node *h) {

    struct tree_node *x = h->left;

    h->left = x->right;
    x->right = h;
    x->parent_color = h->parent_color;
    h->parent_color = RED;

    x->n = h->n;
    h->n = 1 + size(h->left) + size(h->right);

    return x;
}


static inline struct tree_node *_put(struct tree_node *node, uint32_t key, void *value, size_t val_len) {
    struct tree_node *new;
    if (!node) {
        new = new_node(key, value, RED, val_len, 1);
        if (!new) {
            fprintf(stderr, "Tree insertion error");
            return NULL;
        }
        return new;
    }

    if (key < node->key) node->left = _put(node->left, key, value, val_len);
    else if (key > node->key) node->right = _put(node->right, key, value, val_len);
    else {
        memcpy(node->value, value, val_len);
        node->val_len = val_len;
    }

    if (is_red(node->right) && !is_red(node->left)) node = rotate_left(node);
    if (is_red(node->left) && is_red(node->left->left)) node = rotate_right(node);
    if (is_red(node->left) && is_red(node->right)) flip_colors(node);

    node->n = size(node->left) + size(node->right) + 1;

    return node;
}


int tree_put(tree_t *tree, uint32_t key, void *value, size_t val_len) {
    struct tree_node *root;

    root = _put(tree->root, key, value, val_len);
    if (!root) return -1;
    root->parent_color = BLACK;

    tree->root = root;
    return 0;
}

int tree_get(tree_t *tree, uint32_t key, void *data_cpy) {

    struct tree_node *curr_node;

    if (!tree) return -1;
    curr_node = tree->root;

    while (curr_node != NULL) {
        if (key < curr_node->key) curr_node = curr_node->left;
        else if (key > curr_node->key) curr_node = curr_node->right;
        else {
            memcpy(data_cpy, curr_node->value, curr_node->val_len);
            return 0;
        }
    }

    return -1;
}

static inline struct tree_node *min(struct tree_node *node) {

    struct tree_node *walker, *last_min;

    if (!node) return NULL;

    walker = last_min = node;
    while (walker) {
        last_min = walker;
        walker = walker->left;
    }

    return last_min;
}

static inline struct tree_node *delete_min(struct tree_node *node) {
    if (node->left == NULL) return node->right;
    node->left = delete_min(node->left);
    node->n = size(node->left) + size(node->right) + 1;
    return node;
}


static inline struct tree_node *_delete(struct tree_node *node, uint32_t key) {

    struct tree_node *t, *ret;

    if (!node) return NULL;

    if (key < node->key) node->left = _delete(node->left, key);
    else if (key > node->key) node->right = _delete(node->right, key);
    else {
        if (node->right == NULL) {
            ret = node->left;
            delete_tree_node(node);
            return ret;
        }
        if (node->left == NULL) {
            ret = node->right;
            delete_tree_node(node);
            return ret;
        }

        t = node;
        node = min(t->right);
        node->right = delete_min(t->right);
        node->left = t->left;
        delete_tree_node(t);
    }

    node->n = size(node->left) + size(node->right) + 1;
    return node;
}

int tree_rm_key(tree_t *tree, uint32_t key) {
    tree->root = _delete(tree->root, key);
    return 0;
}

void new_tree(tree_t *tree) {
    tree->root = NULL;
}

static struct tree_node *__tree_iterator_next(struct tree_iterator *it) {
    struct tree_node *next, *walker;
    if (pop(it->queue, &next) == -1) return NULL;

    if (!next) return NULL;

    walker = next->right;
    while (walker) {
        push(it->queue, &walker);
        walker = walker->left;
    }
    return next;
}

int delete_tree(tree_t *tree) {

    struct tree_iterator _it, *it;
    struct tree_node *next;

    it = new_tree_iterator(tree, &_it);

    while ((next = __tree_iterator_next(it)) != NULL) {
        delete_tree_node(next);
    }

    rm_tree_iterator(it);
    return 0;
}

struct tree_iterator *new_tree_iterator(tree_t *tree, struct tree_iterator *it) {

    if (it == NULL) return NULL;

    struct tree_node *walker;

    it->tree = tree;
    it->queue = ebpf_init_list(sizeof(struct tree_node *));
    if (!it->queue) return NULL;

    walker = tree->root;
    while (walker) {
        push(it->queue, &walker);
        walker = walker->left;
    }

    return it;
}

void *tree_iterator_next(struct tree_iterator *it) {

    struct tree_node *next;

    next = __tree_iterator_next(it);

    if (!next) return NULL;
    return next->value;
}

int tree_iterator_has_next(struct tree_iterator *it) {
    return it->queue->size != 0;
}

void rm_tree_iterator(struct tree_iterator *it) {
    destroy_list(it->queue);
}


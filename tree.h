//
// Created by thomas on 27/11/19.
//

#ifndef UBPF_TOOLS_TREE_H
#define UBPF_TOOLS_TREE_H

#include <stdint.h>
#include <stdlib.h>

#define RED 1
#define BLACK 0
#define is_red(node) ((node) == NULL ? 0 : (node)->parent_color == RED)
#define size(node) ((node) == NULL ? 0 : (node)->n)

#define flip_colors(node) {\
(node)->parent_color = RED;\
(node)->left->parent_color = BLACK;\
(node)->right->parent_color = BLACK;}

struct tree_node {
    uint32_t key;
    void *value;
    size_t val_len;
    uint32_t n;
    uint8_t parent_color;
    struct tree_node *left;
    struct tree_node *right;

    // hidden value for iterators
    struct tree_node *next_;
    struct tree_node *prev_;
};

typedef struct tree {
    struct tree_node *root;
} tree_t;


struct tree_iterator {
    struct tree_node *tree;
};

void new_tree(tree_t *tree);

struct tree_node *rotate_left(struct tree_node *h);

struct tree_node *rotate_right(struct tree_node *h);

struct tree_node *new_node(uint32_t key, void *value, int color, size_t val_len, size_t n_size);

int tree_put(tree_t *tree, uint32_t key, void *value, size_t val_len);

int tree_get(tree_t *tree, uint32_t key, void *data_cpy);

int tree_rm_key(tree_t *tree, uint32_t key);

void delete_tree_node(struct tree_node *node);

struct tree_iterator *new_tree_iterator(tree_t *tree, struct tree_iterator *it);

void *tree_iterator_next(struct tree_iterator *it);

int tree_iterator_has_next(struct tree_iterator *it);

void rm_tree_iterator(struct tree_iterator *it);

int delete_tree(tree_t *tree);

#endif //UBPF_TOOLS_TREE_H

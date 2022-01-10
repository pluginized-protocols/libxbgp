//
// Created by thomas on 27/07/21.
//

#ifndef UBPF_TOOLS_DICT_H
#define UBPF_TOOLS_DICT_H

#include <stdlib.h>
#include <stdint.h>

#include "uthash.h"

#define dict_init(dict) do { \
    *(dict) = NULL; \
} while(0)

typedef struct dict *dict_t;

void *dict_add(dict_t *dict, const char *key, size_t len_key, void *data, size_t data_len);

void *dict_add_key_int(struct dict **dict, unsigned int key, void *data, size_t data_len);

void *dict_get(dict_t *dict, const char *key);

void *dict_get_by_int(dict_t *dict, unsigned int key);

void dict_entry_del(dict_t *dict, const char *key);

void dict_entry_del_key_int(struct dict **dict, unsigned int key);

void dict_del(dict_t *dict);

#endif //UBPF_TOOLS_DICT_H

//
// Created by thomas on 27/07/21.
//

#include "dict.h"
#include <string.h>

struct dict {
    char *key;  // points to _data
    void *data; // points to _data + len_key

    UT_hash_handle hh;

    struct {
        size_t len_key;
        size_t len_data;
    } len;
    uint8_t _data[0];
};

static inline struct dict *new_dict_entry(const char *key, size_t key_len, void *data, size_t data_len) {
    struct dict *entry;
    entry = calloc(1, sizeof(*entry) + key_len + 1 + data_len);
    if (!entry) return NULL;

    /* copy the key */
    memcpy(entry->_data, key, key_len);
    entry->_data[key_len] = 0;


    /* copy the data */
    memcpy(entry->_data + key_len + 1, data, data_len);

    /* update entry pointers */
    entry->key = (char *) entry->_data;
    entry->data = entry->_data + key_len + 1;

    entry->len.len_data = data_len;
    entry->len.len_key = key_len;

    return entry;
}

static inline void free_dict_entry(struct dict *entry) {
    if (!entry) return;
    free(entry);
}

int dict_add(struct dict **dict, const char *key, size_t len_key, void *data, size_t data_len) {
    struct dict *entry;

    HASH_FIND_STR(*dict, key, entry);
    if (entry) return -1; /* key already used */

#define MAX_STR_DEVIATION 3
    if (strnlen(key, len_key + MAX_STR_DEVIATION) != len_key) {
        return -1;
    }

    entry = new_dict_entry(key, len_key, data, data_len);
    if (!entry) return -1;

    HASH_ADD_KEYPTR(hh, *dict, entry->key, entry->len.len_key, entry);
    return 0;
}

void *dict_get(dict_t *dict, const char *key) {
    struct dict *entry;

    HASH_FIND_STR(*dict, key, entry);
    if (!entry) return NULL;

    return entry->data;
}

#define delete_entry(dict, entry) \
do {                              \
    HASH_DEL((dict), (entry));    \
    free_dict_entry((entry));       \
} while(0)


void dict_entry_del(struct dict **dict, const char *key) {
    struct dict *entry;

    HASH_FIND_STR(*dict, key, entry);
    if (!entry) return;

    delete_entry(*dict, entry);
}

void dict_del(struct dict **dict) {
    struct dict *entry, *tmp;
    HASH_ITER(hh, *dict, entry, tmp) {
        delete_entry(*dict, entry);
    }
}
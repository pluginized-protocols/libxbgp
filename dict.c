//
// Created by thomas on 27/07/21.
//

#include "dict.h"
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>

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

void *dict_add(struct dict **dict, const char *key, size_t len_key, void *data, size_t data_len) {
    struct dict *entry;

    HASH_FIND_STR(*dict, key, entry);
    if (entry) return NULL; /* key already used */

#define MAX_STR_DEVIATION 3
    if (strnlen(key, len_key + MAX_STR_DEVIATION) != len_key) {
        return NULL;
    }

    entry = new_dict_entry(key, len_key, data, data_len);
    if (!entry) return NULL;

    HASH_ADD_KEYPTR(hh, *dict, entry->key, entry->len.len_key, entry);
    return entry->data;
}


// http://www.concentric.net/~Ttwang/tech/inthash.htm
static unsigned long mix(unsigned long a, unsigned long b, unsigned long c) {
    a = a - b;
    a = a - c;
    a = a ^ (c >> 13);
    b = b - c;
    b = b - a;
    b = b ^ (a << 8);
    c = c - a;
    c = c - b;
    c = c ^ (b >> 13);
    a = a - b;
    a = a - c;
    a = a ^ (c >> 12);
    b = b - c;
    b = b - a;
    b = b ^ (a << 16);
    c = c - a;
    c = c - b;
    c = c ^ (b >> 5);
    a = a - b;
    a = a - c;
    a = a ^ (c >> 3);
    b = b - c;
    b = b - a;
    b = b ^ (a << 10);
    c = c - a;
    c = c - b;
    c = c ^ (b >> 15);
    return c;
}

static inline void rd_init(void) {
    static int init = 0;
    unsigned long seed;

    if (init) return;
    char state[256];
    memset(state, 0, sizeof(state));

    seed = mix(clock(), time(NULL), getpid());
    initstate(seed, state, sizeof(state));
    init = 1;
}


#define itostr(i, str, str_len) ({                    \
    char *ret__ = NULL;                               \
    typeof(str_len) ss__;                                         \
    memset(str, 0, str_len);                          \
    ss__ = snprintf(str, (str_len) - 1, "%u", i);     \
    if (ss__ < (str_len)-1) {                         \
        ret__ = str;                                  \
    }                                                 \
    ret__;                                            \
})


void *dict_add_key_int(struct dict **dict, unsigned int key, void *data, size_t data_len) {
#define MAX_INT_STR 12
    char str_int[MAX_INT_STR];
    memset(str_int, 0, sizeof(str_int));

    if (itostr(key, str_int, sizeof(str_int)) == NULL) {
        return NULL;
    }

    return dict_add(dict, str_int, sizeof(str_int), data, data_len);
}

void *dict_get(dict_t *dict, const char *key) {
    struct dict *entry;

    HASH_FIND_STR(*dict, key, entry);
    if (!entry) return NULL;

    return entry->data;
}

void *dict_get_by_int(dict_t *dict, unsigned int key) {
    char str_int[MAX_INT_STR];
    memset(str_int, 0, sizeof(str_int));

    if (itostr(key, str_int, sizeof(str_int)) == NULL) {
        return NULL;
    }

    return dict_get(dict, str_int);
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

void dict_entry_del_key_int(struct dict **dict, unsigned int key) {
    char str_int[MAX_INT_STR];
    memset(str_int, 0, sizeof(str_int));

    if (itostr(key, str_int, sizeof(str_int)) == NULL) {
        return;
    }
    return dict_entry_del(dict, str_int);
}

void dict_del(struct dict **dict) {
    struct dict *entry, *tmp;
    HASH_ITER(hh, *dict, entry, tmp) {
        delete_entry(*dict, entry);
    }
}
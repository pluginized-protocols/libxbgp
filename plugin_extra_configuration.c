//
// Created by thomas on 28/05/20.
//

#include <json-c/json_object_iterator.h>
#include "plugin_extra_configuration.h"
#include "ubpf_memory_pool.h"
#include "include/global_info_str.h"
#include <string.h>
#include <json-c/json.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <limits.h>

struct conf_arg *global_conf = NULL;


const char *type_arg_char_key = "type_arg";
const char *arg_char_key = "arg";

struct json_conf_parse {
    const char *str;
    enum type_val val_id;
    size_t len_str;

    int (*parser)(json_object *, struct conf_val *);

    int (*delete)(struct conf_val *);

    int (*copy)(struct global_info *info, void *buf, size_t len_buf);
};

#define null_json_conf_parse {.val_id = 0, .str = NULL, .len_str = 0, .parser = NULL, .delete = NULL, .copy = NULL}

struct json_conf_parse val_parsers[] = {
        [conf_val_type_int] = {.val_id = conf_val_type_int, .str = "int", .len_str = 3, .parser = extra_conf_parse_int, .delete = extra_conf_parse_delete_int, .copy = extra_conf_copy_int},
        [conf_val_type_double] = {.val_id = conf_val_type_double, .str = "float", .len_str = 5, .parser = extra_conf_parse_float, .delete = extra_conf_parse_delete_float, .copy = extra_conf_copy_float},
        [conf_val_type_ipv4] = {.val_id = conf_val_type_ipv4, .str = "ipv4", .len_str = 4, .parser = extra_conf_parse_ip4, .delete = extra_conf_parse_delete_ip4, .copy = extra_conf_copy_ip4},
        [conf_val_type_ipv6] = {.val_id = conf_val_type_ipv6, .str = "ipv6", .len_str = 4, .parser = extra_conf_parse_ip6, .delete = extra_conf_parse_delete_ip6, .copy = extra_conf_copy_ip6},
        [conf_val_type_ipv4_prefix] = {.val_id = conf_val_type_ipv4_prefix, .str = "ipv4_prefix", .len_str = 11, .parser = extra_conf_parse_ip4_prefix, .delete = extra_conf_parse_delete_ip4_prefix, .copy = extra_conf_copy_ip4_prefix},
        [conf_val_type_ipv6_prefix] = {.val_id = conf_val_type_ipv6_prefix, .str = "ipv6_prefix", .len_str = 11, .parser = extra_conf_parse_ip6_prefix, .delete = extra_conf_parse_delete_ip6_prefix, .copy = extra_conf_copy_ip6_prefix},
        [conf_val_type_string] = {.val_id = conf_val_type_string, .str = "str", .len_str = 3, .parser = extra_conf_parse_str, .delete = extra_conf_parse_delete_str, .copy = extra_conf_copy_str},
        [conf_val_type_list] = {.val_id = conf_val_type_list, .str = "list", .len_str = 4, .parser = extra_conf_parse_list, .delete = extra_conf_parse_delete_list, .copy = error_cpy},
        [conf_val_type_dict] = {.val_id = conf_val_type_dict, .str = "dict", .len_str = 4, .parser = extra_conf_parse_dict, .delete = extra_conf_delete_dict, .copy = error_cpy},
        [conf_val_type_max] = null_json_conf_parse,
};

static struct conf_arg *new_conf_arg(const char *key, size_t len_key) {
    struct conf_arg *arg;
    arg = calloc(1, sizeof(*arg) + len_key + 1);
    if (!arg) return NULL;

    arg->len_key = len_key;
    memcpy(arg->key, key, len_key);

    arg->val = malloc(sizeof(struct conf_val));

    if (!arg->val) {
        free(arg);
        return NULL;
    }

    return arg;
}

int delete_conf_arg(const char *key) {
    struct conf_arg *the_arg;

    HASH_FIND_STR(global_conf, key, the_arg);
    if (!the_arg) return -1; // not found

    delete_current_info(the_arg->val);
    free(the_arg);
    return 0;
}

int delete_all() {
    if (!global_conf) return 0;
    struct conf_arg *curr_arg, *tmp;
    HASH_ITER(hh, global_conf, curr_arg, tmp) {
        HASH_DEL(global_conf, curr_arg);
        delete_current_info(curr_arg->val);
        free(curr_arg);
    }

    global_conf = NULL;
    return 0;
}

struct conf_val *get_extra_from_key(const char *key) {
    struct conf_arg *the_arg;
    HASH_FIND_STR(global_conf, key, the_arg);

    if (!the_arg) return NULL;

    return the_arg->val;
}

int get_global_info(const char *key, struct global_info *info) {

    struct conf_arg *the_arg;
    HASH_FIND_STR(global_conf, key, the_arg);

    if (!the_arg) return -1;

    info->type = the_arg->val->type;
    info->hidden_ptr = the_arg->val;

    return 0;
}

int get_info_lst_idx(struct global_info *info, int array_idx, struct global_info *value) {

    struct conf_val *val;

    if (info->type != conf_val_type_list) return -1;

    val = info->hidden_ptr;

    if (array_idx >= val->val.lst.len) return -1;

    value->type = val->val.lst.array[array_idx]->type;
    value->hidden_ptr = val->val.lst.array[array_idx];
    return 0;
}

int get_info_dict(struct global_info *info, const char *key, struct global_info *value) {

    struct conf_val *val;
    dict *curr_dict;
    if (info->type != conf_val_type_dict) return -1;

    val = info->hidden_ptr;

    HASH_FIND_STR(val->val.dict, key, curr_dict);
    if (!curr_dict) return -1;

    value->type = curr_dict->val->type;
    value->hidden_ptr = curr_dict->val;
    return 0;
}

int extra_info_copy_data(struct global_info *info, void *buf, size_t len) {

    if (info->type == conf_val_type_list) return -1; // not here

    if (info->type >= conf_val_type_max) return -1;

    return val_parsers[info->type].copy(info, buf, len);
}

#define MAX(a, b) ((a) > (b) ? (a) : (b))

static int parse_current_info(const char *type, size_t len, json_object *value, struct conf_val *val) {
    int i;
    for (i = 0; i < conf_val_type_max; i++) {
        if (strncmp(type, val_parsers[i].str, MAX(val_parsers[i].len_str, len)) == 0) {
            if (val_parsers[i].parser(value, val) != 0) return -1;
            return 0;
        }
    }

    return -1;
}

inline int delete_current_info(struct conf_val *val) {

    if (0 > val->type || val->type >= conf_val_type_max) return -1;

    return val_parsers[val->type].delete(val);

}

int extra_conf_parse_int(json_object *value, struct conf_val *val) {

    uint64_t my_int;
    my_int = json_object_get_int64(value);

    val->val.int_val = my_int;
    val->type = conf_val_type_int;

    return 0;
}

int extra_conf_parse_float(json_object *value, struct conf_val *val) {

    double my_double;
    my_double = json_object_get_double(value);

    val->val.dbl_val = my_double;
    val->type = conf_val_type_double;

    return 0;
}

int extra_conf_parse_str(json_object *value, struct conf_val *val) {

    int len;
    const char *my_char;
    char *cpy_str;
    my_char = json_object_get_string(value);
    len = json_object_get_string_len(value);

    cpy_str = calloc(len + 1, sizeof(char));
    strncpy(cpy_str, my_char, len);

    val->val.string.len = len;
    val->val.string.str = cpy_str;
    val->type = conf_val_type_string;

    return 0;
}

int extra_conf_parse_ip4(json_object *value, struct conf_val *val) {
    //int len;
    const char *my_cpy;
    my_cpy = json_object_get_string(value);
    //len = json_object_get_string_len(value);

    if (inet_pton(AF_INET, my_cpy, &val->val.ip4) == 0) {
        return -1;
    }
    val->type = conf_val_type_ipv4;
    return 0;
}

int extra_conf_parse_ip6(json_object *value, struct conf_val *val) {
    //int len;
    const char *my_cpy;
    my_cpy = json_object_get_string(value);
    //len = json_object_get_string_len(value);

    if (inet_pton(AF_INET6, my_cpy, &val->val.ip6) == 0) {
        return -1;
    }
    val->type = conf_val_type_ipv6;

    return 0;
}

static inline int extra_conf_parse_ip_prefix(json_object *value, struct conf_val *val, int is_v6) {

    int family;
    //int len;
    long prefix_len;
    const char *my_str_pfx;
    char cpy_string[MAX_STR_BUF_PFX];
    char *token;
    char *endptr;
    my_str_pfx = json_object_get_string(value);
    //len = json_object_get_string_len(value);

    memset(cpy_string, 0, sizeof(char) * MAX_STR_BUF_PFX);
    strncpy(cpy_string, my_str_pfx, MAX_STR_BUF_PFX - 1);

    family = is_v6 ? AF_INET6 : AF_INET;


    token = strtok(cpy_string, "/");
    if (!token) return -1;

    /* gneuhgneuhgneuh not POSIX return value............ */
    if (!inet_pton(family, token, is_v6 ? (void *) &val->val.ip6_pfx.p : &val->val.ip4_pfx.p)) {
        return -1;
    }

    token = strtok(0, "/");
    if (!token) {
        return -1;
    }

    prefix_len = strtol(token, &endptr, 10);

    if (endptr && *endptr != '\0')
        return -1;

    if (is_v6) {
        if (0 > prefix_len || prefix_len > 128) return -1;
    } else if (0 > prefix_len || prefix_len > 32) return -1;

    val->val.ip4_pfx.prefix_len = (int) prefix_len;
    val->val.ip4_pfx.family = family;
    return 0;
}

int extra_conf_parse_ip4_prefix(json_object *value, struct conf_val *val) {
    val->type = conf_val_type_ipv4_prefix;
    return extra_conf_parse_ip_prefix(value, val, 0);
}

int extra_conf_parse_ip6_prefix(json_object *value, struct conf_val *val) {
    val->type = conf_val_type_ipv6_prefix;
    return extra_conf_parse_ip_prefix(value, val, 1);
}


int extra_conf_parse_list(json_object *value, struct conf_val *val) {

    size_t i;
    struct array_list *lst;
    size_t len;
    json_object *array_val;
    struct conf_val *curr_elem_lst;

    const char *nested_type_value;
    int nested_type_value_len;
    json_object *nested_type_value_json;
    json_object *nested_value;

    lst = json_object_get_array(value);
    len = json_object_array_length(value);

    val->type = conf_val_type_list;
    val->val.lst.len = len;
    val->val.lst.array = malloc(sizeof(struct conf_val *) * len); // constant time access ...
    if (!val->val.lst.array) return -1;

    for (i = 0; i < len; i++) {
        array_val = array_list_get_idx(lst, i);

        if (!json_object_object_get_ex(array_val, type_arg_char_key, &nested_type_value_json)) return -1;

        if (!json_object_object_get_ex(array_val, arg_char_key, &nested_value)) return -1;

        nested_type_value = json_object_get_string(nested_type_value_json);
        nested_type_value_len = json_object_get_string_len(nested_type_value_json);

        curr_elem_lst = malloc(sizeof(*curr_elem_lst));
        if (!curr_elem_lst) return -1;
        if (parse_current_info(nested_type_value, nested_type_value_len, nested_value, curr_elem_lst) ==
            -1)
            return -1;

        val->val.lst.array[i] = curr_elem_lst; // append to the list
    }

    return 0;
}

int extra_conf_parse_dict(json_object *value, struct conf_val *val) {

    val->type = conf_val_type_dict;
    val->val.dict = NULL;

    const char *current_key;
    size_t key_len;
    struct json_object *current_val;
    struct json_object_iterator it_value_info;
    struct json_object_iterator it_value_info_end;

    json_object *nested_val_type;
    json_object *nested_val;
    const char *type_nested_val;
    int type_nested_val_len;

    dict *new_hash;

    it_value_info_end = json_object_iter_end(value);

    for (it_value_info = json_object_iter_begin(value);
         !json_object_iter_equal(&it_value_info, &it_value_info_end);
         json_object_iter_next(&it_value_info)) {


        current_key = json_object_iter_peek_name(&it_value_info);
        current_val = json_object_iter_peek_value(&it_value_info);
        key_len = strnlen(current_key, NAME_MAX);

        if (!json_object_object_get_ex(current_val, type_arg_char_key, &nested_val_type)) return -1;
        if (!json_object_object_get_ex(current_val, arg_char_key, &nested_val)) return -1;

        type_nested_val = json_object_get_string(nested_val_type);
        type_nested_val_len = json_object_get_string_len(nested_val_type);

        new_hash = new_conf_arg(current_key, key_len);
        if (!new_hash) return -1;

        HASH_ADD_STR(val->val.dict, key, new_hash);

        if (parse_current_info(type_nested_val, type_nested_val_len, nested_val, new_hash->val) != 0) return -1;
    }
    return 0;
}


int extra_conf_parse_delete_int(struct conf_val *val) {
    if (val->type != conf_val_type_int) return -1;
    free(val);
    return 0;
}

int extra_conf_parse_delete_float(struct conf_val *val) {
    if (val->type != conf_val_type_double) return -1;
    free(val);
    return 0;
}

int extra_conf_parse_delete_ip4(struct conf_val *val) {
    if (val->type != conf_val_type_ipv4) return -1;
    free(val);
    return 0;
}

int extra_conf_parse_delete_ip4_prefix(struct conf_val *val) {
    if (val->type != conf_val_type_ipv4_prefix) return -1;
    free(val);
    return 0;
}

int extra_conf_parse_delete_ip6_prefix(struct conf_val *val) {
    if (val->type != conf_val_type_ipv6_prefix) return -1;
    free(val);
    return 0;
}

int extra_conf_parse_delete_ip6(struct conf_val *val) {
    if (val->type != conf_val_type_ipv6) return -1;
    free(val);
    return 0;
}

int extra_conf_parse_delete_str(struct conf_val *val) {
    if (val->type != conf_val_type_string) return -1;
    free(val->val.string.str);
    free(val);
    return 0;
}

int extra_conf_parse_delete_list(struct conf_val *val) {

    struct conf_val *lst_elem;
    int i;

    if (val->type != conf_val_type_list) return -1;

    for (i = 0; i < val->val.lst.len; i++) {
        lst_elem = val->val.lst.array[i];
        delete_current_info(lst_elem);
        // free(lst_elem);
    }
    free(val->val.lst.array);
    free(val);
    return 0;
}

int extra_conf_delete_dict(struct conf_val *val) {

    if (val->type != conf_val_type_dict) return -1;

    dict *curr_arg, *tmp;

    HASH_ITER(hh, val->val.dict, curr_arg, tmp) {
        HASH_DEL(val->val.dict, curr_arg);
        delete_current_info(curr_arg->val);
        free(curr_arg);
    }
    return 0;
}

int extra_conf_copy_int(struct global_info *info, void *buf, size_t len) {

    struct conf_val *val;

    if (info->type != conf_val_type_int) return -1;
    if (len < sizeof(uint64_t)) return -1;

    val = info->hidden_ptr;

    memcpy(buf, &val->val.int_val, sizeof(uint64_t));
    return 0;
}

int extra_conf_copy_float(struct global_info *info, void *buf, size_t len) {
    struct conf_val *val = info->hidden_ptr;
    if (val->type != conf_val_type_double) return -1;
    if (len < sizeof(double)) return -1;


    memcpy(buf, &val->val.dbl_val, sizeof(double));
    return 0;
}

int extra_conf_copy_ip4(struct global_info *info, void *buf, size_t len) {
    struct conf_val *val = info->hidden_ptr;
    if (val->type != conf_val_type_ipv4) return -1;
    if (len < sizeof(struct in_addr)) return -1;

    memcpy(buf, &val->val.ip4, sizeof(struct in_addr));
    return 0;
}

int extra_conf_copy_ip6(struct global_info *info, void *buf, size_t len) {
    struct conf_val *val = info->hidden_ptr;
    if (val->type != conf_val_type_ipv6) return -1;
    if (len < sizeof(struct in6_addr)) return -1;

    memcpy(buf, &val->val.ip6, sizeof(struct in6_addr));
    return 0;
}

int extra_conf_copy_ip4_prefix(struct global_info *info, void *buf, size_t len) {
    struct conf_val *val = info->hidden_ptr;
    if (val->type != conf_val_type_ipv4_prefix) return -1;
    if (len < sizeof(struct prefix_ip4)) return -1;

    memcpy(buf, &val->val.ip4_pfx, sizeof(struct prefix_ip4));
    return 0;
}

int extra_conf_copy_ip6_prefix(struct global_info *info, void *buf, size_t len) {
    struct conf_val *val = info->hidden_ptr;
    if (val->type != conf_val_type_ipv6_prefix) return -1;
    if (len < sizeof(struct prefix_ip6)) return -1;

    memcpy(buf, &val->val.ip6_pfx, sizeof(struct prefix_ip6));
    return 0;
}

int extra_conf_copy_str(struct global_info *info, void *buf, size_t len) {
    struct conf_val *val = info->hidden_ptr;
    if (val->type != conf_val_type_string) return -1;
    if (len < val->val.string.len + 1) return -1;

    memcpy(buf, val->val.string.str, val->val.string.len);
    ((char *) buf)[val->val.string.len] = 0;
    return 0;
}

int extra_info_from_json(const char *path, const char *key) {
    json_object *tmp, *tmp2;
    tmp = json_object_from_file(path);
    if (!tmp) return -1;

    if (key) {
        if (!json_object_object_get_ex(tmp, key, &tmp2)) {
            return -1;
        }
        if (json_parse_extra_info(tmp2) != 0) return -1;
    } else {
        if (json_parse_extra_info(tmp) != 0) return -1;
    }

    if (!json_object_put(tmp)) return -1;

    return 0;
}

int json_parse_extra_info(json_object *manifest) {

    if (!manifest) return -1;

    const char *current_key;
    struct json_object *current_val;

    struct json_object *type_arg;
    struct json_object *arg;
    const char *type_arg_str;
    int type_arg_str_len;

    struct json_object_iterator it_value_info;
    struct json_object_iterator it_value_info_end;


    it_value_info_end = json_object_iter_end(manifest);


    int len_str_key;
    struct conf_arg *new_arg;

    for (it_value_info = json_object_iter_begin(manifest);
         !json_object_iter_equal(&it_value_info, &it_value_info_end);
         json_object_iter_next(&it_value_info)) {

        current_key = json_object_iter_peek_name(&it_value_info);
        current_val = json_object_iter_peek_value(&it_value_info);

        if (!json_object_object_get_ex(current_val, type_arg_char_key, &type_arg)) {
            return -1;
        }

        if (!json_object_object_get_ex(current_val, arg_char_key, &arg)) {
            return -1;
        }

        len_str_key = strnlen(current_key, 256) + 1;

        if (len_str_key == 257) {
            fprintf(stderr, "Too long key\n");
            return -1;
        }

        new_arg = new_conf_arg(current_key, len_str_key);
        if (!new_arg) return -1;
        HASH_ADD_STR(global_conf, key, new_arg);

        type_arg_str = json_object_get_string(type_arg);
        type_arg_str_len = json_object_get_string_len(type_arg);

        if (parse_current_info(type_arg_str, type_arg_str_len, arg, new_arg->val) != 0) return -1;

    }

    return 0;
}

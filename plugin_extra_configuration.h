//
// Created by thomas on 28/05/20.
//

#ifndef UBPF_TOOLS_PLUGIN_EXTRA_CONFIGURATION_H
#define UBPF_TOOLS_PLUGIN_EXTRA_CONFIGURATION_H

#include <json-c/json_object.h>
#include <netinet/in.h>
#include <include/ubpf_prefix.h>
#include <include/global_info_str.h>
#include "uthash.h"
#include "utlist.h"

enum type_val {
    conf_val_type_int = 0,
    conf_val_type_double,
    conf_val_type_ipv4,
    conf_val_type_ipv6,
    conf_val_type_ipv4_prefix,
    conf_val_type_ipv6_prefix,
    conf_val_type_list,
    conf_val_type_string,
    conf_val_type_max,
};

/*struct conf_lst {
    struct conf_val *cf_val;
    struct conf_lst *next, *prev;
};*/

struct conf_val {

    int type;

    union {
        struct prefix_ip4 ip4_pfx;
        struct prefix_ip6 ip6_pfx;
        struct in_addr ip4;
        struct in6_addr ip6;
        uint64_t int_val;
        double dbl_val;
        struct {
            size_t len;
            char *str;
        } string;
        struct {
            size_t len;
            struct conf_val **array;
        } lst;
    } val;

};

struct conf_arg {
    UT_hash_handle hh;

    struct conf_val *val;
    size_t len_key;
    char key[0];
};

int extra_info_from_json(const char *path, const char *key);

int json_parse_extra_info(json_object *manifest);

struct conf_val *get_extra_from_key(const char *key);

int get_global_info(const char *key, struct global_info *info);

int get_info_lst_idx(struct global_info *info, int array_idx, struct global_info *value);

int extra_info_copy_data(struct global_info *info, void *buf, size_t len);

int extra_info_copy_data_lst_idx(const char *key, int arr_idx, void *buf, size_t len);

int delete_conf_arg(const char *key);

int delete_all(void);

int extra_conf_parse_int(json_object *value, struct conf_val *val);

int extra_conf_parse_float(json_object *value, struct conf_val *val);

int extra_conf_parse_ip4(json_object *value, struct conf_val *val);

int extra_conf_parse_ip6(json_object *value, struct conf_val *val);

int extra_conf_parse_ip4_prefix(json_object *value, struct conf_val *val);

int extra_conf_parse_ip6_prefix(json_object *value, struct conf_val *val);

int extra_conf_parse_str(json_object *value, struct conf_val *val);

int extra_conf_parse_list(json_object *value, struct conf_val *val);

int delete_current_info(struct conf_val *val);

int extra_conf_parse_delete_int(struct conf_val *val);

int extra_conf_parse_delete_float(struct conf_val *val);

int extra_conf_parse_delete_ip4(struct conf_val *val);

int extra_conf_parse_delete_ip6(struct conf_val *val);

int extra_conf_parse_delete_ip4_prefix(struct conf_val *val);

int extra_conf_parse_delete_ip6_prefix(struct conf_val *val);

int extra_conf_parse_delete_str(struct conf_val *val);

int extra_conf_parse_delete_list(struct conf_val *val);

int extra_conf_copy_int(struct global_info *info, void *buf, size_t len);

int extra_conf_copy_float(struct global_info *info, void *buf, size_t len);

int extra_conf_copy_ip4(struct global_info *info, void *buf, size_t len);

int extra_conf_copy_ip6(struct global_info *info, void *buf, size_t len);

int extra_conf_copy_ip4_prefix(struct global_info *info, void *buf, size_t len);

int extra_conf_copy_ip6_prefix(struct global_info *info, void *buf, size_t len);

int extra_conf_copy_str(struct global_info *info, void *buf, size_t len);

static inline int error_cpy(struct global_info *val, void *buf, size_t len) {
    return -1;
}

#endif //UBPF_TOOLS_PLUGIN_EXTRA_CONFIGURATION_H

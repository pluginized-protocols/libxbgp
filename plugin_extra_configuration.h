//
// Created by thomas on 28/05/20.
//

#ifndef UBPF_TOOLS_PLUGIN_EXTRA_CONFIGURATION_H
#define UBPF_TOOLS_PLUGIN_EXTRA_CONFIGURATION_H

#include <json-c/json_object.h>
#include <netinet/in.h>
#include <include/prefix.h>
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

struct conf_lst {
    struct conf_val *cf_val;
    struct conf_lst *next, *prev;
};

struct conf_val {

    int type;

    union {
        struct prefix_ip4 ip4_pfx;
        struct prefix_ip6 ip6_pfx;
        struct in_addr ip4;
        struct in6_addr ip6;
        uint64_t int_val;
        double dbl_val;
        char *string;
        struct conf_lst *lst;
    } val;

};

struct conf_arg {
    UT_hash_handle hh;

    struct conf_val *val;
    size_t len_key;
    char key[0];
};

int extra_info_from_json(const char *path, json_object **manifest, const char *key);

int json_parse_extra_info(json_object *manifest);

struct conf_val *get_extra_from_key(const char *key);

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

#endif //UBPF_TOOLS_PLUGIN_EXTRA_CONFIGURATION_H

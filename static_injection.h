//
// Created by thomas on 1/07/20.
//

#ifndef UBPF_TOOLS_STATIC_INJECTION_H
#define UBPF_TOOLS_STATIC_INJECTION_H

#include <include/ebpf_mod_struct.h>
#include <linux/limits.h>
#include "insertion_point.h"
#include "utlist.h"
#include "uthash.h"

// 256 MiB
#define MAX_MEM_PARSE 268435456

struct insertion_point_parser {
    struct insertion_point_parser *next;
    struct insertion_point_parser *prev;

    size_t name_insertion_len;
    const char *name_insertion;
    int insertion_point_id;

    const char *pluglet_name;
    size_t pluglet_name_len;

    anchor_t anchor;
    int seq;
};


struct job_plugin_parser {
    unsigned long long int schedule;
    struct insertion_point_parser *parser;
};

struct obj_code_list_parser {
    UT_hash_handle hh;

    int jit;
    int permissions;
    int add_memchecks;

    size_t path_len;
    char path_code[PATH_MAX];

    size_t name_len;
    char name[0];
};

struct global_opts_parser {
    int extra_mem;
    int shared_mem;
    int jit_all;
    char pluglet_dir[PATH_MAX];
    size_t plugin_name_len;
    char plugin_name[NAME_MAX];
};


int str_to_id_insertion_point(insertion_point_info_t *info, const char *str, size_t len);

int str_anchor_to_enum(const char *anchor_str, anchor_t *anchor);

int load_extension_code(const char *path, const char *extension_code_dir, proto_ext_fun_t *api_proto,
                        insertion_point_info_t *points_info);

#endif //UBPF_TOOLS_STATIC_INJECTION_H

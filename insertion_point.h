//
// Created by thomas on 30/06/20.
//

#ifndef UBPF_TOOLS_INSERTION_POINT_H
#define UBPF_TOOLS_INSERTION_POINT_H

#include <include/plugin_arguments.h>
#include <include/context_hdr.h>
#include "tree.h"
#include "uthash.h"

#define MAX_INSERTION_POINTS 128

typedef struct insertion_point insertion_point_t;
typedef struct vm_container vm_container_t;

typedef enum BPF_PLUGIN_TYPE {
    BPF_UNKNOWN = 0,
    BPF_PRE,
    BPF_POST,
    BPF_REPLACE,
} anchor_t;

struct insertion_point_entry {
    insertion_point_t *point; //back pointer to the insertion point structure
    vm_container_t *vm; //back pointer to the VM struct
    anchor_t anchor;
    int seq;
};

struct insertion_point {

    UT_hash_handle hh;

    int id;

    vm_container_t *pre_vms;
    vm_container_t *post_vms;

    struct {
        int nb;
        vm_container_t *replace_vms;
    } replace;

    //int fallback_request;

    size_t name_len;
    char name[0];

    //struct plugin *new_transaction;

};

struct insertion_point_iterator {

    int idx_table;
    vm_container_t *tables[3];
    vm_container_t *current_vm;
};

int insertion_point_vm_iterator(insertion_point_t *point, struct insertion_point_iterator *it);

vm_container_t *insertion_point_vm_iterator_next(struct insertion_point_iterator *it);

int insertion_point_vm_iterator_hasnext(struct insertion_point_iterator *it);


insertion_point_t *new_insertion_point(int id, const char *name, size_t name_len);

int free_insertion_point(insertion_point_t *point);

int flush_insertion_points(insertion_point_t **hash_table);

int run_pre_functions(insertion_point_t *p, args_t *args, uint64_t *ret);

int run_post_functions(insertion_point_t *p, args_t *args, uint64_t *ret);

int run_replace_function(insertion_point_t *p, args_t *args, uint64_t *ret);

int run_replace_next_replace_function(context_t *ctx);

int
add_vm_insertion_point(insertion_point_t *point, vm_container_t *vm, anchor_t anchor, int seq);

int add_pre_vm(insertion_point_t *point, vm_container_t *vm, int seq);

int add_replace_vm(insertion_point_t *point, vm_container_t *vm, int seq);

int add_post_vm(insertion_point_t *point, vm_container_t *vm, int seq);

int rm_vm_insertion_point(vm_container_t *vm);

struct insertion_point_entry *
new_insertion_point_entry(anchor_t anchor, int seq, insertion_point_t *point, vm_container_t *vm);

int free_insertion_point_entry(struct insertion_point_entry *entry);

#endif //UBPF_TOOLS_INSERTION_POINT_H

//
// Created by thomas on 30/06/20.
//

#include <stdio.h>
#include "insertion_point.h"
#include "bpf_plugin.h"
#include "tools_ubpf_api.h"
#include "ubpf_manager.h"

static inline int cmp_seq(vm_container_t *a, vm_container_t *b) {
    return a->pop->seq - b->pop->seq;
}

insertion_point_t *new_insertion_point(int id, const char *name, size_t name_len) {
    insertion_point_t *point = calloc(1, sizeof(insertion_point_t) + ((name_len + 1) * sizeof(char)));
    if (!point) return NULL;

    point->id = id;
    point->name_len = name_len;

    strncpy(point->name, name, name_len);
    point->name[name_len] = 0;

    point->pre_vms = NULL;
    point->post_vms = NULL;
    point->pre_vms = NULL;

    point->replace.nb = 0;
    point->replace.replace_vms = NULL;

    return point;
}

struct insertion_point_entry *
new_insertion_point_entry(anchor_t anchor, int seq, insertion_point_t *point, vm_container_t *vm) {

    struct insertion_point_entry *point_entry;

    point_entry = malloc(sizeof(*point));
    if (!point_entry) return NULL;

    point_entry->vm = vm;
    point_entry->seq = seq;
    point_entry->anchor = anchor;
    point_entry->point = point;
    return point_entry;
}

int free_insertion_point_entry(struct insertion_point_entry *entry) {
    free(entry);
    return 0;
}

int flush_insertion_points(insertion_point_t **hash_table) {
    insertion_point_t *point, *tmp;

    HASH_ITER(hh, *hash_table, point, tmp) {
        HASH_DEL(*hash_table, point);
        free_insertion_point(point);
    }

    return 0;
}

int free_insertion_point(insertion_point_t *point) {
    int i;
    int size;
    vm_container_t *curr_vm, *tmp;
    vm_container_t *hash_tables[] = {point->pre_vms, point->post_vms, point->replace.replace_vms};

    size = sizeof(hash_tables) / sizeof(hash_tables[0]);

    for (i = 0; i < size; i++) {
        HASH_ITER(hh_insertion_point, hash_tables[i], curr_vm, tmp) {
            HASH_DELETE(hh_insertion_point, hash_tables[i], curr_vm);

            // remove vm from plugin and shutdown
            if (plugin_delete_vm(curr_vm) != 0) {
                return -1;
            }
            shutdown_vm(curr_vm);
        }
    }

    free(point);
    return 0;
}

inline int
add_vm_insertion_point(insertion_point_t *point, vm_container_t *vm, anchor_t anchor, int seq) {

    vm_container_t *entry_table, *check;

    switch (anchor) {
        case BPF_PRE:
            entry_table = point->pre_vms;
            break;
        case BPF_POST:
            entry_table = point->post_vms;
            break;
        case BPF_REPLACE:
            entry_table = point->replace.replace_vms;
            break;
        default:
            return -1;
    }

    HASH_FIND(hh_insertion_point, entry_table, vm->vm_name, vm->vm_name_len, check);

    if (check) {
        return -1;
        // vm already in the insertion point
    } else {
        vm->pop->point = point;
        vm->pop->anchor = anchor;
        vm->pop->vm = vm;
        vm->pop->seq = seq;
    }

    HASH_ADD_INORDER(hh_insertion_point, entry_table, vm_name, vm->vm_name_len, vm, cmp_seq);

    switch (anchor) {
        case BPF_PRE:
            point->pre_vms = entry_table;
            break;
        case BPF_POST:
            point->post_vms = entry_table;
            break;
        case BPF_REPLACE:
            point->replace.nb++;
            point->replace.replace_vms = entry_table;
            break;
        default:
            return -1;
    }
    return 0;
}

int add_pre_vm(insertion_point_t *point, vm_container_t *vm, int seq) {
    return add_vm_insertion_point(point, vm, BPF_PRE, seq);
}

int add_replace_vm(insertion_point_t *point, vm_container_t *vm, int seq) {
    return add_vm_insertion_point(point, vm, BPF_REPLACE, seq);
}

int add_post_vm(insertion_point_t *point, vm_container_t *vm, int seq) {
    return add_vm_insertion_point(point, vm, BPF_POST, seq);
}

static inline int
run_insertion_point(insertion_point_t *point, args_t *args, int type, uint64_t *ret) {

    vm_container_t *curr_vm, *tmp;
    vm_container_t *entry_table;
    int exec_ok;

    switch (type) {
        case BPF_REPLACE:
            entry_table = point->replace.replace_vms;
            if (entry_table) {
                entry_table->ctx->args = args; /* set args */
                exec_ok = run_injected_code(entry_table, ret);
                entry_table->ctx->args = NULL; /* unset args */
                return exec_ok;
            }
            return -1;
        case BPF_PRE:
            entry_table = point->pre_vms;
            break;
        case BPF_POST:
            entry_table = point->post_vms;
            break;
        default:
            return -1;
    }

    if (entry_table) {
        HASH_ITER(hh_insertion_point, entry_table, curr_vm, tmp) {

            curr_vm->ctx->args = args; /* set args */
            exec_ok = run_injected_code(curr_vm, ret);
            curr_vm->ctx->args = NULL; /* unset args */

            if (exec_ok != 0) return -1;
        }
    }

    return 0;
}


int run_pre_functions(insertion_point_t *p, args_t *args, uint64_t *ret) {
    if (!p) return -1;
    return run_insertion_point(p, args, BPF_PRE, ret);
}

int run_post_functions(insertion_point_t *p, args_t *args, uint64_t *ret) {
    if (!p) return -1;
    return run_insertion_point(p, args, BPF_POST, ret);
}

int run_replace_function(insertion_point_t *p, args_t *args, uint64_t *ret) {
    if (!p) return -1;
    return run_insertion_point(p, args, BPF_REPLACE, ret);
}


int run_replace_next_replace_function(context_t *ctx) {
    int return_val;
    insertion_point_t *point;
    vm_container_t *next_vm;

    if (!ctx) return -1;
    if (ctx->pop->anchor != BPF_REPLACE) return -1;

    point = ctx->pop->point;

    if (!point) return -1;

    next_vm = ctx->vm->hh_insertion_point.next;

    if (!next_vm) {
        ctx->fallback = 1;
        return -1;
    }

    // flush all memory taken by the previous call
    mem_reset(&ctx->p->mem.mgr_heap);

    /* set arguments + return value for next replace VM*/
    next_vm->ctx->return_val = ctx->return_val;
    next_vm->ctx->args = ctx->args;
    return_val = run_injected_code(next_vm, ctx->return_val);
    /* propagate context when backtrack */
    ctx->return_value_set = next_vm->ctx->return_value_set;
    ctx->fallback = next_vm->ctx->fallback;

    return return_val;
}

inline int rm_vm_insertion_point(vm_container_t *vm) {

    vm_container_t *vm_to_rm;
    vm_container_t *entry_table;
    insertion_point_t *point = vm->pop->point;

    switch (vm->pop->anchor) {
        case BPF_PRE:
            entry_table = point->pre_vms;
            break;
        case BPF_REPLACE:
            entry_table = point->replace.replace_vms;
            break;
        case BPF_POST:
            entry_table = point->post_vms;
            break;
        default:
            return -1;
    }

    HASH_FIND(hh_insertion_point, entry_table, vm->vm_name, vm->vm_name_len, vm_to_rm);
    if (!vm_to_rm) return -1;

    HASH_DELETE(hh_insertion_point, entry_table, vm_to_rm);

    switch (vm->pop->anchor) {
        case BPF_PRE:
            vm->pop->point->pre_vms = entry_table;
            break;
        case BPF_POST:
            vm->pop->point->post_vms = entry_table;
            break;
        case BPF_REPLACE:
            vm->pop->point->replace.replace_vms = entry_table;
            vm->pop->point->replace.nb--;
            break;
        default:
            return -1;
    }

    return 0;
}


int insertion_point_vm_iterator(insertion_point_t *point, struct insertion_point_iterator *it) {
    int i = 0;
    if (!point) return -1;
    it->idx_table = 0;

    vm_container_t *mich[3] = {
            point->pre_vms,
            point->replace.replace_vms,
            point->post_vms,
    };

    memcpy(it->tables, mich, sizeof(mich));

    while (!mich[i] && i < 3) {
        i++;
    }

    it->current_vm = mich[i];

    return 0;
}

vm_container_t *insertion_point_vm_iterator_next(struct insertion_point_iterator *it) {

    vm_container_t *next_vm = it->current_vm;

    if (next_vm->hh_insertion_point.next) {
        it->current_vm = next_vm->hh_insertion_point.next;
        return next_vm;
    }

    do {
        it->idx_table++;
    } while (!it->tables[it->idx_table] && it->idx_table < 3);

    it->current_vm = it->tables[it->idx_table];
    return next_vm;
}

int insertion_point_vm_iterator_hasnext(struct insertion_point_iterator *it) {
    return it->current_vm != NULL;
}

/*
 int transaction_pre_function(plugin_t *p, const uint8_t *bytecode, size_t len, uint32_t seq, uint8_t jit) {
    if (!p) return -1;
    if (!p->new_transaction) return -1;
    return generic_add_function(p->new_transaction, bytecode, len, seq, BPF_PRE, jit);
}

int transaction_post_function(plugin_t *p, const uint8_t *bytecode, size_t len, uint32_t seq, uint8_t jit) {
    if (!p) return -1;
    if (!p->new_transaction) return -1;
    return generic_add_function(p->new_transaction, bytecode, len, seq, BPF_PRE, jit);
}

int transaction_replace_function(plugin_t *p, const uint8_t *bytecode, size_t len, uint32_t seq, uint8_t jit) {
    if (!p) return -1;
    if (!p->new_transaction) return -1;
    return generic_add_function(p->new_transaction, bytecode, len, seq, BPF_PRE, jit);
}

int init_plugin_transaction(plugin_t *p) {

    plugin_t *new_p;
    if (p->new_transaction) return -1;

    new_p = init_plugin(p->mem.heap.mp.total_mem, p->mem.shared_heap.smp.heap_len, p->plugin_id);

    if (!new_p) return -1;
    return 0;
}

int commit_transaction(plugin_t *p) {

    plugin_t *p_tran;

    if (!p) return -1;
    if (!p->new_transaction) return -1;

    p_tran = p->new_transaction;
    _destroy_plugin(p, 0);

    memcpy(p, p_tran, sizeof(plugin_t));
    p->new_transaction = NULL;

    // free memcpy
    return 0;
}
 */
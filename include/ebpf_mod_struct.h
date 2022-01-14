//
// Created by thomas on 11/05/19.
//

#ifndef FRR_UBPF_EBPF_MOD_STRUCT_H
#define FRR_UBPF_EBPF_MOD_STRUCT_H

#include <stddef.h>
#include <ffi.h>

/* attribute for helper functions */
#define HELPER_ATTR_NONE 0
#define HELPER_ATTR_USR_PTR 1
#define HELPER_ATTR_WRITE 2
#define HELPER_ATTR_READ 4
#define HELPER_ATTR_MASK 7

#define valid_perm_null {.perm_str = NULL, .perm = 0, .len_perm = 0}
#define valid_perm_is_null(a) (((a)->perm_str == NULL) && ((a)->perm = 0) && ((a)->len_perm = 0))

struct perms {
    const char *perm_str;
    int perm;
    size_t len_perm;
};

extern struct perms valid_perms[];


#define valid_perms_len (sizeof(valid_perms)/sizeof(valid_perms[0]))

typedef struct proto_ext_fun {
    void *fn;
    void (*closure_fn) (ffi_cif *, void *ret, void **args, void *ctx);
    const char *name;
    int attributes;

    int args_nb;
    ffi_type *return_type;
    ffi_type **args_type;

} proto_ext_fun_t;

#define TYPE_MSG_MONITOR 1

typedef struct mesg_buffer {
    long mesg_type;
    char mesg_text[20];
} ebpf_message_t;

typedef struct insertion_point_info {
    const char *insertion_point_str;
    int insertion_point_id;
} insertion_point_info_t;

#define insertion_point_info_null {.insertion_point_str = NULL, .insertion_point_id = 0}
#define proto_ext_func_null {.fn = NULL, .name = NULL, .attributes = 0, \
                             .args_type = NULL, .return_type = NULL, \
                             .args_nb = 0, .closure_fn = NULL }

#define proto_ext_func_is_null(a) (((a)->fn == NULL) &&       \
             ((a)->name == NULL) && ((a)->attributes == 0) &&     \
             ((a)->args_nb == 0) && ((a)->args_type == NULL) &&         \
             ((a)->return_type == NULL) && ((a)->closure_fn == NULL))

#define is_insertion_point_info_null(info) (((info)->insertion_point_str == NULL) && ((info)->insertion_point_id == 0))


#endif //FRR_UBPF_EBPF_MOD_STRUCT_H

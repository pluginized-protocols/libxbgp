//
// Created by thomas on 11/05/19.
//

#ifndef FRR_UBPF_EBPF_MOD_STRUCT_H
#define FRR_UBPF_EBPF_MOD_STRUCT_H

#include <stddef.h>
#include <ffi.h>

#include <xbgp_compliant_api/xbgp_common.h>

#define valid_perm_null {.perm_str = NULL, .perm = 0, .len_perm = 0}
#define valid_perm_is_null(a) (((a)->perm_str == NULL) && ((a)->perm = 0) && ((a)->len_perm = 0))

struct perms {
    const char *perm_str;
    int perm;
    size_t len_perm;
};

extern struct perms valid_perms[];

#define valid_perms_len (sizeof(valid_perms)/sizeof(valid_perms[0]))

#define TYPE_MSG_MONITOR 1

typedef struct mesg_buffer {
    long mesg_type;
    char mesg_text[20];
} ebpf_message_t;




#endif //FRR_UBPF_EBPF_MOD_STRUCT_H

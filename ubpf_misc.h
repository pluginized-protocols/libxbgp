//
// Created by thomas on 19/02/19.
//

#ifndef FRR_UBPF_UBPF_MISC_H
#define FRR_UBPF_UBPF_MISC_H

typedef enum error_symbol {
    OK = 0,
    CONN_ERROR,
    MEM_ERROR,
    THREAD_ERROR,
    NOT_INIT_ERROR,
    INSERTION_ERROR,
} ubpf_error_t;

void set_log_file(const char *path);

void ubpf_log(ubpf_error_t error, uint32_t plugin_id, int type, uint32_t seq, const char *extra);

#endif

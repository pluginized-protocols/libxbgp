//
// Created by thomas on 28/11/19.
//


#include <stdint.h>
#include <stdio.h>
#include "ubpf_misc.h"
#include "bpf_plugin.h"
#include "insertion_point.h"
#include <time.h>
#include <string.h>

#define ERROR_STR 200

FILE *log_file = NULL;

char *format_time() {
    time_t raw_time;
    struct tm *time_info;

    time(&raw_time);
    time_info = localtime(&raw_time);

    return asctime(time_info);
}

void set_log_file(const char *path) {
    if (*path == '-') {
        log_file = stderr;
    } else {
        log_file = fopen(path, "a");
        if (log_file == NULL) {
            perror("fopen");
        }
    }

}

void
ubpf_log(ubpf_error_t error, uint32_t plugin_id __attribute__((unused)),
         int type, uint32_t seq __attribute__((unused)),
         __attribute__((unused)) const char *extra) {

    if (log_file == NULL) return;

    int n;
    char error_str[ERROR_STR];
    const char *error_meaning;
    const char *type_str __attribute__((unused));
    memset(error_str, 0, sizeof(char) * ERROR_STR);

    switch (type) {
        case BPF_REPLACE:
            type_str = "replace";
            break;
        case BPF_PRE:
            type_str = "pre";
            break;
        case BPF_POST:
            type_str = "post";
            break;
        default:
            type_str = "???";
    }

    switch (error) {
        case OK:
            error_meaning = "No errors";
            break;
        case CONN_ERROR:
            error_meaning = "Connection to remote server failed";
            break;
        case MEM_ERROR:
            error_meaning = "Unable to allocate memory";
            break;
        case THREAD_ERROR:
            error_meaning = "Internal thread error";
            break;
        case NOT_INIT_ERROR:
            error_meaning = "Internal structures not initialized";
            break;
        case INSERTION_ERROR:
            error_meaning = "Can't insert plugglet";
            break;
        default:
            error_meaning = "???";
    }

    // todo when time
    n = snprintf(error_str, ERROR_STR, "%s",
                 error_meaning);

    fwrite(error_str, sizeof(char), n, log_file);
}
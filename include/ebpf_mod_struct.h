//
// Created by thomas on 11/05/19.
//

#ifndef FRR_UBPF_EBPF_MOD_STRUCT_H
#define FRR_UBPF_EBPF_MOD_STRUCT_H

typedef struct proto_ext_fun {
    void *fn;
    const char *name;
} proto_ext_fun_t;

#define TYPE_MSG_MONITOR 1

typedef struct mesg_buffer {
    long mesg_type;
    char mesg_text[20];
} ebpf_message_t;

typedef struct plugin_info {
    const char *plugin_str;
    unsigned int plugin_id;
} plugin_info_t;

#define plugin_info_null {.plugin_str = NULL, .plugin_id = 0}


#endif //FRR_UBPF_EBPF_MOD_STRUCT_H

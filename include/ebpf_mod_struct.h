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

typedef struct insertion_point_info {
    const char *insertion_point_str;
    int insertion_point_id;
} insertion_point_info_t;

#define insertion_point_info_null {.insertion_point_str = NULL, .insertion_point_id = 0}
#define proto_ext_func_null {.fn = NULL, .name = NULL}

#define is_insertion_point_info_null(info) (((info)->insertion_point_str == NULL) && ((info)->insertion_point_id == 0))


#endif //FRR_UBPF_EBPF_MOD_STRUCT_H

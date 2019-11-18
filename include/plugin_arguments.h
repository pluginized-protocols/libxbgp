//
// Created by thomas on 19/11/18.
//

#ifndef FRR_UBPF_PLUGIN_ARGUMENTS_H
#define FRR_UBPF_PLUGIN_ARGUMENTS_H

#include "../hashmap.h"

/// EACH plugin MUST!!! HAVE AT LEAST
/// ONE ARGUMENT OF TYPE (context_t *)
/// AND MUST BE THE FIRST ONE !!!!!!!!

typedef enum ID_ARGUMENTS_STRUCT {
    ARGS_INVALID = 0,
    ARGS_DECISION_STEPS,
    ARGS_RCV_UPDATE_PROCEDURE,
    ARGS_DECISION_INBOUND_FAIL,
    ARGS_BGP_OPEN,
    ARGS_BGP_KEEPALIVE,
    ARGS_BGP_DECISION_PROCESS,
    ARGS_BGP_ASPATH_RECV,
    ARGS_BGP_UPDATE,
    ARGS_BGP_UPDATE_TIME,
    ARGS_BGP_WITHDRAW_IN_FILTER,
    ARGS_BGP_INVALID_UPDATE,
    ARGS_BGP_PROC_INPUT_FILTER,
    ARGS_BGP_PROC_OUTPUT_FILTER,
    ARGS_ZEBRA_ANNOUNCE_PREFIX,
    ARGS_ZEBRA_RM_PREFIX,

    ARGS_OSPF_SPF_NEXT,
    ARGS_OSPF_SPF_CALCULATE,
    ARGS_OSPF_LSA_FLOOD,
    ARGS_OSPF_ISM_CHANGE,
    ARGS_OSPF_HELLO_SEND,

    ARGS_ID_KNOWN_MAX, // last of enum
} argument_type_t;


#define kind_ptr 0
#define kind_primitive 1

typedef enum ARG_TYPE {
    BPF_ARG_PRIMITIVE,
    BPF_ARG_POINTER,
    BPF_ARG_PEER,
    BPF_ARG_PREFIX,
    BPF_ARG_PATH_INFO,
    BPF_ARG_MAXPATH_CFG,
    BPF_ARG_BGP,
    BPF_ARG_ATTR,
    BPF_ARG_INT,
    BPF_ARG_INT_MOD,
    BPF_ARG_TIME,
    BPF_ARG_STRING,
    BPF_ARG_PREFIX_RD,
    BPF_ARG_MPLS_LABEL,
    BPF_ARG_EVPN,
    BPF_ARG_DEC_STEPS, /* decision process context */
    BPF_ARG_BGP_NODE,

    /* OSPF RELATED STUFFS */
    BPF_ARG_OSPF_INTERFACE,
    BPF_ARG_OSPF_INTERFACE_LST,
    BPF_ARG_INTERFACE,
    BPF_ARG_OSPF_LSA,
    BPF_ARG_OSPF_LSA_HEADER,
    BPF_ARG_OSPF_AREA,
    BPF_ARG_OSPF,
    BPF_ARG_OSPF_NEIGHBOR,
    BPF_ARG_VERTEX,
    BPF_ARG_PQUEUE,
    BPF_ARG_ROUTE_TABLE,
    BPF_ARG_OSPF_VERTEX

} bpf_arg_type_t;

typedef struct {
    void *arg;
    size_t len;
    short kind;
    bpf_arg_type_t type;
} bpf_args_t;

typedef struct {
    bpf_args_t *args;
    int nargs;
    int plugin_type;
} bpf_full_args_t;

typedef hashmap_t(bpf_full_args_t *) map_args_bpf_t;


#endif //FRR_UBPF_PLUGIN_ARGUMENTS_H

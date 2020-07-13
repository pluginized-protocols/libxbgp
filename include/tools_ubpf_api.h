//
// Created by thomas on 19/08/19.
//

#ifndef FRR_UBPF_TOOLS_UBPF_API_H
#define FRR_UBPF_TOOLS_UBPF_API_H

#include "plugin_arguments.h"
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

//#include "ubpf_context.h"

#define UBPF_AFI_IPV4 1
#define UBPF_AFI_IPV6 2

#define UBPF_SAFI_UNICAST 1
#define UBPF_SAFI_MULTICAST 2
#define UBPF_MPLS 4

struct ubpf_prefix__ {
    uint16_t afi;
    uint8_t safi;
    uint8_t padding;
    uint16_t prefixlen;
    uint8_t u[20];
};

enum {
    EBGP_SESSION,
    IBGP_SESSION,
    LOCAL_SESSION,
};


struct path_attribute {
    uint8_t flags;
    uint8_t code;
    uint16_t len;
    uint8_t *data;
};

struct ubpf_peer_info {
    uint32_t as;
    uint32_t router_id;
    uint32_t capability;
    uint8_t peer_type; // iBGP, eBGP, or LOCAL for local_bgp_sessions field.

    struct {
        uint8_t af;
        union {
            struct in6_addr in6;
            struct in_addr in;
        } addr;
    } addr;

    struct ubpf_peer_info *local_bgp_session; // NULL if the structure is about the local BGP router.
};

struct bgp_route {
    struct ubpf_prefix__ pfx;
    int attr_nb;
    struct path_attribute *attr;
    struct ubpf_peer_info *peer_info;
    uint32_t type; // CONNECTED, STATIC, IGP, BGP
};

struct ubpf_nexthop {
    uint8_t route_type; // connected, static, kernel
    uint64_t igp_metric;
};

/**
 * On PRE and POST mode, these are the only value
 * accepted by the manager.
 * On REPLACE mode, the return value is not checked
 * by the manager. If the function has to return
 * a specific value --> TODO
 */
enum RESERVED_RETURN_VAL {
    BPF_CONTINUE = 1, // continue the execution of the mode (ONLY in PRE or POST mode)
    BPF_FAILURE, // the uBPF code has badly terminated. On PRE and POST mode, continue the execution of other modes
    BPF_SUCCESS, // the uBPF code has successfully terminated. On PRE and POST, tells to the manager to return (other mode are skipped)
};

#ifndef UNUSED
#define UNUSED __attribute__((unused))
#endif

#define api_args context_t *vm_ctx, args_t *args, int pos_arg

#define get_arg_from_type(ctx, type_arg) ({ \
    int i; \
    void *ret; \
    args_t *fargs; \
    ret = NULL; \
    fargs = ctx->args; \
    for (i = 0; i < fargs->nargs; i++) { \
        if (fargs->args[i].type == type_arg) { \
            ret = fargs->args[i].arg; \
            break; \
        } \
    } \
    ret; \
})

#endif //FRR_UBPF_TOOLS_UBPF_API_H

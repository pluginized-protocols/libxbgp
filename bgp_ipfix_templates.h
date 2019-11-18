//
// Created by thomas on 25/12/18.
//

#ifndef FRR_UBPF_BGP_IPFIX_TEMPLATES_H
#define FRR_UBPF_BGP_IPFIX_TEMPLATES_H

#include <fixbuf/public.h>
#include "ubpf_tools/list.h"

#define E_NUM 2568 /* private enterprise number, (here this number is totally random) */



////// !!!! The same order must be respected for BOTH internal and external structure

enum TEMPLATE_TYPE {
    BGP_MAIN_TMPL = 0,
    BGP_UPDATE_PREFIX_TMPL,
    BGP_WITHDRAW_PREFIX_TMPL,
    BGP_INVALID_PREFIX_TMPL,

    TMPL_MAX_SIZE,
};

enum SUBTEMPL_TYPE {
    SB_UPDATE_PREFIX,
    SB_WITHRDAW_PREFIX,
    SB_INVALID_PREFIX,
};

///////// DON'T FORGET TO FREE buffers in fbVarfield_t struct !!!

typedef struct update_prefix {

    fbVarfield_t prefix_update;
    uint8_t inet_family;
    fbVarfield_t as_path;

} update_prefix_t;

typedef struct withdraw_prefix {

    fbVarfield_t prefix;
    uint8_t inet_family;

} withdraw_prefix_t;

typedef struct invalid_prefix {
    fbVarfield_t invalid_prefix;
    uint8_t inet_family;
    fbVarfield_t reason;
} invalid_prefix_t;

// "packed" here is not really a good option since
// some values are accessed by pointers, resulting
// in a non aligned pointers, which causes a crash
// of the program on some processor architecture (SIGBUS)
typedef struct bgp_ipfix {

    uint32_t destinationIPv4Address;   /* Local BGP router */
    uint32_t local_as;                 /* Local AS number  */

    /* opt 1 */ /// Data concerning a remote peer
    uint32_t sourceIPv4Address;           /* BGP peer IPv4 address */
    uint32_t peer_as;                     /* peer AS */
    //uint32_t bgp_community;             /* optional (0 if missing)*/
    fbSubTemplateList_t prefix_update;    /* updated prefixes sent to local BGP with the aspath */
    fbSubTemplateList_t prefix_withdraw;  /* prefixes to withdraw  */
    fbSubTemplateList_t invalid_prefixes;
    uint32_t nb_keepalive;                /* number of keepalive sent since last IPFIX message */
    uint64_t last_open_message_time;      /* may be an indication of  */
    uint64_t last_update_message_time;    /* time in milliseconds */
    uint64_t last_keepalive_message_time; /* */
    uint32_t update_message_duration;
    uint32_t nb_open_msg;
    uint32_t nb_update_msg;
    uint64_t total_route_adj_rib_in;      /* total routes received by remote peer */
    uint64_t total_route_adj_rib_out;     /* total routes advertised to remote peer*/
    uint32_t invalidated_update;          /* rejected update since last IPFIX message */

    /* opt 2 */ /// Data concerning local BGP router (extra info) may be null (set to 0)
    uint32_t bgp_decision_process_time; /* mean time */
    uint32_t nb_decision_process;       /*updatenumber of time the decision process has
                                         * been run since last IPFIX message
                                         */
    uint64_t total_routes_loc_rib;      /* total routes inside router */


} bgp_ipfix_t;


typedef struct bgp_ipfix_state {

    uint32_t destinationIPv4Address;   /* Local BGP router */
    uint32_t local_as;                 /* Local AS number  */

    /* opt 1 */ /// Data concerning a remote peer
    uint32_t sourceIPv4Address;        /* BGP peer IPv4 address */
    uint32_t peer_as;                  /* peer AS */
    uint32_t bgp_community;            /* optional (0 if missing)*/
    list_t *prefix_update;             /* updated prefixes sent to local BGP with the aspath */
    list_t *prefix_withdraw;           /* prefixes to withdraw  */
    uint32_t nb_keepalive;             /* number of keepalive sent since last IPFIX message */
    uint64_t last_keepalive_time;      /* last keepalive time */
    uint64_t last_open_message_time;   /* may be an indication of  */
    uint32_t nb_open_msg;
    uint64_t last_update_message_time; /* time in milliseconds */
    uint32_t update_message_duration;  /* how long an update is processed */
    uint32_t nb_update_msg;            /* nb of update msg since last IPFIX messages sent*/
    uint64_t total_route_adj_rib_in;   /* total routes received by remote peer */
    uint64_t total_route_adj_rib_out;  /* total routes advertised to remote peer*/
    uint32_t invalidated_update;       /* rejected update since last IPFIX message */
    list_t *invalid_prefixes;

    /* delete list */
    /* contains pointers to heap used to store fbVarfield_t buffers (used to dealloc when msg sent to collector) */
    list_t *fbVarFieldBuffers;

} bgp_ipfix_state_t;

typedef struct local_bgp_state {

    list_t *bgp_decision_time;      /* list of time in uint64_t */
    uint32_t nb_decision_process;   /* nb of decision process */
    uint64_t total_routes_loc_rib;  /* total known routes */

} local_bgp_state_t;

#endif //FRR_UBPF_BGP_IPFIX_TEMPLATES_H

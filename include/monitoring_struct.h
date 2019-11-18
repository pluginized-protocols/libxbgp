//
// Created by thomas on 4/11/18.
//

#ifndef FRR_THESIS_MONITORING_STRUCT_H
#define FRR_THESIS_MONITORING_STRUCT_H

#include <stdint.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>

#include "lib/prefix.h"


#define MAXMSG

typedef struct bgp_test {

    uint32_t curr_timer;

} bgp_test_t;

typedef struct monit_bgp_keepalive {
    struct timeval elapsed; // time elapsed between two consecutive keepalive
    struct timeval last; // time when last keepalive has been sent
    uint32_t keepalive_interval; // normal interval between two keepalive
    struct in_addr remote_id; // remote router IP
    uint32_t peer_as;
    struct in_addr local_id; // local router IP (which send a keepalive)
    uint64_t time;

} monit_bgp_keepalive_t;

typedef struct monit_open_received_msg {

    clock_t begin; // bgp open processing start
    clock_t end_process; // bgp open processing end
    struct in_addr remote_id; // remote router IP
    struct in_addr local_id;
    uint32_t peer_as;
    int status; // is this message correctly processed
    uint64_t time;

} monit_open_received_msg_t;

typedef struct monit_update_msg {

    clock_t begin;
    clock_t end_processing;
    struct in_addr remote_id;
    struct in_addr local_id;
    uint32_t peer_as;
    int status;
    uint64_t time;

} monit_update_msg_t;


typedef struct monit_prefix_update {
    struct prefix p;
    struct in_addr remote_id;
    struct in_addr local_id;
    uint64_t loc_rib;
    uint64_t adj_rib_in;
    uint64_t adj_rib_out;
    uint32_t as_path_size; // in bytes !!
    uint32_t peer_as;

} monit_prefix_update_t;

typedef struct monit_prefix_withdraw {
    struct prefix p;
    struct in_addr remote_id;
    struct in_addr local_id;
    uint32_t peer_as;
} monit_prefix_withdraw_t;


typedef struct monit_decision_process {
    clock_t begin;
    clock_t end;
    struct in_addr router_id;
} monit_decision_process_t;

typedef struct monit_invalid_update_inbound {
    struct prefix p;
    struct in_addr local_id;
    struct in_addr remote_id;
    uint32_t peer_as;
    uint16_t reason_len;
    uint8_t reason[50];
} monit_invalid_update_inbound_t;


#endif //FRR_THESIS_MONITORING_STRUCT_H

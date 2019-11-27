//
// Created by thomas on 21/12/18.
//

#ifndef FRR_UBPF_BGP_IPFIX_H
#define FRR_UBPF_BGP_IPFIX_H

#include <fixbuf/public.h>
#include "bgp_ipfix_templates.h"

#define BGP_IPFIX_H_DESTINATION_IPV4_ADDRESS "destinationIPv4Address"
#define BGP_IPFIX_H_LOCAL_AS "local_as"
#define BGP_IPFIX_H_PEER_AS "peer_as"
#define BGP_IPFIX_H_SOURCE_IPV4_ADDRESS "sourceIPv4Address"
#define BGP_IPFIX_H_PREFIX_UPDATE "prefix_update"
#define BGP_IPFIX_H_PREFIX_WITHDRAW "prefix_withdraw"
#define BGP_IPFIX_H_INVALID_PREFIXES "invalid_prefixes"
#define BGP_IPFIX_H_NB_KEEPALIVE "nb_keepalive"
#define BGP_IPFIX_H_LAST_OPEN_MSG_TIME "last_open_message_time"
#define BGP_IPFIX_H_LAST_UPDATE_MSG_TIME "last_update_message_time"
#define BGP_IPFIX_H_LAST_KEEPALIVE_MSG_TIME "last_keepalive_message_time"
#define BGP_IPFIX_H_UPDATE_MSG_DURATION "update_message_duration"
#define BGP_IPFIX_H_NB_OPEN_MSG "nb_open_msg"
#define BGP_IPFIX_H_NB_UPDATE_MSG "nb_update_msg"
#define BGP_IPFIX_H_TOTAL_ROUTE_ADJ_RIB_IN "total_route_adj_rib_in"
#define BGP_IPFIX_H_TOTAL_ROUTE_ADJ_RIB_OUT "total_route_adj_rib_out"
#define BGP_IPFIX_H_INVALIDATED_UPDATE "invalidated_update"
#define BGP_IPFIX_H_BGP_DEC_PROC_TIME "bgp_decision_process_time"
#define BGP_IPFIX_H_NB_DECISION_PROCESS "nb_decision_process"
#define BGP_IPFIX_H_TOTAL_ROUTE_LOC_RIB "total_route_loc_rib"
#define BGP_IPFIX_H_KEEPALIVE_TIME "keepalive_time"

#define BGP_IPFIX_H_PREFIX "prefix"
#define BGP_IPFIX_H_INET_FAMILY "inet_family"
#define BGP_IPFIX_H_AS_PATH "as_path"
#define BGP_IPFIX_H_REASON "reason"

#if __BIG_ENDIAN__
#define htonll(x)   (x)
#define ntohll(x)   (x)
#else
#define htonll(x)   ((((uint64_t)htonl(x&0xFFFFFFFF)) << 32) + htonl(x >> 32))
#define ntohll(x)   ((((uint64_t)ntohl(x&0xFFFFFFFF)) << 32) + ntohl(x >> 32))
#endif

struct ipfix_state {
    fbInfoModel_t *model;
    fbSession_t *session;
    fbListener_t *listener;
    fbExporter_t *exporter;
    fbTemplate_t *template[TMPL_MAX_SIZE];
    fbTemplate_t *template_ext[TMPL_MAX_SIZE];
    uint16_t id_template[TMPL_MAX_SIZE];
    uint16_t id_ext_template[TMPL_MAX_SIZE];
};

extern struct ipfix_state *ipfix_vars;



void print_ipfix_message(bgp_ipfix_t *s);


/**
 * Initialize IPFIX exporter
 * @param port string containing the port number on which the collector is listening to
 * @param collector_host IP address of the IPFIX collector host
 * @param ebuf output buffer used to write IPFIX message to IPFIX collector
 * @return 0 if connection is established, -1 otherwise
 */
int ipfix_exporter_init(const char *port, const char *collector_host);

/**
 * Initializes IPFIX collector
 * @param collector input buffer containing received IPFIX message from exporters
 * @param ip_listen Which ip to listen to. NULL to listen to all interfaces
 * @param port which port must be used to listen on
 * @return -1 on failure. 0 otherwise
 */
int ipfix_collector_init(char *ip_listen, char *port);

/**
 * Deallocate memory related to IPFIX exporter and close remote connection
 * with collector host
 * @return 0
 */
int ipfix_exporter_shutdown(void);

int msg_wait(fBuf_t **buf);

int ipfix_structure_decode(uint8_t *data, bgp_ipfix_t *pkt);

size_t ipfix_structure_encode(bgp_ipfix_t *pkt, uint8_t **data);

int ipfix_update_prefix_decode(uint8_t *buffer, update_prefix_t *upd);

int ipfix_withdraw_prefix_decode(uint8_t *buffer, withdraw_prefix_t *wth);

int ipfix_invalid_prefix_decode(uint8_t *buffer, invalid_prefix_t *inv);

int dup_struct_hton(bgp_ipfix_t *src, bgp_ipfix_t *tgt);

int bgp_buffer_exporter(fBuf_t **ebuf);

int struct_ntoh(bgp_ipfix_t *s);


#endif //FRR_UBPF_BGP_IPFIX_H

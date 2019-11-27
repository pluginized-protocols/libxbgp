//
// Created by thomas on 22/12/18.
// https://tools.netsa.cert.org/confluence/display/tt/Creating+an+IPFIX+Flow+Exporter+using+libfixbuf

#include "bgp_ipfix.h"
#include "bgp_ipfix_templates.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static struct ipfix_state state;
struct ipfix_state *ipfix_vars = &state;

fbInfoElement_t certElements[] = {
        FB_IE_INIT_FULL(BGP_IPFIX_H_BGP_DEC_PROC_TIME, E_NUM, 33, 4, FB_IE_DEFAULT | FB_UNITS_MILLISECONDS | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_32, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_AS_PATH, E_NUM, 34, FB_IE_VARLEN, FB_IE_DEFAULT | FB_IE_F_REVERSIBLE, 0, 0, FB_STRING, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_PREFIX_UPDATE, E_NUM, 35, FB_IE_VARLEN, FB_IE_DEFAULT | FB_IE_LIST | FB_IE_F_REVERSIBLE, 0, 0, FB_SUB_TMPL_LIST, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_PREFIX_WITHDRAW, E_NUM, 36, FB_IE_VARLEN, FB_IE_DEFAULT | FB_IE_LIST | FB_IE_F_REVERSIBLE, 0, 0, FB_SUB_TMPL_LIST, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_INVALID_PREFIXES, E_NUM, 37, FB_IE_VARLEN, FB_IE_DEFAULT | FB_IE_LIST | FB_IE_F_REVERSIBLE, 0, 0, FB_SUB_TMPL_LIST, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_KEEPALIVE_TIME, E_NUM, 38, 4, FB_IE_DEFAULT | FB_IE_F_REVERSIBLE | FB_UNITS_MILLISECONDS | FB_IE_F_ENDIAN, 0, 0, FB_UINT_32,NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_PEER_AS, E_NUM, 39, 4, FB_IE_DEFAULT | FB_IE_F_REVERSIBLE | FB_IE_F_ENDIAN, 0, 0, FB_UINT_32, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_LOCAL_AS, E_NUM, 40, 4, FB_IE_DEFAULT | FB_IE_F_REVERSIBLE | FB_IE_F_ENDIAN, 0, 0, FB_UINT_32, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_NB_KEEPALIVE, E_NUM, 41, 4, FB_IE_DEFAULT | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_32, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_NB_OPEN_MSG, E_NUM, 42, 4, FB_IE_DEFAULT | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_32, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_NB_UPDATE_MSG, E_NUM, 43, 4, FB_IE_DEFAULT | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_32, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_LAST_OPEN_MSG_TIME, E_NUM, 44, 8, FB_IE_DEFAULT | FB_UNITS_NANOSECONDS | FB_IE_F_ENDIAN, 0, 0, FB_DT_NANOSEC, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_LAST_UPDATE_MSG_TIME, E_NUM, 45, 8, FB_IE_DEFAULT | FB_UNITS_NANOSECONDS | FB_IE_F_ENDIAN, 0, 0, FB_DT_NANOSEC, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_LAST_KEEPALIVE_MSG_TIME, E_NUM, 46, 8, FB_IE_DEFAULT | FB_UNITS_NANOSECONDS | FB_IE_F_ENDIAN, 0, 0, FB_DT_NANOSEC, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_TOTAL_ROUTE_ADJ_RIB_IN, E_NUM, 47, 8, FB_IE_DEFAULT | FB_IE_F_ENDIAN, 0, 0, FB_UINT_64, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_TOTAL_ROUTE_ADJ_RIB_OUT, E_NUM, 48, 8, FB_IE_DEFAULT | FB_IE_F_ENDIAN, 0, 0, FB_UINT_64, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_TOTAL_ROUTE_LOC_RIB, E_NUM, 49, 8, FB_IE_DEFAULT | FB_IE_F_ENDIAN, 0, 0, FB_UINT_64, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_INVALIDATED_UPDATE, E_NUM, 50, 4, FB_IE_DEFAULT | FB_IE_F_ENDIAN, 0, 0, FB_UINT_32, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_INET_FAMILY, E_NUM, 52, 1, FB_IE_DEFAULT | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_8, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_UPDATE_MSG_DURATION, E_NUM, 53, 4, FB_IE_DEFAULT | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE | FB_UNITS_MILLISECONDS, 0, 0, FB_UINT_32, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_NB_DECISION_PROCESS, E_NUM, 54, 4, FB_IE_DEFAULT | FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE, 0, 0, FB_UINT_32, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_PREFIX, E_NUM, 55, FB_IE_VARLEN, FB_IE_DEFAULT | FB_IE_F_REVERSIBLE, 0, 0, FB_STRING, NULL),
        FB_IE_INIT_FULL(BGP_IPFIX_H_REASON, E_NUM, 56, FB_IE_VARLEN, FB_IE_DEFAULT | FB_IE_F_REVERSIBLE, 0, 0, FB_STRING, NULL),

        FB_IE_NULL,
};

/* (char *) cast explicitly added to avoid useless GCC warnings */

fbInfoElementSpec_t bgp_monitor[] = {
        {(char *) BGP_IPFIX_H_DESTINATION_IPV4_ADDRESS, 4, 0},
        {(char *) BGP_IPFIX_H_LOCAL_AS, 4, 0},
        {(char *) BGP_IPFIX_H_SOURCE_IPV4_ADDRESS, 4, 0},
        {(char *) BGP_IPFIX_H_PEER_AS, 4, 0},
        {(char *) "subTemplateList", FB_IE_VARLEN, 0},
        {(char *) "subTemplateList", FB_IE_VARLEN, 0},
        {(char *) "subTemplateList", FB_IE_VARLEN, 0},
        {(char *) BGP_IPFIX_H_NB_KEEPALIVE, 4, 0},
        {(char *) BGP_IPFIX_H_LAST_OPEN_MSG_TIME, 8, 0},
        {(char *) BGP_IPFIX_H_LAST_UPDATE_MSG_TIME, 8, 0},
        {(char *) BGP_IPFIX_H_LAST_KEEPALIVE_MSG_TIME, 8, 0},
        {(char *) BGP_IPFIX_H_UPDATE_MSG_DURATION, 4, 0},
        {(char *) BGP_IPFIX_H_NB_OPEN_MSG, 4, 0},
        {(char *) BGP_IPFIX_H_NB_UPDATE_MSG, 4, 0},
        {(char *) BGP_IPFIX_H_TOTAL_ROUTE_ADJ_RIB_IN, 8, 0},
        {(char *) BGP_IPFIX_H_TOTAL_ROUTE_ADJ_RIB_OUT, 8, 0},
        {(char *) BGP_IPFIX_H_INVALIDATED_UPDATE, 4, 0},

        // local router information only
        {(char *) BGP_IPFIX_H_BGP_DEC_PROC_TIME, 4, 0},
        {(char *) BGP_IPFIX_H_NB_DECISION_PROCESS, 4, 0},
        {(char *) BGP_IPFIX_H_TOTAL_ROUTE_LOC_RIB, 8, 0},
        FB_IESPEC_NULL
};

fbInfoElementSpec_t bgp_monitor_ext[] = {
        {(char *) BGP_IPFIX_H_DESTINATION_IPV4_ADDRESS, 0, 0},
        {(char *) BGP_IPFIX_H_LOCAL_AS, 0, 0},
        {(char *) BGP_IPFIX_H_SOURCE_IPV4_ADDRESS, 0, 0},
        {(char *) BGP_IPFIX_H_PEER_AS, 0, 0},
        {(char *) "subTemplateList", 0, 0},
        {(char *) "subTemplateList", 0, 0},
        {(char *) "subTemplateList", 0, 0},
        {(char *) BGP_IPFIX_H_NB_KEEPALIVE, 0, 0},
        {(char *) BGP_IPFIX_H_LAST_OPEN_MSG_TIME, 0, 0},
        {(char *) BGP_IPFIX_H_LAST_UPDATE_MSG_TIME, 0, 0},
        {(char *) BGP_IPFIX_H_LAST_KEEPALIVE_MSG_TIME, 0, 0},
        {(char *) BGP_IPFIX_H_UPDATE_MSG_DURATION, 0, 0},
        {(char *) BGP_IPFIX_H_NB_OPEN_MSG, 0, 0},
        {(char *) BGP_IPFIX_H_NB_UPDATE_MSG, 0, 0},
        {(char *) BGP_IPFIX_H_TOTAL_ROUTE_ADJ_RIB_IN, 0, 0},
        {(char *) BGP_IPFIX_H_TOTAL_ROUTE_ADJ_RIB_OUT, 0, 0},
        {(char *) BGP_IPFIX_H_INVALIDATED_UPDATE, 0, 0},

        // local router information only
        {(char *) BGP_IPFIX_H_BGP_DEC_PROC_TIME, 0, 0},
        {(char *) BGP_IPFIX_H_NB_DECISION_PROCESS, 0, 0},
        {(char *) BGP_IPFIX_H_TOTAL_ROUTE_LOC_RIB, 0, 0},
        FB_IESPEC_NULL
};

fbInfoElementSpec_t update_prefix_internal[] = {
        {(char *) BGP_IPFIX_H_PREFIX, FB_IE_VARLEN, 0},
        {(char *) BGP_IPFIX_H_INET_FAMILY, 1, 0},
        {(char *) BGP_IPFIX_H_AS_PATH, FB_IE_VARLEN, 0},
        FB_IESPEC_NULL,
};

fbInfoElementSpec_t withdraw_prefix_internal[] = {
        {(char *) BGP_IPFIX_H_PREFIX, FB_IE_VARLEN, 0},
        {(char *) BGP_IPFIX_H_INET_FAMILY, 1, 0},
        FB_IESPEC_NULL,
};

fbInfoElementSpec_t invalid_prefix_internal[] = {
        {(char *) BGP_IPFIX_H_PREFIX, FB_IE_VARLEN, 0},
        {(char *) BGP_IPFIX_H_INET_FAMILY, 1, 0},
        {(char *) BGP_IPFIX_H_REASON, FB_IE_VARLEN, 0},
        FB_IESPEC_NULL,
};

fbInfoElementSpec_t update_prefix_external[] = {
        {(char *) BGP_IPFIX_H_PREFIX, 0, 0},
        {(char *) BGP_IPFIX_H_INET_FAMILY, 0, 0},
        {(char *) BGP_IPFIX_H_AS_PATH, 0, 0},
        FB_IESPEC_NULL,
};

fbInfoElementSpec_t withdraw_prefix_external[] = {
        {(char *) BGP_IPFIX_H_PREFIX, 0, 0},
        {(char *) BGP_IPFIX_H_INET_FAMILY, 0, 0},
        FB_IESPEC_NULL,
};

fbInfoElementSpec_t invalid_prefix_external[] = {
        {(char *) BGP_IPFIX_H_PREFIX, 0, 0},
        {(char *) BGP_IPFIX_H_INET_FAMILY, 0, 0},
        {(char *) BGP_IPFIX_H_REASON, 0, 0},
        FB_IESPEC_NULL,
};


/**
 * Add new IPFIX field for BGP into libipfix and the structure fields
 * WARNING : ipfix_init must be called before this function
 *
 * @param fields : structure which will contains new IPFIX fields
 * @return -1 if errors, 0 otherwise
 */
static int add_new_fields(fbInfoModel_t *model) {
    fbInfoModelAddElementArray(model, certElements);
    return 0;
}

static void fnprintf(struct _IO_FILE *file, size_t size, uint8_t *string){

    size_t i;

    for(i = 0; i < size; i++){
        fprintf(file, "%c", string[i]);
    }

}

int dup_struct_hton(bgp_ipfix_t *src, bgp_ipfix_t *tgt) {

    if (!src || !tgt) return -1;

    *tgt = *src; // shallow copy (assuming pointers in network byte order)

    // src and destination already in network byte order

    tgt->local_as = htonl(tgt->local_as);
    tgt->peer_as = htonl(tgt->peer_as);
    tgt->nb_keepalive = htonl(tgt->nb_keepalive);
    tgt->last_keepalive_message_time = htonll(tgt->last_keepalive_message_time);
    tgt->last_update_message_time = htonll(tgt->last_update_message_time);
    tgt->last_open_message_time = htonll(tgt->last_open_message_time);
    tgt->update_message_duration = htonl(tgt->update_message_duration);
    tgt->nb_open_msg = htonl(tgt->nb_open_msg);
    tgt->nb_update_msg = htonl(tgt->nb_update_msg);
    tgt->total_routes_loc_rib = htonll(tgt->total_routes_loc_rib);
    tgt->total_route_adj_rib_out = htonll(tgt->total_route_adj_rib_out);
    tgt->total_route_adj_rib_in = htonll(tgt->total_route_adj_rib_in);
    tgt->invalidated_update = htonl(tgt->invalidated_update);
    tgt->bgp_decision_process_time = htonl(tgt->bgp_decision_process_time);
    tgt->nb_decision_process = htonl(tgt->nb_decision_process);


    return 0;
}

int struct_ntoh(bgp_ipfix_t *s){
    if(!s) return -1;

    s->local_as = ntohl(s->local_as);
    s->peer_as = ntohl(s->peer_as);
    s->nb_keepalive = ntohl(s->nb_keepalive);
    s->last_keepalive_message_time = ntohll(s->last_keepalive_message_time);
    s->last_update_message_time = ntohll(s->last_update_message_time);
    s->last_open_message_time = ntohll(s->last_open_message_time);
    s->update_message_duration = ntohl(s->update_message_duration);
    s->nb_open_msg = ntohl(s->nb_open_msg);
    s->nb_update_msg = ntohl(s->nb_update_msg);
    s->total_routes_loc_rib = ntohll(s->total_routes_loc_rib);
    s->total_route_adj_rib_out = ntohll(s->total_route_adj_rib_out);
    s->total_route_adj_rib_in = ntohll(s->total_route_adj_rib_in);
    s->invalidated_update = ntohl(s->invalidated_update);
    s->bgp_decision_process_time = ntohl(s->bgp_decision_process_time);
    s->nb_decision_process = ntohl(s->nb_decision_process);

    return 0;
}

void print_ipfix_message(bgp_ipfix_t *s) {


    update_prefix_t *u;
    withdraw_prefix_t *w;
    invalid_prefix_t *i;

    w = fbSubTemplateListGetDataPtr(&s->prefix_withdraw);
    u = fbSubTemplateListGetDataPtr(&s->prefix_update);
    i = fbSubTemplateListGetDataPtr(&s->invalid_prefixes);


    fprintf(stderr,
            "bgp_ipfix_t {\n"
            "  destinationAddress %u\n"
            "  local_as %u\n"
            "  sourceAddress %u\n"
            "  peer_as %u\n"
            "  nb_keepalive %u\n"
            "  last_open_message_time %lu\n"
            "  last_update_message_time %lu\n"
            "  last_keepalive_message_time %lu\n"
            "  update_message_duration %u\n"
            "  nb_open_message %u\n"
            "  nb_update_message %u\n"
            "  total_route_adj_rib_in %lu\n"
            "  total_route_adj_rib_out %lu\n"
            "  invalidated_update %u\n"
            "  bgp_decision_process_time %u\n"
            "  nb_decision_process %u\n"
            "  total_route_loc_rib %lu\n",
            s->destinationIPv4Address,
            s->local_as,
            s->sourceIPv4Address,
            s->peer_as,
            s->nb_keepalive,
            s->last_open_message_time,
            s->last_update_message_time,
            s->last_keepalive_message_time,
            s->update_message_duration,
            s->nb_open_msg,
            s->nb_update_msg,
            s->total_route_adj_rib_in,
            s->total_route_adj_rib_out,
            s->invalidated_update,
            s->bgp_decision_process_time,
            s->nb_decision_process,
            s->total_routes_loc_rib);

    fprintf(stderr, "  withdraw_prefixes (%i) [ ", s->prefix_withdraw.numElements);
    //w = fbSubTemplateListGetNextPtr(&s->prefix_withdraw, w);
    while (w) {
        fnprintf(stderr, w->prefix.len, w->prefix.buf);
        fprintf(stderr, " ");
        w = fbSubTemplateListGetNextPtr(&s->prefix_withdraw, w);
    }
    fprintf(stderr, "]\n  update_prefixes (%i) [", s->prefix_update.numElements);
    //u = fbSubTemplateListGetNextPtr(&s->prefix_update, u);
    while (u) {
        fnprintf(stderr, u->prefix_update.len, u->prefix_update.buf);
        fprintf(stderr, " ");
        u = fbSubTemplateListGetNextPtr(&s->prefix_update, u);
    }
    fprintf(stderr, "]\n  invalid_prefixes (%i) [", s->invalid_prefixes.numElements);
    //i = fbSubTemplateListGetNextPtr(&s->invalid_prefixes, i);
    while (i) {
        fnprintf(stderr, i->invalid_prefix.len, i->invalid_prefix.buf);
        fprintf(stderr, " ");
        i = fbSubTemplateListGetNextPtr(&s->invalid_prefixes, i);
    }
    fprintf(stderr, "]\n}\n");


}

int ipfix_structure_decode(uint8_t *data, bgp_ipfix_t *pkt) {

    if (!data || !pkt) return -1;

    memcpy(&pkt->destinationIPv4Address, data, 4);
    data += 4;
    memcpy(&pkt->local_as, data, 4);
    data += 4;
    memcpy(&pkt->sourceIPv4Address, data, 4);
    data += 4;
    memcpy(&pkt->peer_as, data, 4);
    data += 4;
    memcpy(&pkt->prefix_update, data, sizeof(fbSubTemplateList_t));
    data += sizeof(fbSubTemplateList_t);
    memcpy(&pkt->prefix_withdraw, data, sizeof(fbSubTemplateList_t));
    data += sizeof(fbSubTemplateList_t);
    memcpy(&pkt->invalid_prefixes, data, sizeof(fbSubTemplateList_t));
    data += sizeof(fbSubTemplateList_t);
    memcpy(&pkt->nb_keepalive, data, 4);
    data += 4;
    memcpy(&pkt->last_open_message_time, data, 8);
    data += 8;
    memcpy(&pkt->last_update_message_time, data, 8);
    data += 8;
    memcpy(&pkt->last_keepalive_message_time, data, 8);
    data += 8;
    memcpy(&pkt->update_message_duration, data, 4);
    data += 4;
    memcpy(&pkt->nb_open_msg, data, 4);
    data += 4;
    memcpy(&pkt->nb_update_msg, data, 4);
    data += 4;
    memcpy(&pkt->total_route_adj_rib_in, data, 8);
    data += 8;
    memcpy(&pkt->total_route_adj_rib_out, data, 8);
    data += 8;
    memcpy(&pkt->invalidated_update, data, 4);
    data += 4;
    memcpy(&pkt->bgp_decision_process_time, data, 4);
    data += 4;
    memcpy(&pkt->nb_decision_process, data, 4);
    data += 4;
    memcpy(&pkt->total_routes_loc_rib, data, 8);

    struct_ntoh(pkt);

    return 0;
}

size_t ipfix_structure_encode(bgp_ipfix_t *pkt, uint8_t **data) {

    uint8_t *buffer;
    size_t size = 0;
    bgp_ipfix_t pkt_net;

    if (!pkt || !data) return 0;

    uint16_t s = fbTemplateGetIELenOfMemBuffer(state.template[BGP_MAIN_TMPL]);
    buffer = (uint8_t *) malloc(s * sizeof(uint8_t));
    if (!buffer) return 0;

    dup_struct_hton(pkt, &pkt_net);
    pkt = &pkt_net;

    /* begin encoding */
    memcpy(buffer + size, &pkt->destinationIPv4Address, sizeof(uint32_t));
    size += 4;
    memcpy(buffer + size, &pkt->local_as, sizeof(uint32_t));
    size += 4;
    memcpy(buffer + size, &pkt->sourceIPv4Address, sizeof(uint32_t));
    size += 4;
    memcpy(buffer + size, &pkt->peer_as, sizeof(uint32_t));
    size += 4;
    memcpy(buffer + size, &pkt->prefix_update, sizeof(fbSubTemplateList_t));
    size += sizeof(fbSubTemplateList_t);
    memcpy(buffer + size, &pkt->prefix_withdraw, sizeof(fbSubTemplateList_t));
    size += sizeof(fbSubTemplateList_t);
    memcpy(buffer + size, &pkt->invalid_prefixes, sizeof(fbSubTemplateList_t));
    size += sizeof(fbSubTemplateList_t);
    memcpy(buffer + size, &pkt->nb_keepalive, sizeof(uint32_t));
    size += 4;
    memcpy(buffer + size, &pkt->last_open_message_time, sizeof(uint64_t));
    size += 8;
    memcpy(buffer + size, &pkt->last_update_message_time, sizeof(uint64_t));
    size += 8;
    memcpy(buffer + size, &pkt->last_keepalive_message_time, sizeof(uint64_t));
    size += 8;
    memcpy(buffer + size, &pkt->update_message_duration, sizeof(uint32_t));
    size += 4;
    memcpy(buffer + size, &pkt->nb_open_msg, sizeof(uint32_t));
    size += 4;
    memcpy(buffer + size, &pkt->nb_update_msg, sizeof(uint32_t));
    size += 4;
    memcpy(buffer + size, &pkt->total_route_adj_rib_in, sizeof(uint64_t));
    size += 8;
    memcpy(buffer + size, &pkt->total_route_adj_rib_out, sizeof(uint64_t));
    size += 8;
    memcpy(buffer + size, &pkt->invalidated_update, sizeof(uint32_t));
    size += 4;
    memcpy(buffer + size, &pkt->bgp_decision_process_time, sizeof(uint32_t));
    size += 4;
    memcpy(buffer + size, &pkt->nb_decision_process, sizeof(uint32_t));
    size += 4;
    memcpy(buffer + size, &pkt->total_routes_loc_rib, sizeof(uint64_t));
    size += 8;
    /* end encoding */

    *data = buffer;

    //fprintf(stderr, "Encoded size %zu, expected size : %hu\n",
    //        size, fbTemplateGetIELenOfMemBuffer(state.template[BGP_MAIN_TMPL]));

    return size;
}


static int ipfix_global_init() {

    GError *err;
    uint16_t etid, etid2;
    fbInfoElementSpec_t *elts, *elts_ext;
    fbTemplate_t *etmpl, *etmpl_ext;

    err = NULL;
    memset(&state, 0, sizeof(struct ipfix_state));

    fbInfoModel_t *ipfix_instance = fbInfoModelAlloc();
    if (!ipfix_instance) return -1;

    state.model = ipfix_instance;

    fbSession_t *ipfix_session = fbSessionAlloc(ipfix_instance);
    if (!ipfix_session) return -1;

    state.session = ipfix_session;

    if (add_new_fields(ipfix_instance) < 0) return -1;

    for (int i = BGP_MAIN_TMPL; i < TMPL_MAX_SIZE; i++) {
        etmpl = fbTemplateAlloc(ipfix_instance);
        etmpl_ext = fbTemplateAlloc(ipfix_instance);
        if (!etmpl || !etmpl_ext) {
            fprintf(stderr, "Unable to add template\n");
            return -1;
        }

        state.template[i] = etmpl;
        state.template_ext[i] = etmpl_ext;

        switch (i) {
            case BGP_MAIN_TMPL:
                elts = bgp_monitor;
                elts_ext = bgp_monitor_ext;
                break;
            case BGP_UPDATE_PREFIX_TMPL:
                elts = update_prefix_internal;
                elts_ext = update_prefix_external;
                break;
            case BGP_WITHDRAW_PREFIX_TMPL:
                elts = withdraw_prefix_internal;
                elts_ext = withdraw_prefix_external;
                break;
            case BGP_INVALID_PREFIX_TMPL:
                elts = invalid_prefix_internal;
                elts_ext = invalid_prefix_external;
                break;
            default:
                return -1;
        }

        if (!fbTemplateAppendSpecArray(etmpl, elts, 0xffffffff, &err)) {
            fprintf(stderr, "Unable to append elements to template: %s\n", err->message);
            return -1;
        }
        if (!fbTemplateAppendSpecArray(etmpl_ext, elts_ext, 0xffffffff, &err)) {
            fprintf(stderr, "Unable to append elements to template: %s\n", err->message);
            return -1;
        }

        etid = fbSessionAddTemplate(ipfix_session, TRUE, FB_TID_AUTO, etmpl, &err);

        if (etid == 0) {
            fprintf(stderr, "SessionAddTemplate failure: %s\n", err->message);
            return -1;
        }


        etid2 = fbSessionAddTemplate(ipfix_session, FALSE, etid, etmpl_ext, &err);

        if (etid2 == 0) {
            fprintf(stderr, "SessionAddTemplate failure: %s\n", err->message);
            return -1;
        }

        state.id_ext_template[i] = etid;
        state.id_template[i] = etid;
    }


    return 0;
}

int ipfix_update_prefix_decode(uint8_t *buffer, update_prefix_t *upd){

    size_t offset = 0;

    if(!buffer || !upd) return -1;

    memcpy(&upd->prefix_update, buffer + offset, sizeof(fbVarfield_t));
    offset += sizeof(fbVarfield_t);
    memcpy(&upd->inet_family, buffer + offset, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    memcpy(&upd->as_path, buffer + offset, sizeof(fbVarfield_t));

    return 0;
}

int ipfix_withdraw_prefix_decode(uint8_t *buffer, withdraw_prefix_t *wth){

    size_t offset = 0;
    if(!buffer || !wth) return -1;

    memcpy(&wth->prefix, buffer+offset, sizeof(fbVarfield_t));
    offset += sizeof(fbVarfield_t);
    memcpy(&wth->inet_family, buffer+offset, sizeof(uint8_t));

    return 0;
}

int ipfix_invalid_prefix_decode(uint8_t *buffer, invalid_prefix_t *inv){
    size_t offset = 0;

    if(!buffer || !inv) return -1;

    memcpy(&inv->invalid_prefix, buffer + offset, sizeof(fbVarfield_t));
    offset += sizeof(fbVarfield_t);
    memcpy(&inv->inet_family, buffer + offset, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    memcpy(&inv->reason, buffer + offset, sizeof(fbVarfield_t));

    return 0;
}

int ipfix_collector_init(char *ip_listen, char *port) {
    GError *err;

    struct fbConnSpec_st socketDef;

    if (ipfix_global_init() < 0) {
        return -1;
    }
    socketDef.transport = FB_TCP;
    socketDef.host = ip_listen;
    socketDef.svc = port;
    socketDef.ssl_ca_file = NULL;
    socketDef.ssl_cert_file = NULL;
    socketDef.ssl_key_file = NULL;
    socketDef.ssl_key_pass = NULL;
    socketDef.vai = NULL;
    socketDef.vssl_ctx = NULL;
    err = NULL;

    fbListener_t *collectorListener = fbListenerAlloc(&socketDef, state.session, NULL, NULL, &err);

    if (!collectorListener) {
        fprintf(stderr, "ListenerAlloc failure: %s\n", err->message);
        return -1;
    }


    state.listener = collectorListener;

    return 0;
}

int msg_wait(fBuf_t **buf) {
    GError *err;
    if (!buf) return -1;
    err = NULL;

    fBuf_t *collectorBuf = fbListenerWait(state.listener, &err);
    if (!collectorBuf) {
        fprintf(stderr, "Wait for connection failure : %s\n", err->message);
        return -1;
    }

    if (!fBufSetInternalTemplate(collectorBuf, state.id_template[BGP_MAIN_TMPL], &err)) {
        fprintf(stderr, "fBufSetInternalTemplate failure: %s\n", err->message);
        return -1;
    }

    *buf = collectorBuf;

    return 0;
}

int ipfix_exporter_init(const char *port, const char *collector_host) {

    fbConnSpec_t exSocketDef;

    if (ipfix_global_init() < 0) {
        return -1;
    }

    exSocketDef.transport = FB_TCP;
    exSocketDef.host = (char *) collector_host;
    exSocketDef.svc = (char *) port;
    exSocketDef.ssl_ca_file = NULL;
    exSocketDef.ssl_cert_file = NULL;
    exSocketDef.ssl_key_file = NULL;
    exSocketDef.ssl_key_pass = NULL;
    exSocketDef.vai = NULL;
    exSocketDef.vssl_ctx = NULL;


    fbExporter_t *exporter = fbExporterAllocNet(&exSocketDef);

    if (!exporter) {
        return -1;
    }

    state.exporter = exporter;


    return 0;

}

int bgp_buffer_exporter(fBuf_t **ebuf) {

    GError *err;
    fBuf_t *buf;
    if (!ebuf) return -1;

    err = NULL;

    buf = fBufAllocForExport(state.session, state.exporter);

    if (!buf) {
        fprintf(stderr, "Unable to create buffer\n");
    }

    if (!fbSessionExportTemplates(state.session, &err)) {
        fprintf(stderr, "Export templates failure: %s\n", err->message);
        return -1;
    }

    if (!fBufSetInternalTemplate(buf, state.id_template[BGP_MAIN_TMPL], &err)) {
        fprintf(stderr, "fBufSetInternalTemplate failure: %s\n", err->message);
        return -1;
    }

    if (!fBufSetExportTemplate(buf, state.id_ext_template[BGP_MAIN_TMPL], &err)) {
        fprintf(stderr, "fbufSetExportTemplate failure: %s\n", err->message);
        return -1;
    }

    fBufSetAutomaticMode(buf, TRUE);

    *ebuf = buf;

    return 0;

}

int ipfix_exporter_shutdown() {

    return 0;
}

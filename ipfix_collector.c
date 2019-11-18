//
// Created by thomas on 30/12/18.
//

#include "ipfix_collector.h"
#include "bgp_ipfix.h"
#include "bgp_ipfix_templates.h"
#include <mongoc.h>
#include <time.h>
#include <pthread.h>
#include <fixbuf/public.h>

#define OFFSET_NTP_TO_UNIX_EPOCH -2208988800

struct mongo_state {
    mongoc_collection_t *collection;
    mongoc_uri_t *uri;
    mongoc_client_t *client;
};

static struct mongo_state mongo_state;

static int ipfix_nanotime_to_timespec(uint64_t ipfix_time, struct timespec *store) {

    if (!store) return -1;

    store->tv_sec = ((ipfix_time & 0xFFFFFFFF00000000u) >> 32u) + OFFSET_NTP_TO_UNIX_EPOCH;
    store->tv_nsec = ipfix_time & 0xFFFFFFFF;

    return 0;
}

static int ipfix_time_append(bson_t *document, uint64_t ipfix_time, const char *key, size_t len_key) {

    struct timespec tp;
    bson_t child_doc;
    if (!document) return -1;
    if (ipfix_nanotime_to_timespec(ipfix_time, &tp) < 0) return -1;

    if (!bson_append_document_begin(document, key, (int) len_key, &child_doc)) return -1;
    BSON_APPEND_INT64(&child_doc, "time", tp.tv_sec);
    BSON_APPEND_INT32(&child_doc, "nanosec",
                      (uint32_t) tp.tv_nsec); // tv_nsec varies from 0 to 999999999, thus fits into uint32_t
    return bson_append_document_end(document, &child_doc) ? 0 : -1;
}

int init_collector(char *db_name, char *coll_name, const char *const uri_base) {

    const char *uri_string = uri_base;
    mongoc_client_t *client;
    mongoc_uri_t *uri;
    mongoc_collection_t *collection;
    bson_error_t error;

    mongoc_init();
    uri = mongoc_uri_new_with_error(uri_string, &error);

    if (!uri) {
        fprintf(stderr,
                "failed to parse URI: %s\n"
                "error message:       %s\n",
                uri_string,
                error.message);
        return -1;
    }
    client = mongoc_client_new_from_uri(uri);

    if (!client) {
        return -1;
    }

    collection = mongoc_client_get_collection(client, db_name, coll_name);

    mongo_state.collection = collection;
    mongo_state.uri = uri;
    mongo_state.client = client;

    return 0;
}

static int create_bson_list(bson_t *document, int type, fbSubTemplateList_t *stl) {

    int index = -1;
    bson_t child, child2;
    void *generic_ptr;
    if (!document || !stl) return -1;

    char buffer[100];
    char str_index[11];

    memset(buffer, 0, sizeof(char) * 100);
    memset(str_index, 0, sizeof(char) * 11);

    switch (type) {
        case LIST_BGP_INVALID_UPDATE:
            if(!BSON_APPEND_ARRAY_BEGIN(document, "invalid_update", &child)) return -1;
            break;
        case LIST_BGP_PREFIX_UPDATE:
            if(!BSON_APPEND_ARRAY_BEGIN(document, "prefix_update", &child)) return -1;
            break;
        case LIST_BGP_PREFIX_WITHDRAW:
            if(!BSON_APPEND_ARRAY_BEGIN(document, "prefix_withdraw", &child)) return -1;
            break;
        default:
            return -1; // è_é
    }

    generic_ptr = fbSubTemplateListGetDataPtr(stl);
    while (generic_ptr) {
        index++;
        memset(str_index, 0, sizeof(char) * 11);
        snprintf(str_index, 11, "%i", index); // int to string (bson keys are strings)

        if(!bson_append_document_begin(&child, str_index, (int) strlen(str_index), &child2)) return -1;

        switch (type) {
            case LIST_BGP_INVALID_UPDATE: {
                invalid_prefix_t invalid;
                ipfix_invalid_prefix_decode(generic_ptr, &invalid);

                memset(buffer, 0, sizeof(char) * 100);
                memcpy(buffer, invalid.invalid_prefix.buf, invalid.invalid_prefix.len);
                BSON_APPEND_UTF8(&child2, "prefix", buffer);
                BSON_APPEND_INT32(&child2, "family", invalid.inet_family);
                memset(buffer, 0, sizeof(char) * 100);
                memcpy(buffer, invalid.reason.buf, invalid.reason.len);
                BSON_APPEND_UTF8(&child2, "reason", buffer);
                break;
            }
            case LIST_BGP_PREFIX_UPDATE: {
                update_prefix_t update;
                ipfix_update_prefix_decode(generic_ptr, &update);

                memset(buffer, 0, sizeof(char) * 100);
                memcpy(buffer, update.prefix_update.buf, update.prefix_update.len);
                BSON_APPEND_UTF8(&child2, "prefix", buffer);
                BSON_APPEND_INT32(&child2, "family", update.inet_family);
                memset(buffer, 0, sizeof(char) * 100);
                memcpy(buffer, update.as_path.buf, update.as_path.len);
                BSON_APPEND_UTF8(&child2, "as_path", buffer);
                break;
            }
            case LIST_BGP_PREFIX_WITHDRAW: {
                withdraw_prefix_t withdraw;
                ipfix_withdraw_prefix_decode(generic_ptr, &withdraw);

                memset(buffer, 0, sizeof(char) * 100);
                memcpy(buffer, withdraw.prefix.buf, withdraw.prefix.len);
                BSON_APPEND_UTF8(&child2, "prefix", buffer);
                BSON_APPEND_INT32(&child2, "family", withdraw.inet_family);
                break;
            }
        }
        if(!bson_append_document_end(&child, &child2)) return -1;
        generic_ptr = fbSubTemplateListGetNextPtr(stl, generic_ptr);
    }

    bson_append_array_end(document, &child);
    return 0;
};

int handle_record(bgp_ipfix_t *record) {
    bson_t *document, *local_stat, *prefixes;
    bson_error_t error;
    struct in_addr a;
    char *tmp;

    char sourceIPv4[16];
    char remoteIPv4[16];

    document = bson_new();
    local_stat = bson_new();
    prefixes = bson_new();
    if (!document || !local_stat || !prefixes) {
        fprintf(stderr, "Can't allocate new BSON documents\n");
        return -1;
    }

    a.s_addr = record->sourceIPv4Address;
    tmp = inet_ntoa(a);
    memcpy(remoteIPv4, tmp, strlen(tmp) + 1);

    a.s_addr = record->destinationIPv4Address;
    tmp = inet_ntoa(a);
    memcpy(sourceIPv4, tmp, strlen(tmp) + 1);


    document = BCON_NEW(
            "type", BCON_UTF8("peerGlobalStats"),
            "destinationIPv4Address", BCON_UTF8(remoteIPv4),
            "sourceIPv4Address", BCON_UTF8(sourceIPv4),
            "peer_as", BCON_INT32((record->peer_as)),
            "local_as", BCON_INT32((record->local_as)),
            "nb_open_msg", BCON_INT32((record->nb_open_msg)),
            "nb_update_msg", BCON_INT32((record->nb_update_msg)),
            "nb_keepalive", BCON_INT32((record->nb_keepalive)),
            "total_route_adj_rib_in", BCON_INT64((record->total_route_adj_rib_in)),
            "total_route_adj_rib_out", BCON_INT64((record->total_route_adj_rib_out)),
            "update_duration", BCON_INT32((record->update_message_duration)),
            "invalidated_update", BCON_INT32((record->invalidated_update))
    );

    if(ipfix_time_append(document, record->last_keepalive_message_time, "last_keepalive", 14) < 0){
        fprintf(stderr, "Can't append time to document\n");
    }
    if(ipfix_time_append(document, record->last_update_message_time, "last_update", 11) < 0){
        fprintf(stderr, "Can't append time to document\n");
    }
    if(ipfix_time_append(document, record->last_open_message_time, "last_open", 9) < 0){
        fprintf(stderr, "Can't append time to document\n");
    }


    local_stat = BCON_NEW(
            "type", BCON_UTF8("localRouterStats"),
            "destinationIPv4Address", BCON_UTF8(remoteIPv4),
            "local_as", BCON_INT32((record->local_as)),
            "total_route_loc_rib", BCON_INT64((record->total_routes_loc_rib)),
            "bgp_decision_process_time", BCON_INT32((record->bgp_decision_process_time)),
            "nb_decision_process", BCON_INT32((record->nb_decision_process))
    );

    prefixes = BCON_NEW(
            "type", BCON_UTF8("peerGlobalStats"),
            "destinationIPv4Address", BCON_UTF8(remoteIPv4),
            "sourceIPv4Address", BCON_UTF8(sourceIPv4),
            "peer_as", BCON_INT32((record->peer_as)),
            "local_as", BCON_INT32((record->local_as))
    );

    /* unaligned pointer value */
    create_bson_list(prefixes, LIST_BGP_PREFIX_WITHDRAW, &record->prefix_withdraw);
    create_bson_list(prefixes, LIST_BGP_PREFIX_UPDATE, &record->prefix_update);
    create_bson_list(prefixes, LIST_BGP_INVALID_UPDATE, &record->invalid_prefixes);

    const bson_t *docs[] = {
            document,
            local_stat,
            prefixes
    };

    if (!mongoc_collection_insert_many(mongo_state.collection, docs, 3, NULL, NULL, &error)) {
        fprintf(stderr, "MongoDB insertion failed: %s\n", error.message);
        return -1;
    }

    bson_destroy(document);
    bson_destroy(local_stat);
    bson_destroy(prefixes);

    return 0;
}

void *handle_connection(void *arg) {

    gboolean rc;
    GError *err;
    fBuf_t *collector;

    bgp_ipfix_t current_record;
    err = NULL;
    collector = (fBuf_t *) arg;
    size_t length = 188; // TODO fix that hardcoded length
    uint8_t curr_buff[length]; // allocated size is larger than necessary (might have some padding)

    while (1) {

        memset(curr_buff, 0, length);

        rc = fBufNext(collector, curr_buff, &length, &err);

        if (FALSE == rc) {
            fprintf(stderr, "Read failure: %s\n", err->message);
            if (err->code != FB_ERROR_EOM) {
                g_clear_error(&err);
                fBufFree(collector);
                break;
            }
            g_clear_error(&err);
            continue;
        }

        if (ipfix_structure_decode(curr_buff, &current_record) < 0) {
            fprintf(stderr, "Unsuccessful decoding\n");
        };

        //print_ipfix_message(&current_record);


        if (handle_record(&current_record) < 0) {
            fprintf(stderr, "FAIL :(\n");
        }

        fbSubTemplateListClear(&current_record.invalid_prefixes);
        fbSubTemplateListClear(&current_record.prefix_update);
        fbSubTemplateListClear(&current_record.prefix_withdraw);


    }
    return 0;
}


int connection_listener() {

    fBuf_t *curr_buff;

    while (1) {
        msg_wait(&curr_buff);
        handle_connection(curr_buff);
    }

    return 0; // shouldn't be reached
}

int start_collector(char *ipfix_listen, char *ipfix_port, char *db_name, char *coll_name, char *uri_base) {

    if (init_collector(db_name, coll_name, uri_base) != 0) {
        fprintf(stderr, "Unable to init this collector\n");
        return -1;
    }

    if (ipfix_collector_init(ipfix_listen, ipfix_port) < 0) {
        fprintf(stderr, "Unable to init IPFIX listener\n");
        return -1;
    }

    connection_listener();

    /* main collector loop */
    /*if (handle_connection() < 0) {
        fprintf(stderr, "Collecting server has crashed\n");
        return -1;
    }*/

    // should not be reached
    return 0;
}
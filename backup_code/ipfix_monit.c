//
// Created by thomas on 22/11/19.
//


int data_handling(data_t *data) {

    bgp_ipfix_state_t *message;
    char local[MAX_CHAR_IPV4_ARRAY], remote[MAX_CHAR_IPV4_ARRAY];


    switch (data->type) {
        case BGP_KEEPALIVE: {
            monit_bgp_keepalive_t *keepalive = (monit_bgp_keepalive_t *) data->data;
            parse_ipv4(keepalive->local_id, keepalive->remote_id, local, remote, MAX_CHAR_IPV4_ARRAY);
            get_or_new_ipfix_state(&current_state->msg, remote, local, &message);

            message->nb_keepalive++;
            message->last_keepalive_time = keepalive->time;

            //fprintf(stderr,
            //        "[MONITOR] KeepAlive sent from local router %s to %s peer after %lis %liµs (normal ka %u)\n",
            //        local, remote, keepalive->elapsed.tv_sec,
            //        keepalive->elapsed.tv_usec, keepalive->keepalive_interval);


            break;
        }
        case BGP_OPEN_MSG: {
            monit_open_received_msg_t *open = (monit_open_received_msg_t *) data->data;
            parse_ipv4(open->local_id, open->remote_id, local, remote, MAX_CHAR_IPV4_ARRAY);
            get_or_new_ipfix_state(&current_state->msg, remote, local, &message);

            message->peer_as = open->peer_as;

            message->nb_open_msg++;
            message->last_open_message_time = open->time;

            //clock_t diffticks = open->end_process - open->begin;

            //fprintf(stderr, "[MONITOR] Open BGP message received from %s, processing time %lfms, status %i\n",
            //        remote, diffticks / (CLOCKS_PER_SEC / 1000.0), open->status);

            break;
        }
        case BGP_UPDATE_TIME_MSG: {
            monit_update_msg_t *update = (monit_update_msg_t *) data->data;
            parse_ipv4(update->local_id, update->remote_id, local, remote, MAX_CHAR_IPV4_ARRAY);
            get_or_new_ipfix_state(&current_state->msg, remote, local, &message);

            clock_t difftick = update->end_processing - update->begin;
            message->nb_update_msg++;
            message->update_message_duration = (uint32_t) (difftick * 1000.0 / CLOCKS_PER_SEC);
            message->last_update_message_time = update->time;
            message->invalidated_update += update->status != 12 ? 1 : 0; // bgp value TODO RM MAGIC NUMBER

            //fprintf(stderr, "[MONITOR] Update message received from %s, processing time %lfms, status %i\n",
            //        remote, difftick * 1000.0 / CLOCKS_PER_SEC, update->status);
            break;
        }
        case BGP_PREFIX_WITHDRAW: {
            char prefix[PREFIX2STR_BUFFER];
            withdraw_prefix_t new_withdraw;
            monit_prefix_withdraw_t *withdraw = (monit_prefix_withdraw_t *) data->data;
            parse_ipv4(withdraw->local_id, withdraw->remote_id, local, remote, MAX_CHAR_IPV4_ARRAY);
            get_or_new_ipfix_state(&current_state->msg, remote, local, &message);

            memset(prefix, 0, sizeof(prefix));
            prefix2str(&withdraw->p, prefix, sizeof(prefix));

            new_withdraw.ubpf_prefix.len = strlen(prefix) * sizeof(char);
            new_withdraw.ubpf_prefix.buf = malloc(new_withdraw.ubpf_prefix.len + 1);
            if (!new_withdraw.ubpf_prefix.buf) {
                fprintf(stderr, "No enough memory\n");
            }
            memcpy(new_withdraw.ubpf_prefix.buf, prefix, new_withdraw.ubpf_prefix.len);
            new_withdraw.ubpf_prefix.buf[new_withdraw.ubpf_prefix.len] = 0;

            push(message->fbVarFieldBuffers, &new_withdraw.ubpf_prefix.buf);


            push(message->prefix_withdraw, &new_withdraw);

            //fprintf(stderr, "[MONITOR] Withdraw prefix received: %s\n", prefix);

            break;
        }
        case BGP_PREFIX_UPDATE: {

            char prefix[PREFIX2STR_BUFFER];
            update_prefix_t new_prefix;
            monit_prefix_update_t2 *prefix_update;
            parse_update_prefix(data->data, &prefix_update);
            parse_ipv4(prefix_update->local_id, prefix_update->remote_id, local, remote, MAX_CHAR_IPV4_ARRAY);
            get_or_new_ipfix_state(&current_state->msg, remote, local, &message);

            memset(prefix, 0, sizeof(prefix));
            prefix2str(&prefix_update->p, prefix, sizeof(prefix));

            new_prefix.inet_family = prefix_update->p.family;

            new_prefix.as_path.len = prefix_update->as_path_size;
            new_prefix.as_path.buf = malloc(prefix_update->as_path_size + 1);

            if (!new_prefix.as_path.buf) {
                fprintf(stderr, "OOM\n");
            }
            memcpy(new_prefix.as_path.buf, prefix_update->as_path, prefix_update->as_path_size);
            new_prefix.as_path.buf[new_prefix.as_path.len] = 0;

            new_prefix.prefix_update.len = strnlen(prefix, PREFIX2STR_BUFFER) * sizeof(char);
            new_prefix.prefix_update.buf = calloc(new_prefix.prefix_update.len + 1, sizeof(char));
            if (!new_prefix.prefix_update.buf) {
                fprintf(stderr, "Out of memory\n");
            }
            memcpy(new_prefix.prefix_update.buf, prefix, new_prefix.prefix_update.len);
            new_prefix.prefix_update.buf[new_prefix.prefix_update.len] = 0;

            push(message->prefix_update, &new_prefix);

            /* save addresses of buffers to list */
            push(message->fbVarFieldBuffers, &new_prefix.as_path.buf);
            push(message->fbVarFieldBuffers, &new_prefix.prefix_update.buf);

            message->total_route_adj_rib_in = prefix_update->adj_rib_in;
            current_state->local_state.total_routes_loc_rib = prefix_update->loc_rib;

            //fprintf(stderr, "[MONITOR] Update received for ubpf_prefix %s\n", ubpf_prefix);

            free(prefix_update->as_path);
            free(prefix_update);

            break;
        }
        case BGP_INVALID_UPDATE_INBOUND: {
            char prefix[PREFIX2STR_BUFFER];
            invalid_prefix_t invalid_prefix;
            monit_invalid_update_inbound_t *invalid = (monit_invalid_update_inbound_t *) data->data;
            parse_ipv4(invalid->local_id, invalid->remote_id, local, remote, MAX_CHAR_IPV4_ARRAY);
            get_or_new_ipfix_state(&current_state->msg, remote, local, &message);

            memset(prefix, 0, PREFIX2STR_BUFFER * sizeof(char));
            prefix2str(&invalid->p, prefix, sizeof(prefix));

            invalid_prefix.invalid_prefix.len = strlen(prefix) * sizeof(char);
            invalid_prefix.invalid_prefix.buf = malloc(invalid_prefix.invalid_prefix.len + 1);
            if (!invalid_prefix.invalid_prefix.buf) {
                fprintf(stderr, "Out of memory");
            }
            memcpy(invalid_prefix.invalid_prefix.buf, prefix, invalid_prefix.invalid_prefix.len);
            invalid_prefix.invalid_prefix.buf[invalid_prefix.invalid_prefix.len] = 0;
            invalid_prefix.inet_family = invalid->p.family;

            invalid_prefix.reason.len = invalid->reason_len;
            invalid_prefix.reason.buf = malloc(invalid_prefix.reason.len + 1);
            if (!invalid_prefix.reason.buf) {
                fprintf(stderr, "Out of memory");
            }
            memcpy(invalid_prefix.reason.buf, invalid->reason, invalid->reason_len);
            invalid_prefix.reason.buf[invalid_prefix.reason.len] = 0;

            push(message->invalid_prefixes, &invalid_prefix);

            /* push address to heap (used to free buffers when sent) */
            push(message->fbVarFieldBuffers, &invalid_prefix.reason.buf);
            push(message->fbVarFieldBuffers, &invalid_prefix.invalid_prefix.buf);

            message->invalidated_update++;
            //fprintf(stderr, "[MONITOR] Invalid update received %s : %s\n", prefix, invalid_prefix.reason.buf);
            break;

        }
        case BGP_DECISION_PROCESS: {
            monit_decision_process_t *decision_msg = (monit_decision_process_t *) data->data;
            clock_t difftick = decision_msg->end - decision_msg->begin;
            uint64_t store = difftick;

            push(current_state->local_state.bgp_decision_time, &store);
            current_state->local_state.nb_decision_process++;

            //fprintf(stderr, "[MONITOR] Decision process time : %lfms\n", difftick * 1000.0 / CLOCKS_PER_SEC);

            break;

        }

        case BGP_PREFIX_UPDATE_TEST: {
            /* avro */
            /*avro_reader_t reader;
            avro_schema_error_t  error;
            avro_schema_t reader_schema;
            avro_value_iface_t *reader_iface;
            avro_value_t reader_value;

            size_t mem;

            reader = avro_reader_memory((const char *) data->data, data->length);
            if(avro_schema_from_json(SCHEMA_UPDATE_PREFIX, 0, &reader_schema, &error) != 0) break;

            reader_iface = avro_generic_class_from_schema(reader_schema);
            if(!reader_iface) break;
            if(avro_generic_value_new(reader_iface, &reader_value) != 0) break;


            while (avro_value_read(reader, &reader_value) == 0) {
                avro_value_t  field;
                struct ubpf_prefix p;
                int32_t  peer_as, local_id, remote_id;
                uint64_t loc_rib, adj_rib_in, adj_rib_out;
                const char *as_path = calloc(sizeof(const char), 1024);
                if(!as_path) break;

                avro_value_get_by_name(&reader_value, "peer_as", &field, NULL);
                avro_value_get_int(&field, &peer_as);
                avro_value_get_by_name(&reader_value, "p", &field, NULL);
                avro_value_get_bytes(&field, &p, &mem);
                avro_value_get_by_name(&reader_value, "remote_id", &field, NULL);
                avro_value_get_int(&field, &remote_id);
                avro_value_get_by_name(&reader_value, "local_id", &field, NULL);
                avro_value_get_int(&field, &local_id);
                avro_value_get_by_name(&reader_value, "loc_rib", &field, NULL);
                avro_value_get_long(&field, &loc_rib);
                avro_value_get_by_name(&reader_value, "adj_rib_in", &field, NULL);
                avro_value_get_long(&field, &adj_rib_in);
                avro_value_get_by_name(&reader_value, "adj_rib_out", &field, NULL);
                avro_value_get_long(&field, &adj_rib_out);
                avro_value_get_by_name(&reader_value, "as_path", &field, NULL);
                avro_value_get_string(&field, &as_path, &mem);

                fprintf(stderr, "aspath lol : %s\n", as_path);
            }
            avro_value_decref(&reader_value);
            avro_value_iface_decref(reader_iface);
            avro_schema_decref(reader_schema);*/


            break;
        }

        default:
            fprintf(stderr, "UNKNOWN TYPE ignoring\n");
    }

    free(data->data);


    return 1;
}



void put_list_to_subtemplate(list_t *list, fbSubTemplateList_t *fbl, int type) {


    uint8_t *ptr = fbSubTemplateListGetDataPtr(fbl);
    //ptr = fbSubTemplateListGetNextPtr(fbl, ptr);
    size_t offset = 0;

    while (size(list) > 0 && ptr) {
        offset = 0;
        switch (type) {
            case SB_UPDATE_PREFIX: {
                update_prefix_t update_prefix;
                pop(list, &update_prefix);

                memcpy(ptr, &update_prefix.prefix_update, sizeof(fbVarfield_t));
                offset += sizeof(fbVarfield_t);
                memcpy(ptr + offset, &update_prefix.inet_family, sizeof(uint8_t));
                offset += sizeof(uint8_t);
                memcpy(ptr + offset, &update_prefix.as_path, sizeof(fbVarfield_t));

                break;
            }
            case SB_INVALID_PREFIX: {
                invalid_prefix_t invalid_prefix;
                pop(list, &invalid_prefix);

                memcpy(ptr, &invalid_prefix.invalid_prefix, sizeof(fbVarfield_t));
                offset += sizeof(fbVarfield_t);
                memcpy(ptr + offset, &invalid_prefix.inet_family, sizeof(uint8_t));
                offset += sizeof(uint8_t);
                memcpy(ptr + offset, &invalid_prefix.reason, sizeof(fbVarfield_t));

                break;
            }
            case SB_WITHRDAW_PREFIX: {
                withdraw_prefix_t withdraw_prefix;
                pop(list, &withdraw_prefix);

                memcpy(ptr, &withdraw_prefix.prefix, sizeof(fbVarfield_t));
                offset += sizeof(fbVarfield_t);
                memcpy(ptr + offset, &withdraw_prefix.inet_family, sizeof(uint8_t));


                break;
            }
            default:
                fprintf(stderr, "ERROR\n");

        }


        ptr = fbSubTemplateListGetNextPtr(fbl, ptr);

    }
}

void free_state(bgp_ipfix_state_t *state) {
    uint8_t *curr_buffer;

    destroy_list(state->invalid_prefixes);
    destroy_list(state->prefix_withdraw);
    destroy_list(state->prefix_update);


    while (size(state->fbVarFieldBuffers) > 0) {
        pop(state->fbVarFieldBuffers, &curr_buffer);
        free(curr_buffer);
    }

    free(state);
}

int state_to_ipfix_msg(bgp_ipfix_state_t *const state, bgp_ipfix_t *const message) {

    //fprintf(stderr, "Pointer in function %p\n", message);

    fbSubTemplateList_t *prefix_update;
    fbSubTemplateList_t *prefix_withdraw;
    fbSubTemplateList_t *invalid_prefixes;

    update_prefix_t *curr_updt;
    withdraw_prefix_t *curr_withdraw;
    invalid_prefix_t *curr_invalid;

    prefix_update = &message->prefix_update;
    prefix_withdraw = &message->prefix_withdraw;
    invalid_prefixes = &message->invalid_prefixes;

    curr_updt = fbSubTemplateListInit(prefix_update, FB_LIST_SEM_UNDEFINED,
                                      ipfix_vars->id_template[BGP_UPDATE_PREFIX_TMPL],
                                      ipfix_vars->template[BGP_UPDATE_PREFIX_TMPL],
                                      (uint16_t) size(state->prefix_update));
    curr_withdraw = fbSubTemplateListInit(prefix_withdraw, FB_LIST_SEM_UNDEFINED,
                                          ipfix_vars->id_template[BGP_WITHDRAW_PREFIX_TMPL],
                                          ipfix_vars->template[BGP_WITHDRAW_PREFIX_TMPL],
                                          (uint16_t) size(state->prefix_withdraw));
    curr_invalid = fbSubTemplateListInit(invalid_prefixes, FB_LIST_SEM_UNDEFINED,
                                         ipfix_vars->id_template[BGP_INVALID_PREFIX_TMPL],
                                         ipfix_vars->template[BGP_INVALID_PREFIX_TMPL],
                                         (uint16_t) size(state->invalid_prefixes));


    message->destinationIPv4Address = state->destinationIPv4Address;
    message->local_as = state->local_as;
    message->sourceIPv4Address = state->sourceIPv4Address;
    message->peer_as = state->peer_as;
    message->nb_keepalive = state->nb_keepalive;
    message->last_open_message_time = state->last_open_message_time;
    message->last_update_message_time = state->last_update_message_time;
    message->last_keepalive_message_time = state->last_keepalive_time;
    message->update_message_duration = state->update_message_duration;
    message->nb_update_msg = state->nb_update_msg;
    message->nb_open_msg = state->nb_open_msg;
    message->total_route_adj_rib_in = state->total_route_adj_rib_in;
    message->total_route_adj_rib_out = state->total_route_adj_rib_out;
    message->invalidated_update = state->invalidated_update;

    message->bgp_decision_process_time = 0; // should be set later
    message->nb_decision_process = 0; // same
    message->total_routes_loc_rib = 0; // same

    if (curr_updt)
        put_list_to_subtemplate(state->prefix_update, prefix_update, SB_UPDATE_PREFIX);
    if (curr_withdraw)
        put_list_to_subtemplate(state->prefix_withdraw, prefix_withdraw, SB_WITHRDAW_PREFIX);
    if (curr_invalid)
        put_list_to_subtemplate(state->invalid_prefixes, invalid_prefixes, SB_INVALID_PREFIX);

    return 0;
}

int add_local_state_to_ipfix_msg(local_bgp_state_t *local, bgp_ipfix_t *const msg) {

    uint64_t sum;
    uint32_t size_lst;
    uint64_t tmp;

    size_lst = size(local->bgp_decision_time);

    if (size_lst == 0) {
        msg->bgp_decision_process_time = 0;
    } else {
        sum = 0;
        while (size(local->bgp_decision_time) > 0) {
            pop(local->bgp_decision_time, &tmp);
            sum += tmp;
        }
        msg->bgp_decision_process_time = (uint32_t) (sum / size_lst);
    }

    msg->nb_decision_process = local->nb_decision_process;
    msg->total_routes_loc_rib = local->total_routes_loc_rib;

    return 0;
}

int send_states_ipfix(monit_state_t *state) {

    GError *err;
    const char *key;
    bgp_ipfix_state_t *curr;
    bgp_ipfix_t send;
    uint8_t *buff;
    size_t size;
    map_iter_t iter = map_iter(&state->msg);
    int processed_local = 0; // is local state processed (cf current_state->local_state)
    err = NULL;

    while ((key = map_next(&state->msg, &iter))) {
        memset(&send, 0, sizeof(bgp_ipfix_t));
        curr = *map_get(&state->msg, key);

        state_to_ipfix_msg(curr, &send);

        if (!processed_local) { // only add once the local state into one ipfix message
            processed_local = 1;
            add_local_state_to_ipfix_msg(&current_state->local_state, &send);
            flush_local_state(&current_state->local_state);
        }

        size = ipfix_structure_encode(&send, &buff);

        if (size == 0) {
            fprintf(stderr, "Unable to encode structure\n");
            continue;
        }

        //print_ipfix_message(&send);

        if (fBufAppend(exporter, buff, size, &err) != 0) {
            if (!fBufEmit(exporter, &err)) {
                fprintf(stderr, "Can't emit message %s\n", err->message);
                g_clear_error(&err);
            }
        } else {
            fprintf(stderr, "fBufAppend failure: %s\n", err->message);
            g_clear_error(&err);
        }


        free(buff);
        map_remove(&state->msg, key);
        iter = map_iter(&state->msg); // because we've removed an element
        /* deallocation of memory already sent to collector */
        fbSubTemplateListClear(&send.prefix_update);
        fbSubTemplateListClear(&send.prefix_withdraw);
        fbSubTemplateListClear(&send.invalid_prefixes);
        free_state(curr);
    }
    return 0;
}


typedef struct monit_prefix_update2 {
    struct prefix p;
    struct in_addr remote_id;
    struct in_addr local_id;
    uint64_t loc_rib;
    uint64_t adj_rib_in;
    uint64_t adj_rib_out;
    uint32_t as_path_size; // in bytes !!
    uint32_t peer_as;
    uint8_t *as_path;

} monit_prefix_update_t2;

/**
 * Parse the input buffer received by a uBPF plugin concerning a prefix update
 *
 * @param buffer input buffer containing raw monitoring data sent by uBPF plugins
 *               (headers are already removed from buffer)
 * @param update structure where data will be inserted. Must be eventually deallocated
 * @return -1 if memory alloc failed, 0 otherwise.
 */
static int parse_update_prefix(uint8_t *buffer, monit_prefix_update_t2 **updt) {

    monit_prefix_update_t2 *update = malloc(sizeof(monit_prefix_update_t2));
    if (!update) return -1;

    memcpy(&update->p, buffer, sizeof(struct prefix));
    buffer += sizeof(struct prefix);
    memcpy(&update->remote_id, buffer, sizeof(struct in_addr));
    buffer += sizeof(struct in_addr);
    memcpy(&update->local_id, buffer, sizeof(struct in_addr));
    buffer += sizeof(struct in_addr);
    memcpy(&update->loc_rib, buffer, sizeof(uint64_t));
    buffer += sizeof(uint64_t);
    memcpy(&update->adj_rib_in, buffer, sizeof(uint64_t));
    buffer += sizeof(uint64_t);
    memcpy(&update->adj_rib_out, buffer, sizeof(uint64_t));
    buffer += sizeof(uint64_t);
    memcpy(&update->as_path_size, buffer, sizeof(uint32_t));
    buffer += sizeof(uint32_t);
    memcpy(&update->peer_as, buffer, sizeof(uint32_t));
    buffer += sizeof(uint32_t);

    update->as_path = malloc(update->as_path_size + 1);
    if (!update->as_path) {
        free(update);
        return -1;
    }
    memcpy(update->as_path, buffer, update->as_path_size);
    update->as_path[update->as_path_size] = 0;
    *updt = update;
    return 0;
}

static void parse_ipv4(struct in_addr local, struct in_addr remote, char *local_str, char *remote_str, size_t len) {

    char *tmp;

    memset(local_str, 0, len);
    memset(remote_str, 0, len);

    tmp = inet_ntoa(local);
    memcpy(local_str, tmp, len);
    tmp = inet_ntoa(remote);
    memcpy(remote_str, tmp, len);

}



static char *prefix2str(struct prefix *pu, char *str, int size) {

    if(!str) return NULL;

    char buffer[PREFIX2STR_BUFFER];
    memset(buffer, 0, PREFIX2STR_BUFFER);

    switch (pu->family) {
        case AF_INET:
        case AF_INET6:
            snprintf(
                    str, size, "%s/%d",
                    inet_ntop(pu->family, pu->u, buffer, PREFIX2STR_BUFFER),
                    pu->prefixlen
            );
            break;
        default:
            return NULL;
    }
    return str;
}

queue_t *monitoring_queue;
fBuf_t *exporter;

monit_state_t *current_state;


monit_state_t *init_state() {

    monit_state_t *new;

    new = malloc(sizeof(monit_state_t));
    if (!new) {
        perror("monit_state alloc failed");
        return NULL;
    }

    new->available_data = 0;

    map_init(&new->msg);
    if (pthread_mutex_init(&new->mtx, NULL) != 0) {
        perror("Mutex init error");
        map_deinit(&new->msg);
        free(new);
        return NULL;
    }

    new->local_state.bgp_decision_time = init_list(sizeof(uint64_t));
    if (!new->local_state.bgp_decision_time) {
        map_deinit(&new->msg);
        pthread_mutex_destroy(&new->mtx);
        free(new);
        return NULL;
    }
    new->local_state.nb_decision_process = 0;
    new->local_state.total_routes_loc_rib = 0;

    if (sem_init(&new->data_rm, 0, 0) != 0) {
        map_deinit(&new->msg);
        pthread_mutex_destroy(&new->mtx);
        free(new->local_state.bgp_decision_time);
        free(new);
        return NULL;
    }

    return new;
}

void flush_local_state(local_bgp_state_t *local) {
    flush(local->bgp_decision_time);
    local->nb_decision_process = 0;
    local->total_routes_loc_rib = 0;
}

int
get_or_new_ipfix_state(ipfix_msg_map_t *state, const char *ip_id, const char *local_id, bgp_ipfix_state_t **message) {
    return get_current_state(state, ip_id, message) < 0 ? new_ipfix_state(state, ip_id, local_id, message) : 0;
}

int get_current_state(ipfix_msg_map_t *state, const char *const ip_id, bgp_ipfix_state_t **message) {

    bgp_ipfix_state_t **get;

    if (!state || !ip_id) return -1;

    get = map_get(state, ip_id);

    if (!get) return -1;

    *message = *get;
    return 0;
}

int new_ipfix_state(ipfix_msg_map_t *state, const char *ip_id, const char *local_id, bgp_ipfix_state_t **message) {

    bgp_ipfix_state_t **get;
    struct in_addr peer_bgp;
    struct in_addr local_bgp;

    if (!state || !ip_id) return -1;

    get = map_get(state, ip_id);

    if (get) return -1; /* already init */

    bgp_ipfix_state_t *new_ipfix_msg = calloc(1, sizeof(bgp_ipfix_state_t));
    if (!new_ipfix_msg) return -1;

    if (!inet_aton(ip_id, &peer_bgp)) {
        fprintf(stderr, "Invalid IPv4 address (%s)\n", ip_id);
        return -1;
    }

    if (!inet_aton(local_id, &local_bgp)) {
        fprintf(stderr, "Invalid IPv4 address (%s)\n", ip_id);
        return -1;
    }

    new_ipfix_msg->sourceIPv4Address = peer_bgp.s_addr;
    new_ipfix_msg->destinationIPv4Address = local_bgp.s_addr;

    new_ipfix_msg->prefix_update = init_list(sizeof(update_prefix_t));
    if (!new_ipfix_msg->prefix_update) {
        free(new_ipfix_msg);
        return -1;
    }
    new_ipfix_msg->prefix_withdraw = init_list(sizeof(withdraw_prefix_t));
    if (!new_ipfix_msg->prefix_withdraw) {
        free(new_ipfix_msg->prefix_update);
        free(new_ipfix_msg);
        return -1;
    }
    new_ipfix_msg->invalid_prefixes = init_list(sizeof(invalid_prefix_t));
    if (!new_ipfix_msg->invalid_prefixes) {
        free(new_ipfix_msg->prefix_update);
        free(new_ipfix_msg->prefix_withdraw);
        free(new_ipfix_msg);
        return -1;
    }

    new_ipfix_msg->fbVarFieldBuffers = init_list(sizeof(uint8_t *));
    if (!new_ipfix_msg->fbVarFieldBuffers) {
        destroy_list(new_ipfix_msg->fbVarFieldBuffers);
        free(new_ipfix_msg->prefix_update);
        free(new_ipfix_msg->prefix_withdraw);
        free(new_ipfix_msg);
        return -1;
    }

    if (map_set(state, ip_id, new_ipfix_msg) < 0) {
        return -1;
    }

    *message = new_ipfix_msg;
    return 0;
}

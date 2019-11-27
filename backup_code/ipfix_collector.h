//
// Created by thomas on 30/12/18.
//

#ifndef FRR_UBPF_IPFIX_COLLECTOR_H
#define FRR_UBPF_IPFIX_COLLECTOR_H


#include "backup_code/bgp_ipfix_templates.h"

enum LIST_RECORD_TYPE {
    LIST_BGP_INVALID_UPDATE,
    LIST_BGP_PREFIX_WITHDRAW,
    LIST_BGP_PREFIX_UPDATE,
};

int start_collector(char *ipfix_listen, char *ipfix_port, char *db_name, char *coll_name, char *uri_base);
int init_collector(char *db_name, char *coll_name, const char * uri_base);
int handle_record(bgp_ipfix_t *record);
void * handle_connection(void *arg);
int connection_listener(void);

#endif //FRR_UBPF_IPFIX_COLLECTOR_H

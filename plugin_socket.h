//
// Created by thomas.
//

#ifndef UBPF_TOOLS_PLUGIN_SOCKET_H
#define UBPF_TOOLS_PLUGIN_SOCKET_H

#include <stdio.h>
#include "uthash.h"

enum SOCKET_INTERFACE {
    PLUGIN_SOCKET_QUIC,
    PLUGIN_SOCKET_TCP,
    PLUGIN_SOCKET_UDP
};

// plugin interface only acts as a client
static struct interface_fn {
    void *socket;
    void *bind;
    void *connect;
    void *send;
    void *receive;
} interface[] = {
        [PLUGIN_SOCKET_QUIC] = {},
        [PLUGIN_SOCKET_TCP] = {},
        [PLUGIN_SOCKET_UDP] = {},
};

struct file_description {
    int our_fd;
    UT_hash_handle hh;

    int type_fd;
    union {
#define fdesc (val.fd)
#define pt_sk (val.sk_struct)
        int fd;
        void *sk_struct;
    } val;
};


int open_quic() {

}

int ctx_open(int protocol) {
    switch (protocol) {
        case PLUGIN_SOCKET_QUIC:
            break;
        case PLUGIN_SOCKET_UDP:
            fprintf(stderr, "[FATAL] UDP plugin abstraction not implemented\n");
            return -1;
        case PLUGIN_SOCKET_TCP:
            fprintf(stderr, "[FATAL] TCP plugin abstraction not implemented\n");
            return -1;
            break;
        default:
            return -1;
    }
}


#endif //UBPF_TOOLS_PLUGIN_SOCKET_H
//
// Created by thomas.
//

#include <errno.h>
#include "plugin_socket.h"
#include "uthash.h"
#include "log.h"
#include <xbgp_compliant_api/xbgp_common_vm_defs.h>

#define interface_null {.open=NULL, .send=NULL, .close=NULL, .receive=NULL}

#define check_proto(protocol) ({                                         \
    int __ret__ = 1;                                                     \
    if (protocol <= PLUGIN_SOCKET_MIN || protocol >= PLUGIN_SOCKET_MAX){ \
        __ret__ = 0;                                                     \
    }                                                                    \
    __ret__;                                                             \
})

static int max_plugin_fd = 1;

static struct file_description *fd_table = NULL;


// plugin interface only acts as a client
static struct interface_fn {
    int (*open)(int, const struct sockaddr *, socklen_t);

    int (*send)(int, const void *, size_t);

    int (*receive)(int, void *, size_t);

    int (*close)(int);
} interface[] = {
        [PLUGIN_SOCKET_QUIC] = interface_null,
        [PLUGIN_SOCKET_TCP] = {.open = open_tcp, .send = write_tcp, .close = close_tcp, .receive = read_tcp},
        [PLUGIN_SOCKET_UDP] = interface_null,
};


static inline int next_free_id(void) {
    int curr_cnt = 0;
    struct file_description *curr;

    do {
        curr_cnt += 1;

        if (curr_cnt >= INT16_MAX) {
            // no more fd available
            return -1;
        }

        max_plugin_fd = (max_plugin_fd + 1) % INT16_MAX;
        HASH_FIND_INT(fd_table, &max_plugin_fd, curr);
    } while (curr);

    return max_plugin_fd;
}


static inline struct file_description *get_fd(int p_sock) {
    struct file_description *desc;
    HASH_FIND_INT(fd_table, &p_sock, desc);

    if (!desc) {
        return NULL;
    }

    return desc;
}


struct file_description *new_file_description(int host_fd, int type_fd) {
    struct file_description *f_desc;
    int plugin_fd;

    plugin_fd = next_free_id();
    if (plugin_fd < 0) return NULL;

    f_desc = calloc(1, sizeof(*f_desc));
    if (!f_desc) {
        return NULL;
    }

    f_desc->our_fd = plugin_fd;
    f_desc->fdesc = host_fd;
    f_desc->type_fd = type_fd;

    HASH_ADD_INT(fd_table, our_fd, f_desc);
    return f_desc;
}


void rm_file_description(int plugin_fd) {
    struct file_description *f_desc;
    HASH_FIND_INT(fd_table, &plugin_fd, f_desc);

    if (!f_desc) return;

    interface[f_desc->type_fd].close(f_desc->fdesc);
    HASH_DELETE(hh, fd_table, f_desc);
    free(f_desc);

}

void rm_all_file_descriptions() {
    struct file_description *f_desc, *f_desc_tmp;

    HASH_ITER(hh, fd_table, f_desc, f_desc_tmp) {
        HASH_DELETE(hh, fd_table, f_desc);
        interface[f_desc->type_fd].close(f_desc->fdesc);
        free(f_desc);
    }
}


int open_tcp(int af, const struct sockaddr *addr, socklen_t addrlen) {
    int sfd = -1;

    switch (af) {
        case AF_INET:
        case AF_INET6:
            break;
        default:
            return -1;
    }

    sfd = socket(af, SOCK_STREAM, 0);

    if (sfd < 0) {
        perror("socket");
        goto err;
    }

    if (connect(sfd, addr, addrlen) != 0) {
        msg_log(L_ERR "connect %s", strerror(errno));
        goto err;
    }

    // todo trigger timeout if cannot establish connection within a given time

    return sfd;

    err:
    if (sfd >= 0) { close(sfd); }
    return -1;
}

int write_tcp(int pfd, const void *buf, size_t len) {
    return send(pfd, buf, len, 0);
}

int read_tcp(int pfd, void *buf, size_t len) {
    return recv(pfd, buf, len, 0);
}

int close_tcp(int sfd) {
    return close(sfd);
}

int ctx_open(int protocol, int af, const struct sockaddr *addr, socklen_t len) {
    int sfd;
    struct file_description *f_desc = NULL;

    if (!check_proto(protocol)) {
        // undefined protocol
        return -1;
    }

    sfd = interface[protocol].open(af, addr, len);

    if (sfd < 0) { goto err; }

    f_desc = new_file_description(sfd, protocol);
    if (!f_desc) {
        goto err;
    }

    return f_desc->our_fd;

    err:
    if (sfd < 0) interface[protocol].close(sfd);
    if (f_desc) rm_file_description(f_desc->our_fd);
    return -1;
}

int ctx_write(int sfd, const void *buf, size_t len) {
    struct file_description *f_desc;
    f_desc = get_fd(sfd);

    if (!f_desc) return -1; // bad sfd

    return interface[f_desc->type_fd].send(f_desc->fdesc, buf, len);
}

int ctx_read(int sfd, void *buf, size_t len) {
    struct file_description *f_desc;
    f_desc = get_fd(sfd);

    if (!f_desc) return -1; // bad sfd

    return interface[f_desc->type_fd].receive(f_desc->fdesc, buf, len);
}

int ctx_close(int sfd) {
    struct file_description *f_desc;
    f_desc = get_fd(sfd);

    if (!f_desc) return -1; // bad sfd

    return interface[f_desc->type_fd].close(f_desc->fdesc);
}
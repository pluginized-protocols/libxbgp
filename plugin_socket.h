//
// Created by thomas.
//

#ifndef UBPF_TOOLS_PLUGIN_SOCKET_H
#define UBPF_TOOLS_PLUGIN_SOCKET_H

#include <stdio.h>
#include "uthash.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "include/global_info_str.h"

struct file_description {
    int our_fd;
    UT_hash_handle hh;

    int type_fd;
    union {
#define fdesc val.fd
#define pt_sk (val.sk_struct)
        int fd;
        void *sk_struct;
    } val;
};

struct file_description *new_file_description(int host_fd, int type_fd);

void rm_file_description(int plugin_fd);

/* TCP related functions */
int open_tcp(int af, const struct sockaddr *addr, socklen_t addrlen);

int write_tcp(int pfd, const void *buf, size_t len);

int read_tcp(int pfd, void *buf, size_t len);

int close_tcp(int sfd);


/* actual plugin API */
int ctx_open(int protocol, int af, const struct sockaddr *addr, socklen_t len);

int ctx_write(int sfd, const void *buf, size_t len);

int ctx_read(int sfd, void *buf, size_t len);

int ctx_close(int sfd);

#endif //UBPF_TOOLS_PLUGIN_SOCKET_H
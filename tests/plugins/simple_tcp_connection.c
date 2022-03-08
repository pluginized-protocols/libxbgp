#include <xbgp_compliant_api/xbgp_plugin_api.h>

uint64_t establish_simple_tcp_conn(args_t *args UNUSED);

uint64_t establish_simple_tcp_conn(args_t *args UNUSED) {
    struct sockaddr_in6 add;
    int sfd;
    uint32_t *zzz;
    uint32_t zzz_net;
    uint32_t zzz_recv;
    uint32_t server_val;

    zzz = get_arg(1);
    if (!zzz) {
        log_msg(L_ERR "Unable to get argument\n");
        return EXIT_FAILURE;
    }

    add.sin6_family = AF_INET6;
    add.sin6_port = ebpf_htons(6789);
    add.sin6_flowinfo = 0;
    add.sin6_scope_id = 0;

    if (ebpf_inet_pton(AF_INET6, "::1", &add.sin6_addr, sizeof(add.sin6_addr)) == -1) {
        log_msg(L_ERR "Unable to convert localhost\n");
        return EXIT_FAILURE;
    }

    sfd = sock_open(PLUGIN_SOCKET_TCP, AF_INET6, (struct sockaddr *) &add, sizeof(add));
    if (sfd < 0) {
        log_msg(L_ERR "Unable to open TCP socket\n");
        return EXIT_FAILURE;
    }

    zzz_net = ebpf_htonl(*zzz);

    if (sock_write(sfd, &zzz_net, sizeof(zzz_net)) == -1) {
        log_msg(L_ERR "Unable to write on TCP socket");
        return EXIT_FAILURE;
    }
    if (sock_read(sfd, &zzz_recv, sizeof(zzz_recv)) == -1) {
        log_msg(L_ERR "Unable to read on TCP socket");
        return EXIT_FAILURE;
    }

    server_val = ebpf_ntohl(zzz_recv);

    sock_close(sfd);
    return server_val;
}
